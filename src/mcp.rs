//! Minimal MCP server over the Streamable HTTP transport (JSON-RPC on
//! `POST /mcp`). Exposes read-only tools over the same data the dashboard
//! shows, so an agent can ask "how's the box doing?". Stateless — no session
//! id, single JSON response per request. Auth is the shared bearer token,
//! enforced by `web::require_api_auth` on the route.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bollard::container::{LogOutput, LogsOptions};
use futures_util::StreamExt;
use serde_json::{json, Value};

use crate::web::AppState;

/// MCP protocol revision we speak.
const PROTOCOL: &str = "2025-06-18";

pub async fn handle(State(state): State<AppState>, Json(req): Json<Value>) -> Response {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    // Notifications carry no id and want no response body.
    let Some(id) = id else {
        return StatusCode::ACCEPTED.into_response();
    };

    match method {
        "initialize" => ok(
            id,
            json!({
                "protocolVersion": PROTOCOL,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "vitals", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "ping" => ok(id, json!({})),
        "tools/list" => ok(id, json!({ "tools": tool_list() })),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match call_tool(&state, name, &args).await {
                Ok(text) => ok(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }] }),
                ),
                Err(text) => ok(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
                ),
            }
        }
        _ => err(id, -32601, "method not found"),
    }
}

fn ok(id: Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn err(id: Value, code: i64, msg: &str) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }))
        .into_response()
}

fn tool_list() -> Value {
    json!([
        {
            "name": "host_metrics",
            "description": "Current host vitals: CPU %, memory %, disk %, load average, swap, uptime.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "list_containers",
            "description": "All Docker containers with state, health, restart count, and live CPU %/memory.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "container_logs",
            "description": "Recent log lines for one container (newest last).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Container name (as shown by list_containers)." },
                    "lines": { "type": "integer", "description": "How many recent lines (default 100, max 1000)." }
                },
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": "query_history",
            "description": "Historical time-series for a metric. Metrics: host.cpu, host.mem, host.disk, host.load, host.swap; or c.<container>.cpu / c.<container>.mem for a container.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "metric": { "type": "string", "description": "Metric name, e.g. host.cpu or c.quorum.mem." },
                    "span_secs": { "type": "integer", "description": "Look-back window in seconds (default 3600)." }
                },
                "required": ["metric"],
                "additionalProperties": false
            }
        }
    ])
}

async fn call_tool(state: &AppState, name: &str, args: &Value) -> Result<String, String> {
    match name {
        "host_metrics" => {
            let snap = state.snapshot.read().await.clone();
            let s = snap.ok_or("no snapshot collected yet")?;
            Ok(serde_json::to_string_pretty(&json!({
                "ts": s.ts,
                "hostname": s.host.hostname,
                "cpu_pct": s.host.cpu_pct,
                "mem_used_pct": s.host.mem_used_pct,
                "mem_total_mb": s.host.mem_total_mb,
                "mem_avail_mb": s.host.mem_avail_mb,
                "swap_used_mb": s.host.swap_used_mb,
                "disk_used_pct": s.host.disk_used_pct,
                "disk_total_gb": s.host.disk_total_gb,
                "disk_avail_gb": s.host.disk_avail_gb,
                "load1": s.host.load1, "load5": s.host.load5, "load15": s.host.load15,
                "net_rx_bps": s.host.net_rx_bps, "net_tx_bps": s.host.net_tx_bps,
                "uptime_secs": s.host.uptime_secs
            }))
            .unwrap())
        }
        "list_containers" => {
            let snap = state.snapshot.read().await.clone();
            let s = snap.ok_or("no snapshot collected yet")?;
            Ok(serde_json::to_string_pretty(&s.containers).unwrap())
        }
        "container_logs" => {
            let cname = args
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("missing required argument 'name'")?;
            let lines = args
                .get("lines")
                .and_then(|v| v.as_u64())
                .unwrap_or(100)
                .clamp(1, 1000);
            let docker = state.docker.clone().ok_or("docker socket unavailable")?;
            let opts = LogsOptions::<String> {
                follow: false,
                stdout: true,
                stderr: true,
                tail: lines.to_string(),
                timestamps: true,
                ..Default::default()
            };
            let mut stream = docker.logs(cname, Some(opts));
            let mut out = String::new();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(o) => {
                        let bytes = match o {
                            LogOutput::StdOut { message }
                            | LogOutput::StdErr { message }
                            | LogOutput::Console { message }
                            | LogOutput::StdIn { message } => message,
                        };
                        out.push_str(&String::from_utf8_lossy(&bytes));
                    }
                    Err(e) => return Err(format!("logs error: {e}")),
                }
            }
            if out.is_empty() {
                out.push_str("(no log output)");
            }
            Ok(out)
        }
        "query_history" => {
            let metric = args
                .get("metric")
                .and_then(|v| v.as_str())
                .ok_or("missing required argument 'metric'")?;
            let span = args
                .get("span_secs")
                .and_then(|v| v.as_i64())
                .unwrap_or(3600)
                .clamp(60, 15_552_000);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let res = crate::store::pick_res(span);
            let s = state.store.series(metric, now - span, now, res);
            Ok(serde_json::to_string(&json!({
                "metric": metric,
                "res_secs": res,
                "points": s.t.len(),
                "from": now - span,
                "to": now,
                "t": s.t, "avg": s.avg, "min": s.min, "max": s.max
            }))
            .unwrap())
        }
        other => Err(format!("unknown tool: {other}")),
    }
}
