//! The HTTP surface: the dashboard (passkey-auth), the JSON API + MCP (bearer
//! token), and health. `/api/*` accepts EITHER the bearer token (API/MCP) OR a
//! valid dashboard session cookie, so the browser can read the same data.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        Response,
    },
    routing::{get, post},
    Json, Router,
};
use bollard::container::{LogOutput, LogsOptions};
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use std::convert::Infallible;
use tokio::sync::RwLock;

use crate::auth::{self, AuthState};
use crate::collect::Snapshot;
use crate::store::Store;

/// Latest snapshot, shared between the collector loop and the web handlers.
pub type Shared = Arc<RwLock<Option<Snapshot>>>;
/// Recent-events ring (newest first), shared with the collector loop.
pub type Events = Arc<std::sync::Mutex<std::collections::VecDeque<crate::collect::Event>>>;

#[derive(Clone)]
pub struct AppState {
    pub snapshot: Shared,
    /// Bearer token for /api/* + MCP. None = no token gate.
    pub token: Option<String>,
    /// Passkey auth for the dashboard. None = dashboard unauthenticated.
    pub auth: Option<AuthState>,
    /// Time-series history store.
    pub store: Arc<Store>,
    /// Docker handle for the live-log SSE stream. None = no socket.
    pub docker: Option<bollard::Docker>,
    /// Recent-events ring for the dashboard "recent activity" strip.
    pub events: Events,
    /// Latest endpoint-monitor results (reachability + cert expiry).
    pub endpoints: crate::endpoints::Shared,
}

pub fn router(state: AppState) -> Router {
    // /api/* + /mcp : bearer token OR a valid dashboard session.
    let api = Router::new()
        .route("/api/status", get(status))
        .route("/api/series", get(series))
        .route("/api/events", get(events))
        .route("/api/endpoints", get(endpoints_list))
        .route("/api/logs/:name", get(logs))
        .route("/mcp", post(crate::mcp::handle))
        .route_layer(from_fn_with_state(state.clone(), require_api_auth));

    Router::new()
        .route("/", get(auth::index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/logout", get(auth::logout))
        .route("/auth/status", get(auth::status))
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .merge(api)
        .with_state(state)
}

async fn status(State(state): State<AppState>) -> Json<Option<Snapshot>> {
    Json(state.snapshot.read().await.clone())
}

#[derive(Deserialize)]
struct SeriesQuery {
    metric: String,
    from: i64,
    to: i64,
    res: Option<i64>,
}

async fn series(State(state): State<AppState>, Query(q): Query<SeriesQuery>) -> Json<serde_json::Value> {
    let res = q.res.unwrap_or_else(|| crate::store::pick_res(q.to - q.from));
    let s = state.store.series(&q.metric, q.from, q.to, res);
    Json(serde_json::json!({ "res": res, "t": s.t, "avg": s.avg, "min": s.min, "max": s.max }))
}

/// Recent events (newest first), capped.
async fn events(State(state): State<AppState>) -> Json<Vec<crate::collect::Event>> {
    let q = state.events.lock().map(|q| q.iter().take(40).cloned().collect()).unwrap_or_default();
    Json(q)
}

/// Latest endpoint-monitor results.
async fn endpoints_list(State(state): State<AppState>) -> Json<Vec<crate::endpoints::Status>> {
    Json(state.endpoints.read().await.clone())
}

/// Live container logs as Server-Sent Events. The browser's `EventSource`
/// can't set an Authorization header, so this rides the dashboard session
/// cookie (accepted by `require_api_auth`). Each event's data is
/// `{"s":"out"|"err","m":"<line>"}`.
async fn logs(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let docker = state.docker.clone();
    let stream = async_stream::stream! {
        let Some(d) = docker else {
            yield Ok(Event::default().event("fatal").data("docker socket unavailable"));
            return;
        };
        let opts = LogsOptions::<String> {
            follow: true,
            stdout: true,
            stderr: true,
            tail: "300".to_string(),
            ..Default::default()
        };
        let mut logs = d.logs(&name, Some(opts));
        while let Some(item) = logs.next().await {
            match item {
                Ok(out) => {
                    let (s, bytes) = match out {
                        LogOutput::StdErr { message } => ("err", message),
                        LogOutput::StdOut { message }
                        | LogOutput::Console { message }
                        | LogOutput::StdIn { message } => ("out", message),
                    };
                    let text = String::from_utf8_lossy(&bytes);
                    for line in text.split_inclusive('\n') {
                        let line = line.trim_end_matches(['\n', '\r']);
                        if line.is_empty() {
                            continue;
                        }
                        let data = serde_json::json!({ "s": s, "m": line }).to_string();
                        yield Ok(Event::default().data(data));
                    }
                }
                Err(e) => {
                    yield Ok(Event::default().event("fatal").data(e.to_string()));
                    break;
                }
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn require_api_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();

    // 1) Bearer token (API / MCP clients).
    if let Some(expected) = state.token.as_deref() {
        let ok = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|got| got == expected)
            .unwrap_or(false);
        if ok {
            return Ok(next.run(req).await);
        }
    }

    // 2) Dashboard session cookie (browser).
    if let Some(a) = &state.auth {
        let cookie = headers.get(header::COOKIE).and_then(|h| h.to_str().ok());
        if a.session_valid_in(cookie) {
            return Ok(next.run(req).await);
        }
    }

    // 3) Nothing configured at all → open (loopback dev).
    if state.token.is_none() && state.auth.is_none() {
        return Ok(next.run(req).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}
