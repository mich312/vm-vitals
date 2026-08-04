//! Collectors + the point-in-time Snapshot they produce. M0: host + docker.

pub mod docker;
pub mod host;

use serde::Serialize;

pub use host::HostMetrics;

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    /// Unix seconds when this snapshot was taken.
    pub ts: u64,
    pub host: HostMetrics,
    pub containers: Vec<Container>,
}

/// A noteworthy transition between two snapshots (restart, health flip, state
/// change, container appear/disappear). Kept in a small ring for the "recent
/// events" strip.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts: u64,
    pub container: String,
    /// restart | health | state | up | down
    pub kind: String,
    pub detail: String,
}

/// Diff two container lists (by name) into events. `prev` is the earlier tick.
pub fn diff_events(prev: &[Container], next: &[Container], ts: u64) -> Vec<Event> {
    let mut out = Vec::new();
    let ev = |c: &str, kind: &str, detail: String| Event {
        ts,
        container: c.to_string(),
        kind: kind.to_string(),
        detail,
    };
    for n in next {
        match prev.iter().find(|p| p.name == n.name) {
            None => out.push(ev(&n.name, "up", format!("appeared ({})", n.state))),
            Some(p) => {
                if n.restarts > p.restarts {
                    out.push(ev(&n.name, "restart", format!("restarted (×{})", n.restarts)));
                }
                if p.state != n.state {
                    out.push(ev(&n.name, "state", format!("{} → {}", p.state, n.state)));
                }
                if p.health != n.health {
                    if let Some(h) = &n.health {
                        let from = p.health.as_deref().unwrap_or("none");
                        out.push(ev(&n.name, "health", format!("health {from} → {h}")));
                    }
                }
            }
        }
    }
    for p in prev {
        if !next.iter().any(|n| n.name == p.name) {
            out.push(ev(&p.name, "down", "disappeared".to_string()));
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Container {
    pub name: String,
    pub image: String,
    /// running | exited | restarting | …
    pub state: String,
    /// Human status line, e.g. "Up 3 days (healthy)".
    pub status: String,
    /// healthy | unhealthy | starting | none, if the container has a healthcheck.
    pub health: Option<String>,
    pub restarts: i64,
    pub cpu_pct: Option<f32>,
    pub mem_mb: Option<u64>,
    pub mem_limit_mb: Option<u64>,
}

/// One tick: gather host metrics and the container list.
pub async fn collect(host: &mut host::HostCollector, docker: Option<&bollard::Docker>) -> Snapshot {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let host_metrics = host.collect();
    let containers = match docker {
        Some(d) => docker::collect(d).await.unwrap_or_default(),
        None => Vec::new(),
    };

    Snapshot {
        ts,
        host: host_metrics,
        containers,
    }
}
