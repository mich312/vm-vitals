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
