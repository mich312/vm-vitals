//! Collectors + the point-in-time Snapshot they produce. M0: host + docker.

pub mod docker;
pub mod host;

use serde::Serialize;

pub use docker::DockerCollector;
pub use host::HostMetrics;

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    /// Unix seconds when this snapshot was taken.
    pub ts: u64,
    pub host: HostMetrics,
    pub containers: Vec<Container>,
    /// Why the container list is empty/partial, if it is. An unreachable Docker
    /// daemon must be distinguishable from "this host runs no containers" —
    /// otherwise a blind monitor renders as a healthy one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_error: Option<String>,
    /// How old this snapshot may get before clients should treat it as stale.
    pub stale_after_secs: u64,
}

impl Snapshot {
    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.ts)
    }
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
    /// `None` when the inspect call failed — *not* zero, which would read as a
    /// stable container and hide a crash loop.
    pub restarts: Option<i64>,
    pub cpu_pct: Option<f32>,
    pub mem_mb: Option<u64>,
    pub mem_limit_mb: Option<u64>,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One tick: gather host metrics and the container list.
pub async fn collect(
    host: &mut host::HostCollector,
    docker: Option<(&bollard::Docker, &mut DockerCollector)>,
    budget: std::time::Duration,
) -> Snapshot {
    let ts = now_secs();
    let host_metrics = host.collect();

    let (containers, docker_error) = match docker {
        Some((d, c)) => match c.collect(d, budget).await {
            Ok(list) => (list, None),
            Err(e) => {
                tracing::warn!("docker collect failed: {e:#}");
                (Vec::new(), Some(format!("{e:#}")))
            }
        },
        None => (Vec::new(), Some("docker not connected".to_string())),
    };

    Snapshot {
        ts,
        host: host_metrics,
        containers,
        docker_error,
        stale_after_secs: 0, // set by the caller, which knows the tick interval
    }
}
