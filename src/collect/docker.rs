//! Container list + state via `bollard` over the Docker socket. M0 reports
//! name/image/state/status/health/restarts; per-container cpu/mem (the stats
//! stream) comes in a later milestone.

use bollard::container::ListContainersOptions;
use bollard::Docker;

use super::Container;

pub async fn collect(docker: &Docker) -> anyhow::Result<Vec<Container>> {
    let opts = ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let list = docker.list_containers(Some(opts)).await?;

    let mut out = Vec::with_capacity(list.len());
    for c in list {
        let name = c
            .names
            .and_then(|n| n.into_iter().next())
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let image = c.image.unwrap_or_default();
        let state = c.state.unwrap_or_default();
        let status = c.status.unwrap_or_default();

        // Restart count + health need an inspect.
        let (restarts, health) = match docker.inspect_container(&name, None).await {
            Ok(det) => {
                let restarts = det.restart_count.unwrap_or(0);
                let health = det
                    .state
                    .and_then(|s| s.health)
                    .and_then(|h| h.status)
                    .map(|st| format!("{st:?}").to_lowercase());
                (restarts, health)
            }
            Err(_) => (0, None),
        };

        out.push(Container {
            name,
            image,
            state,
            status,
            health,
            restarts,
            cpu_pct: None,
            mem_mb: None,
        });
    }
    Ok(out)
}
