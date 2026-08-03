//! Container list + state + live usage via `bollard` over the Docker socket.
//! Per container we inspect (restart count + health) and, for running ones,
//! read one non-streaming stats sample (CPU% + memory). All containers are
//! processed concurrently so a tick stays ~1–2s regardless of count.

use bollard::container::{ListContainersOptions, StatsOptions};
use bollard::Docker;
use futures_util::{future::join_all, StreamExt};

use super::Container;

pub async fn collect(docker: &Docker) -> anyhow::Result<Vec<Container>> {
    let opts = ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let list = docker.list_containers(Some(opts)).await?;

    let tasks = list.into_iter().map(|c| async move {
        let name = c
            .names
            .and_then(|n| n.into_iter().next())
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let image = c.image.unwrap_or_default();
        let state = c.state.unwrap_or_default();
        let status = c.status.unwrap_or_default();
        let running = state == "running";

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

        let (cpu_pct, mem_mb, mem_limit_mb) = if running {
            match sample_stats(docker, &name).await {
                Some((c, m, l)) => (Some(c), Some(m), l),
                None => (None, None, None),
            }
        } else {
            (None, None, None)
        };

        Container {
            name,
            image,
            state,
            status,
            health,
            restarts,
            cpu_pct,
            mem_mb,
            mem_limit_mb,
        }
    });

    Ok(join_all(tasks).await)
}

/// One non-streaming stats read → (cpu%, mem MB, mem limit MB). `stream:false`
/// returns a sample that carries `precpu_stats`, so the CPU delta is meaningful.
async fn sample_stats(docker: &Docker, name: &str) -> Option<(f32, u64, Option<u64>)> {
    let mut stream = docker.stats(
        name,
        Some(StatsOptions {
            stream: false,
            one_shot: false,
        }),
    );
    let s = stream.next().await?.ok()?;

    let cpu_delta =
        s.cpu_stats.cpu_usage.total_usage as f64 - s.precpu_stats.cpu_usage.total_usage as f64;
    let sys_delta = s.cpu_stats.system_cpu_usage.unwrap_or(0) as f64
        - s.precpu_stats.system_cpu_usage.unwrap_or(0) as f64;
    let ncpu = s
        .cpu_stats
        .online_cpus
        .or_else(|| s.cpu_stats.cpu_usage.percpu_usage.as_ref().map(|v| v.len() as u64))
        .unwrap_or(1) as f64;
    let cpu = if sys_delta > 0.0 && cpu_delta > 0.0 {
        ((cpu_delta / sys_delta) * ncpu * 100.0) as f32
    } else {
        0.0
    };

    let mem_mb = s.memory_stats.usage.unwrap_or(0) / 1_000_000;
    let limit_mb = s.memory_stats.limit.map(|l| l / 1_000_000);
    Some((cpu, mem_mb, limit_mb))
}
