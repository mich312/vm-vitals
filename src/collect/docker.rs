//! Container list + state + live usage via `bollard` over the Docker socket.
//!
//! Per container we inspect (restart count + health) and, for running ones,
//! read a **one-shot** stats sample. One-shot returns immediately instead of
//! blocking ~1-2s server-side waiting for a second CPU cycle, so we compute the
//! CPU delta ourselves against the previous tick. That is both faster and a
//! better measurement: the delta window becomes the collection interval rather
//! than an arbitrary 1s.
//!
//! Everything is bounded — a per-call timeout, an overall budget, and a cap on
//! in-flight requests — because an unbounded collector lets one wedged
//! container stall the tick, and a stalled tick means the monitor stops seeing.

use std::collections::HashMap;
use std::time::Duration;

use bollard::container::{ListContainersOptions, StatsOptions};
use bollard::Docker;
use futures_util::stream::{self, StreamExt};

use super::Container;

/// Most containers we'll query concurrently. One-shot stats returns promptly,
/// so this bounds socket/fd pressure without stretching the tick.
const MAX_INFLIGHT: usize = 16;

/// Per-request ceiling. Well under a typical tick so one sick container costs
/// its own sample, not the whole collection.
const PER_CALL_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
struct CpuSample {
    total: u64,
    system: u64,
}

/// Keeps the previous CPU counters so one-shot stats can yield a real delta.
#[derive(Default)]
pub struct DockerCollector {
    prev: HashMap<String, CpuSample>,
}

impl DockerCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn collect(
        &mut self,
        docker: &Docker,
        budget: Duration,
    ) -> anyhow::Result<Vec<Container>> {
        let opts = ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        };
        let list = tokio::time::timeout(PER_CALL_TIMEOUT, docker.list_containers(Some(opts)))
            .await
            .map_err(|_| anyhow::anyhow!("listing containers timed out"))??;

        let prev = self.prev.clone();

        let results = tokio::time::timeout(
            budget,
            stream::iter(list.into_iter().map(|c| {
                let prev = &prev;
                async move {
                    let id = c.id.clone().unwrap_or_default();
                    let name = c
                        .names
                        .and_then(|n| n.into_iter().next())
                        .map(|n| n.trim_start_matches('/').to_string())
                        .unwrap_or_else(|| id.chars().take(12).collect());
                    let image = c.image.unwrap_or_default();
                    let state = c.state.unwrap_or_default();
                    let status = c.status.unwrap_or_default();
                    let running = state == "running";

                    // Address by id: a container with no name entry would make a
                    // name-keyed inspect 404 forever.
                    let key = if id.is_empty() { name.clone() } else { id.clone() };

                    let (restarts, health) = match tokio::time::timeout(
                        PER_CALL_TIMEOUT,
                        docker.inspect_container(&key, None),
                    )
                    .await
                    {
                        Ok(Ok(det)) => {
                            let health = det
                                .state
                                .and_then(|s| s.health)
                                .and_then(|h| h.status)
                                .map(|st| format!("{st:?}").to_lowercase());
                            (det.restart_count, health)
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("inspect {name}: {e}");
                            (None, None)
                        }
                        Err(_) => {
                            tracing::debug!("inspect {name}: timed out");
                            (None, None)
                        }
                    };

                    let (cpu_pct, mem_mb, mem_limit_mb, sample) = if running {
                        match sample_stats(docker, &key, prev.get(&key).copied()).await {
                            Some((c, m, l, s)) => (c, Some(m), l, Some(s)),
                            None => (None, None, None, None),
                        }
                    } else {
                        (None, None, None, None)
                    };

                    (
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
                        },
                        key,
                        sample,
                    )
                }
            }))
            .buffer_unordered(MAX_INFLIGHT)
            .collect::<Vec<_>>(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("container collection exceeded its budget"))?;

        // Retain counters only for containers we still see, so the map can't
        // grow without bound as containers churn.
        let mut next = HashMap::with_capacity(results.len());
        let mut out = Vec::with_capacity(results.len());
        for (container, key, sample) in results {
            if let Some(s) = sample {
                next.insert(key, s);
            }
            out.push(container);
        }
        self.prev = next;
        Ok(out)
    }
}

/// One one-shot stats read → (cpu%, mem MB, mem limit MB, counters for next tick).
///
/// CPU is `None` rather than `0.0` when it can't be computed: on the first tick
/// for a container, or when the daemon omits the system counter. Reporting a
/// busy container as 0% would silently blind CPU alerting.
async fn sample_stats(
    docker: &Docker,
    key: &str,
    prev: Option<CpuSample>,
) -> Option<(Option<f32>, u64, Option<u64>, CpuSample)> {
    let mut stream = docker.stats(
        key,
        Some(StatsOptions {
            stream: false,
            one_shot: true,
        }),
    );
    let s = tokio::time::timeout(PER_CALL_TIMEOUT, stream.next())
        .await
        .ok()??
        .ok()?;

    let total = s.cpu_stats.cpu_usage.total_usage;
    let system = s.cpu_stats.system_cpu_usage?;
    let sample = CpuSample { total, system };

    let ncpu = s
        .cpu_stats
        .online_cpus
        .or_else(|| s.cpu_stats.cpu_usage.percpu_usage.as_ref().map(|v| v.len() as u64))
        .unwrap_or(1) as f64;

    // Counters are monotonic but reset when a container restarts; a negative
    // delta means "restarted", not "idle", so report unknown rather than 0.
    let cpu = prev.and_then(|p| {
        let cpu_delta = total.checked_sub(p.total)? as f64;
        let sys_delta = system.checked_sub(p.system)? as f64;
        if sys_delta <= 0.0 {
            return None;
        }
        let pct = (cpu_delta / sys_delta) * ncpu * 100.0;
        pct.is_finite().then(|| pct.clamp(0.0, ncpu * 100.0) as f32)
    });

    let mem_mb = s.memory_stats.usage.unwrap_or(0) / 1_000_000;
    let limit_mb = s.memory_stats.limit.map(|l| l / 1_000_000);
    Some((cpu, mem_mb, limit_mb, sample))
}
