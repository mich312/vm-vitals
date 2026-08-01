//! vitals — know how your servers are doing.
//!
//! M0: load config, collect host + Docker metrics every tick into a shared
//! snapshot, and serve it as JSON on loopback (`/api/status`). No alerting,
//! storage, or auth yet — that's M1+ (see SPEC.md).

mod collect;
mod config;
mod web;

use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::time::interval;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::load()?;
    let snapshot: web::Shared = Arc::new(RwLock::new(None));

    // Collector loop.
    let coll = snapshot.clone();
    let tick = cfg.interval;
    tokio::spawn(async move {
        let docker = match bollard::Docker::connect_with_unix_defaults() {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::warn!("no docker socket ({e}); host metrics only");
                None
            }
        };
        let mut host = collect::host::HostCollector::new();
        let mut iv = interval(tick);
        loop {
            iv.tick().await;
            let snap = collect::collect(&mut host, docker.as_ref()).await;
            tracing::debug!(
                cpu = snap.host.cpu_pct,
                disk = snap.host.disk_used_pct,
                containers = snap.containers.len(),
                "tick"
            );
            *coll.write().await = Some(snap);
        }
    });

    // Web server.
    let state = web::AppState {
        snapshot,
        token: cfg.web_token.clone(),
    };
    let listener = tokio::net::TcpListener::bind(cfg.web_bind).await?;
    tracing::info!(
        "vitals listening on http://{} (api auth: {})",
        cfg.web_bind,
        if cfg.web_token.is_some() { "token" } else { "off" }
    );
    axum::serve(listener, web::router(state)).await?;
    Ok(())
}
