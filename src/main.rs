//! vitals — know how your servers are doing.
//!
//! M0: load config, collect host + Docker metrics every tick into a shared
//! snapshot, and serve it as JSON on loopback (`/api/status`). No alerting,
//! storage, or auth yet — that's M1+ (see SPEC.md).

mod auth;
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

    // Dashboard passkey auth, if the relying-party identity is configured.
    let auth = match (&cfg.rp_id, &cfg.rp_origin) {
        (Some(id), Some(origin)) => match auth::AuthState::new(id, origin, &cfg.data_dir) {
            Ok(a) => {
                tracing::info!("passkey dashboard auth enabled (rp_id={id})");
                Some(a)
            }
            Err(e) => {
                tracing::error!("passkey auth init failed ({e}); dashboard will be open");
                None
            }
        },
        _ => {
            tracing::warn!("rp_id/rp_origin not set — dashboard is unauthenticated");
            None
        }
    };

    // Web server.
    let state = web::AppState {
        snapshot,
        token: cfg.web_token.clone(),
        auth,
    };
    let listener = tokio::net::TcpListener::bind(cfg.web_bind).await?;
    tracing::info!(
        "vitals listening on http://{} (api token: {}, dashboard: {})",
        cfg.web_bind,
        if cfg.web_token.is_some() { "on" } else { "off" },
        if state.auth.is_some() { "passkey" } else { "open" }
    );
    axum::serve(listener, web::router(state)).await?;
    Ok(())
}
