//! vitals — know how your servers are doing.
//!
//! M0: load config, collect host + Docker metrics every tick into a shared
//! snapshot, and serve it as JSON on loopback (`/api/status`). No alerting,
//! storage, or auth yet — that's M1+ (see SPEC.md).

mod auth;
mod collect;
mod config;
mod endpoints;
mod mcp;
mod oauth;
mod store;
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

    // Time-series history store (SQLite, tiered rollups).
    let store = Arc::new(store::Store::open(&format!("{}/vitals.db", cfg.data_dir))?);

    // Shared Docker handle (cheap to clone — wraps an Arc). Used by the
    // collector loop and by the live-log SSE stream in the web layer.
    let docker = match bollard::Docker::connect_with_unix_defaults() {
        Ok(d) => Some(d),
        Err(e) => {
            tracing::warn!("no docker socket ({e}); host metrics only");
            None
        }
    };

    // Recent-events ring (restarts, health/state flips, appear/disappear).
    let events: web::Events = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));

    // Collector loop.
    let coll = snapshot.clone();
    let store_w = store.clone();
    let events_w = events.clone();
    let tick = cfg.interval;
    let docker_loop = docker.clone();
    tokio::spawn(async move {
        let docker = docker_loop;
        let mut host = collect::host::HostCollector::new();
        let mut iv = interval(tick);
        let mut prev: Vec<collect::Container> = Vec::new();
        let mut seeded = false;
        loop {
            iv.tick().await;
            let snap = collect::collect(&mut host, docker.as_ref()).await;

            // Diff against the previous tick into the events ring (skip the
            // first tick so we don't flood with "appeared" on startup).
            if seeded {
                let evs = collect::diff_events(&prev, &snap.containers, snap.ts);
                if !evs.is_empty() {
                    if let Ok(mut q) = events_w.lock() {
                        for e in evs {
                            q.push_front(e);
                        }
                        while q.len() > 100 {
                            q.pop_back();
                        }
                    }
                }
            }
            prev = snap.containers.clone();
            seeded = true;

            // Persist raw samples for the history charts (host + per-container).
            let mut pts: Vec<(String, f64)> = vec![
                ("host.cpu".into(), snap.host.cpu_pct as f64),
                ("host.mem".into(), snap.host.mem_used_pct as f64),
                ("host.disk".into(), snap.host.disk_used_pct as f64),
                ("host.load".into(), snap.host.load1),
                ("host.swap".into(), snap.host.swap_used_mb as f64),
                ("host.net_rx".into(), snap.host.net_rx_bps as f64),
                ("host.net_tx".into(), snap.host.net_tx_bps as f64),
            ];
            for c in &snap.containers {
                if let Some(v) = c.cpu_pct {
                    pts.push((format!("c.{}.cpu", c.name), v as f64));
                }
                if let Some(v) = c.mem_mb {
                    pts.push((format!("c.{}.mem", c.name), v as f64));
                }
            }
            let (sw, ts) = (store_w.clone(), snap.ts);
            tokio::task::spawn_blocking(move || sw.write(ts, &pts)).await.ok();

            *coll.write().await = Some(snap);
        }
    });

    // Compactor: roll raw→5min→1hour and prune, every 5 minutes.
    let store_c = store.clone();
    tokio::spawn(async move {
        let mut iv = interval(std::time::Duration::from_secs(300));
        loop {
            iv.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let s = store_c.clone();
            tokio::task::spawn_blocking(move || s.compact(now)).await.ok();
        }
    });

    // Endpoint monitor (reachability + TLS cert expiry), if configured.
    let ep_status: endpoints::Shared = Arc::new(RwLock::new(Vec::new()));
    if !cfg.endpoints.is_empty() {
        let out = ep_status.clone();
        let eps = cfg.endpoints.clone();
        let iv = cfg.endpoints_interval;
        tracing::info!("endpoint monitor: {} endpoints every {:?}", eps.len(), iv);
        tokio::spawn(async move { endpoints::run(eps, out, iv).await });
    }

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

    // OAuth 2.1 authorization server for MCP — enabled when passkey auth is
    // configured (it reuses the passkey session for consent).
    let oauth = cfg
        .rp_origin
        .as_ref()
        .filter(|_| auth.is_some())
        .map(|origin| Arc::new(oauth::OAuthState::new(origin, &cfg.data_dir)));
    if oauth.is_some() {
        tracing::info!("MCP OAuth server enabled (issuer={})", cfg.rp_origin.as_deref().unwrap_or(""));
    }

    // Web server.
    let state = web::AppState {
        snapshot,
        token: cfg.web_token.clone(),
        auth,
        store,
        docker,
        events,
        endpoints: ep_status,
        control: cfg.docker_control,
        oauth,
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
