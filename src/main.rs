//! vitals — know how your servers are doing.
//!
//! Load config, collect host + Docker metrics every tick into a shared snapshot
//! and a small time-series store, and serve both as JSON plus a passkey-gated
//! dashboard. See SPEC.md for the roadmap.

mod auth;
mod collect;
mod config;
mod store;
mod web;

use std::sync::Arc;
use std::time::Duration;

use bollard::Docker;
use tokio::sync::RwLock;
use tokio::time::{interval, MissedTickBehavior};

/// Docker API request timeout. The old default was 120s — meaningless inside a
/// 15s loop, where it just parks the collector for eight intervals.
const DOCKER_TIMEOUT_SECS: u64 = 10;

fn connect_docker(endpoint: &str) -> Result<Docker, bollard::errors::Error> {
    if endpoint.starts_with("tcp://") || endpoint.starts_with("http://") {
        Docker::connect_with_http(endpoint, DOCKER_TIMEOUT_SECS, bollard::API_DEFAULT_VERSION)
    } else {
        Docker::connect_with_unix(endpoint, DOCKER_TIMEOUT_SECS, bollard::API_DEFAULT_VERSION)
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // A misconfiguration is an operator problem, not a crash — print the
        // chain plainly rather than a Rust backtrace.
        eprintln!("vitals: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::load()?;

    // Before anything opens a file under it.
    std::fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| anyhow::anyhow!("creating data_dir {}: {e}", cfg.data_dir))?;

    // Dashboard passkey auth, if the relying-party identity is configured.
    // An init failure here is fatal: silently serving an open dashboard because
    // auth.json was unreadable is the worst possible interpretation of an error.
    let auth = match (&cfg.rp_id, &cfg.rp_origin) {
        (Some(id), Some(origin)) => {
            let a = auth::AuthState::new(id, origin, &cfg.data_dir)
                .map_err(|e| anyhow::anyhow!("passkey auth init failed: {e:#}"))?;
            tracing::info!("passkey dashboard auth enabled (rp_id={id})");
            Some(a)
        }
        (None, None) => None,
        _ => anyhow::bail!("web.rp_id and web.rp_origin must be set together"),
    };

    // Refuse to publish an unauthenticated dashboard. Loopback stays open so
    // local development needs no ceremony, but binding a public address with no
    // credential configured is almost always a mistake, not a choice.
    if auth.is_none() && cfg.web_token.is_none() {
        anyhow::ensure!(
            cfg.web_bind.ip().is_loopback(),
            "refusing to serve unauthenticated on {}: set web.rp_id + web.rp_origin \
             for passkey sign-in, or web.token (or $VITALS_TOKEN) for the API, \
             or bind to 127.0.0.1 and front it with an authenticating proxy",
            cfg.web_bind
        );
        tracing::warn!(
            "no auth configured — dashboard and API are open on {} (loopback only)",
            cfg.web_bind
        );
    }

    let snapshot: web::Shared = Arc::new(RwLock::new(None));
    let store = Arc::new(store::Store::open(&format!("{}/vitals.db", cfg.data_dir))?);

    // Collector loop.
    let coll = snapshot.clone();
    let store_w = store.clone();
    let tick = cfg.interval;
    let socket = cfg.docker_socket.clone();
    tokio::spawn(async move {
        let mut host = collect::host::HostCollector::new();
        let mut dcoll = collect::DockerCollector::new();
        let mut docker: Option<Docker> = None;
        let mut warned = false;

        // Default (Burst) fires catch-up ticks back-to-back after an overrun,
        // hammering a daemon that is already struggling — and they're wasted
        // work anyway, since same-second samples overwrite each other.
        let mut iv = interval(tick);
        iv.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Leave room in the tick for the host collection and the DB write.
        let budget = tick.mul_f32(0.6).max(Duration::from_secs(2));
        let stale_after = tick.as_secs().saturating_mul(3).max(30);

        loop {
            iv.tick().await;

            // Reconnect lazily: connecting once at startup means a daemon
            // restart blinds the collector permanently.
            if docker.is_none() {
                match connect_docker(&socket) {
                    Ok(d) => {
                        tracing::info!("connected to docker at {socket}");
                        docker = Some(d);
                        warned = false;
                    }
                    Err(e) => {
                        if !warned {
                            tracing::warn!("no docker at {socket} ({e}); host metrics only");
                            warned = true;
                        }
                    }
                }
            }

            let mut snap = match docker.as_ref() {
                Some(d) => collect::collect(&mut host, Some((d, &mut dcoll)), budget).await,
                None => collect::collect(&mut host, None, budget).await,
            };
            snap.stale_after_secs = stale_after;
            // Force a reconnect next tick rather than reusing a dead client.
            if snap.docker_error.is_some() {
                docker = None;
            }

            // Publish first: nothing below depends on the write, and the write
            // can block behind a compaction.
            let pts = sample_points(&snap);
            let ts = snap.ts;
            *coll.write().await = Some(snap);

            let sw = store_w.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || sw.write(ts, &pts)).await {
                tracing::warn!("store write task failed: {e}");
            }
        }
    });

    // Compactor: roll raw→5min→1hour and prune.
    let store_c = store.clone();
    tokio::spawn(async move {
        let mut iv = interval(Duration::from_secs(300));
        iv.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            iv.tick().await;
            let now = collect::now_secs() as i64;
            let s = store_c.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || s.compact(now)).await {
                tracing::warn!("compaction task failed: {e}");
            }
        }
    });

    // Expire ceremonies and sessions. Without this, `/auth/login/start` — which
    // is unauthenticated — grows the ceremony map for the process lifetime.
    if let Some(a) = auth.clone() {
        tokio::spawn(async move {
            let mut iv = interval(Duration::from_secs(60));
            iv.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                iv.tick().await;
                a.sweep();
            }
        });
    }

    // Web server.
    let state = web::AppState {
        snapshot,
        token: cfg.web_token.clone(),
        auth,
        store,
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

/// Flatten a snapshot into the (metric, value) pairs the store records.
fn sample_points(snap: &collect::Snapshot) -> Vec<(String, f64)> {
    let mut pts: Vec<(String, f64)> = vec![
        ("host.cpu".into(), snap.host.cpu_pct as f64),
        ("host.mem".into(), snap.host.mem_used_pct as f64),
        ("host.disk".into(), snap.host.disk_used_pct as f64),
        ("host.load".into(), snap.host.load1),
        ("host.swap".into(), snap.host.swap_used_mb as f64),
    ];
    for c in &snap.containers {
        // Container names are `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, so they can contain
        // `.`; `\u{1}` can't, which keeps the key unambiguous.
        if let Some(v) = c.cpu_pct {
            pts.push((format!("c\u{1}{}\u{1}cpu", c.name), v as f64));
        }
        if let Some(v) = c.mem_mb {
            pts.push((format!("c\u{1}{}\u{1}mem", c.name), v as f64));
        }
    }
    pts
}
