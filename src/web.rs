//! The HTTP surface. M0: a JSON status endpoint + health check. `/api/*` is
//! gated by a bearer token when one is configured; `/healthz` is always open.
//! This same API is what the MCP adapter and the (optional) dashboard read.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{from_fn_with_state, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use tokio::sync::RwLock;

use crate::collect::Snapshot;

#[derive(Clone)]
pub struct AppState {
    pub snapshot: Arc<RwLock<Option<Snapshot>>>,
    pub token: Option<String>,
}

/// Latest snapshot, shared between the collector loop and the web handlers.
pub type Shared = Arc<RwLock<Option<Snapshot>>>;

pub fn router(state: AppState) -> Router {
    // Everything under /api requires the bearer token (when set).
    let api = Router::new()
        .route("/api/status", get(status))
        .route_layer(from_fn_with_state(state.clone(), require_bearer));

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(api)
        .with_state(state)
}

async fn status(State(state): State<AppState>) -> Json<Option<Snapshot>> {
    Json(state.snapshot.read().await.clone())
}

/// Reject /api/* unless the request carries `Authorization: Bearer <token>`.
/// No token configured → open (intended for loopback-only dev).
async fn require_bearer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(expected) = state.token.as_deref() else {
        return Ok(next.run(req).await);
    };
    let ok = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|got| got == expected)
        .unwrap_or(false);

    if ok {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
