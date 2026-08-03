//! The HTTP surface: the dashboard (passkey-auth), the JSON API + MCP (bearer
//! token), and health. `/api/*` accepts EITHER the bearer token (API/MCP) OR a
//! valid dashboard session cookie, so the browser can read the same data.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use tokio::sync::RwLock;

use crate::auth::{self, AuthState};
use crate::collect::Snapshot;

/// Latest snapshot, shared between the collector loop and the web handlers.
pub type Shared = Arc<RwLock<Option<Snapshot>>>;

#[derive(Clone)]
pub struct AppState {
    pub snapshot: Shared,
    /// Bearer token for /api/* + MCP. None = no token gate.
    pub token: Option<String>,
    /// Passkey auth for the dashboard. None = dashboard unauthenticated.
    pub auth: Option<AuthState>,
}

pub fn router(state: AppState) -> Router {
    // /api/* : bearer token OR a valid dashboard session.
    let api = Router::new()
        .route("/api/status", get(status))
        .route_layer(from_fn_with_state(state.clone(), require_api_auth));

    Router::new()
        .route("/", get(auth::index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/logout", get(auth::logout))
        .route("/auth/status", get(auth::status))
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .merge(api)
        .with_state(state)
}

async fn status(State(state): State<AppState>) -> Json<Option<Snapshot>> {
    Json(state.snapshot.read().await.clone())
}

async fn require_api_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();

    // 1) Bearer token (API / MCP clients).
    if let Some(expected) = state.token.as_deref() {
        let ok = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|got| got == expected)
            .unwrap_or(false);
        if ok {
            return Ok(next.run(req).await);
        }
    }

    // 2) Dashboard session cookie (browser).
    if let Some(a) = &state.auth {
        let cookie = headers.get(header::COOKIE).and_then(|h| h.to_str().ok());
        if a.session_valid_in(cookie) {
            return Ok(next.run(req).await);
        }
    }

    // 3) Nothing configured at all → open (loopback dev).
    if state.token.is_none() && state.auth.is_none() {
        return Ok(next.run(req).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}
