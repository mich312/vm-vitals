//! The HTTP surface: the dashboard (passkey-auth), the JSON API + MCP (bearer
//! token), and health. `/api/*` accepts EITHER the bearer token (API/MCP) OR a
//! valid dashboard session cookie, so the browser can read the same data.

use std::sync::Arc;

use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{from_fn, from_fn_with_state, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::auth::{self, AuthState};
use crate::collect::Snapshot;
use crate::config::Secret;
use crate::store::Store;

/// Latest snapshot, shared between the collector loop and the web handlers.
pub type Shared = Arc<RwLock<Option<Snapshot>>>;

#[derive(Clone)]
pub struct AppState {
    pub snapshot: Shared,
    /// Bearer token for /api/* + MCP. None = no token gate.
    pub token: Option<Secret>,
    /// Passkey auth for the dashboard. None = dashboard unauthenticated.
    pub auth: Option<AuthState>,
    /// Time-series history store.
    pub store: Arc<Store>,
}

pub fn router(state: AppState) -> Router {
    // /api/* : bearer token OR a valid dashboard session.
    let api = Router::new()
        .route("/api/status", get(status))
        .route("/api/series", get(series))
        .route_layer(from_fn_with_state(state.clone(), require_api_auth));

    Router::new()
        .route("/", get(auth::index))
        .route("/healthz", get(healthz))
        // POST: a state-changing endpoint reachable by navigation is CSRF-able.
        .route("/logout", post(auth::logout))
        .route("/auth/status", get(auth::status))
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .merge(api)
        .layer(from_fn(security_headers))
        .with_state(state)
}

/// Liveness *and* collector freshness. A monitor whose collector has stopped
/// must not keep answering "ok" — that is the failure this endpoint exists to
/// catch, and reporting health while blind is worse than reporting nothing.
async fn healthz(State(state): State<AppState>) -> (StatusCode, String) {
    match state.snapshot.read().await.as_ref() {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "starting: no snapshot yet\n".into(),
        ),
        Some(s) if s.age_secs() > s.stale_after_secs => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("stale: last collection {}s ago\n", s.age_secs()),
        ),
        Some(s) if s.docker_error.is_some() => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "degraded: docker unreachable ({})\n",
                s.docker_error.as_deref().unwrap_or("unknown")
            ),
        ),
        Some(_) => (StatusCode::OK, "ok\n".into()),
    }
}

async fn status(State(state): State<AppState>) -> Json<Option<Snapshot>> {
    Json(state.snapshot.read().await.clone())
}

#[derive(Deserialize)]
struct SeriesQuery {
    metric: String,
    from: i64,
    to: i64,
    res: Option<i64>,
}

/// Hard ceiling on points returned, independent of retention. Keeps a future
/// retention change from silently turning this into a memory event.
const MAX_POINTS: usize = 20_000;

async fn series(
    State(state): State<AppState>,
    Query(q): Query<SeriesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // `from`/`to` are unvalidated i64 from the query string: `to - from` would
    // overflow. Saturating arithmetic keeps that benign even if a future
    // `overflow-checks = true` would otherwise turn it into a panic (= abort).
    if q.to < q.from {
        return Err((StatusCode::BAD_REQUEST, "to must be >= from".into()));
    }
    let span = q.to.saturating_sub(q.from);

    let res = match q.res {
        None => crate::store::pick_res(span),
        Some(r) if crate::store::is_valid_res(r) => r,
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "res must be one of 15, 300, 3600".into(),
            ))
        }
    };

    // SQLite work is synchronous and takes a mutex the compactor also holds.
    // Running it inline would park a runtime worker; enough concurrent requests
    // would park them all and stall every route, including /healthz.
    let store = state.store.clone();
    let metric = q.metric.clone();
    let (from, to) = (q.from, q.to);
    let s = tokio::task::spawn_blocking(move || store.series(&metric, from, to, res, MAX_POINTS))
        .await
        .map_err(|e| {
            tracing::error!("series task failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed".into())
        })?
        .map_err(|e| {
            tracing::warn!("series query: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed".into())
        })?;

    Ok(Json(serde_json::json!({
        "res": res, "t": s.t, "avg": s.avg, "min": s.min, "max": s.max,
    })))
}

/// Constant-time byte comparison. Length still differs early — an unavoidable
/// leak without hashing — but the content comparison does not short-circuit.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn require_api_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();

    // 1) Bearer token (API / MCP clients).
    if let Some(expected) = state.token.as_ref() {
        let ok = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|got| ct_eq(got.as_bytes(), expected.expose().as_bytes()))
            .unwrap_or(false);
        if ok {
            return Ok(next.run(req).await);
        }
    }

    // 2) Dashboard session cookie (browser). Parsed through the same CookieJar
    //    the page handlers use, so the two surfaces cannot disagree about which
    //    cookie value counts when a header carries duplicates.
    if let Some(a) = &state.auth {
        let jar = CookieJar::from_headers(headers);
        if a.session_valid(&jar) {
            return Ok(next.run(req).await);
        }
    }

    // 3) Nothing configured at all → open. `main` refuses to start in this
    //    state unless the bind address is loopback, so this is dev-only.
    if state.token.is_none() && state.auth.is_none() {
        return Ok(next.run(req).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Baseline response hardening. The CSP still needs `'unsafe-inline'` because
/// both pages carry inline `<script>`/`<style>`; everything else is denied, so
/// no external origin can be reached and the page cannot be framed.
async fn security_headers(req: Request, next: Next) -> Response {
    const CSP: &str = "default-src 'none'; \
         script-src 'unsafe-inline'; \
         style-src 'unsafe-inline'; \
         img-src 'self' data:; \
         connect-src 'self'; \
         base-uri 'none'; \
         form-action 'self'; \
         frame-ancestors 'none'";

    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "referrer-policy",
        HeaderValue::from_static("no-referrer"),
    );
    // Metrics and auth state must never sit in a shared proxy cache.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    h.insert(header::VARY, HeaderValue::from_static("Cookie"));
    res
}
