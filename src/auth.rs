//! Passkey (WebAuthn) auth for the dashboard. The first visitor bootstraps the
//! admin by enrolling a passkey; after that, sign-in requires a passkey. A
//! successful ceremony issues a session cookie. Enrolled credentials persist
//! to `<data_dir>/auth.json`; ceremony + session state is in memory.
//!
//! The programmatic API (/api/*, MCP) keeps its bearer token — this is only the
//! browser session layer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

const SESSION_COOKIE: &str = "v_session";
const REG_COOKIE: &str = "v_reg";
const AUTH_COOKIE: &str = "v_auth";
const SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 12);
const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Persisted credential store.
#[derive(Default, Serialize, Deserialize)]
struct Store {
    user_id: Option<Uuid>,
    passkeys: Vec<Passkey>,
}

#[derive(Clone)]
pub struct AuthState {
    webauthn: Arc<Webauthn>,
    store: Arc<Mutex<Store>>,
    path: PathBuf,
    reg: Arc<Mutex<HashMap<String, (PasskeyRegistration, Instant)>>>,
    auth: Arc<Mutex<HashMap<String, (PasskeyAuthentication, Instant)>>>,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
}

impl AuthState {
    /// Build from config; None if rp_id/rp_origin aren't set (dashboard auth off).
    pub fn new(rp_id: &str, rp_origin: &str, data_dir: &str) -> anyhow::Result<Self> {
        let origin = Url::parse(rp_origin).context("rp_origin must be a URL")?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?
            .rp_name("vitals")
            .build()?;

        std::fs::create_dir_all(data_dir).ok();
        let path = PathBuf::from(data_dir).join("auth.json");
        let store = if path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&path)?)?
        } else {
            Store::default()
        };

        Ok(Self {
            webauthn: Arc::new(webauthn),
            store: Arc::new(Mutex::new(store)),
            path,
            reg: Arc::new(Mutex::new(HashMap::new())),
            auth: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn persist(&self) {
        if let Ok(s) = self.store.lock() {
            if let Ok(json) = serde_json::to_string_pretty(&*s) {
                let _ = std::fs::write(&self.path, json);
            }
        }
    }

    fn registered(&self) -> bool {
        self.store.lock().map(|s| !s.passkeys.is_empty()).unwrap_or(false)
    }

    /// Is the request carrying a valid session cookie?
    pub fn session_valid(&self, jar: &CookieJar) -> bool {
        let Some(tok) = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()) else {
            return false;
        };
        let mut s = self.sessions.lock().unwrap();
        match s.get(&tok) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                s.remove(&tok);
                false
            }
            None => false,
        }
    }

    /// Same check from the /api middleware, which has the raw Cookie header.
    pub fn session_valid_in(&self, cookie_header: Option<&str>) -> bool {
        let Some(h) = cookie_header else { return false };
        let Some(tok) = h
            .split(';')
            .filter_map(|kv| kv.trim().split_once('='))
            .find(|(k, _)| *k == SESSION_COOKIE)
            .map(|(_, v)| v.to_string())
        else {
            return false;
        };
        let s = self.sessions.lock().unwrap();
        matches!(s.get(&tok), Some(exp) if *exp > Instant::now())
    }

    fn new_session(&self) -> Cookie<'static> {
        let token = hex32();
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), Instant::now() + SESSION_TTL);
        session_cookie(token, SESSION_TTL)
    }
}

fn hex32() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn session_cookie(value: String, _ttl: Duration) -> Cookie<'static> {
    build_cookie(SESSION_COOKIE, value)
}

fn scratch_cookie(name: &'static str, value: String) -> Cookie<'static> {
    build_cookie(name, value)
}

// Session cookies (no explicit Max-Age); the server enforces the real TTL.
fn build_cookie(name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build()
}

// ---------------------------------------------------------------- handlers --

/// `/` — dashboard when signed in, otherwise the sign-in / bootstrap page.
pub async fn index(state: State<crate::web::AppState>, jar: CookieJar) -> Response {
    match &state.auth {
        Some(a) if a.session_valid(&jar) => Html(DASHBOARD_HTML).into_response(),
        Some(_) => Html(LOGIN_HTML).into_response(),
        // No auth configured: no gate, just show the dashboard.
        None => Html(DASHBOARD_HTML).into_response(),
    }
}

#[derive(Serialize)]
pub struct AuthStatus {
    registered: bool,
    signed_in: bool,
}

pub async fn status(state: State<crate::web::AppState>, jar: CookieJar) -> Json<AuthStatus> {
    let (registered, signed_in) = match &state.auth {
        Some(a) => (a.registered(), a.session_valid(&jar)),
        None => (true, true),
    };
    Json(AuthStatus { registered, signed_in })
}

pub async fn register_start(
    state: State<crate::web::AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<CreationChallengeResponse>), (StatusCode, String)> {
    let a = state.auth.as_ref().ok_or((StatusCode::NOT_FOUND, "auth off".into()))?;
    // Bootstrap allowed only when empty, or when already signed in (add a device).
    if a.registered() && !a.session_valid(&jar) {
        return Err((StatusCode::FORBIDDEN, "an admin already exists — sign in".into()));
    }

    let (user_id, exclude) = {
        let s = a.store.lock().unwrap();
        let uid = s.user_id.unwrap_or_else(Uuid::new_v4);
        let ex: Vec<CredentialID> = s.passkeys.iter().map(|p| p.cred_id().clone()).collect();
        (uid, if ex.is_empty() { None } else { Some(ex) })
    };

    let (ccr, reg_state) = a
        .webauthn
        .start_passkey_registration(user_id, "admin", "admin", exclude)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Remember the intended user_id for finish.
    a.store.lock().unwrap().user_id.get_or_insert(user_id);

    let rid = hex32();
    a.reg.lock().unwrap().insert(rid.clone(), (reg_state, Instant::now() + CEREMONY_TTL));
    Ok((jar.add(scratch_cookie(REG_COOKIE, rid)), Json(ccr)))
}

pub async fn register_finish(
    state: State<crate::web::AppState>,
    jar: CookieJar,
    Json(cred): Json<RegisterPublicKeyCredential>,
) -> Result<(CookieJar, StatusCode), (StatusCode, String)> {
    let a = state.auth.as_ref().ok_or((StatusCode::NOT_FOUND, "auth off".into()))?;
    let rid = jar.get(REG_COOKIE).map(|c| c.value().to_string())
        .ok_or((StatusCode::BAD_REQUEST, "no ceremony".into()))?;
    let reg_state = a.reg.lock().unwrap().remove(&rid).map(|(s, _)| s)
        .ok_or((StatusCode::BAD_REQUEST, "ceremony expired".into()))?;

    let passkey = a
        .webauthn
        .finish_passkey_registration(&cred, &reg_state)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    {
        let mut s = a.store.lock().unwrap();
        s.passkeys.push(passkey);
    }
    a.persist();

    let session = a.new_session();
    let jar = jar.remove(Cookie::from(REG_COOKIE)).add(session);
    Ok((jar, StatusCode::OK))
}

pub async fn login_start(
    state: State<crate::web::AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<RequestChallengeResponse>), (StatusCode, String)> {
    let a = state.auth.as_ref().ok_or((StatusCode::NOT_FOUND, "auth off".into()))?;
    let passkeys = a.store.lock().unwrap().passkeys.clone();
    if passkeys.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "no account yet — create one".into()));
    }
    let (rcr, auth_state) = a
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let aid = hex32();
    a.auth.lock().unwrap().insert(aid.clone(), (auth_state, Instant::now() + CEREMONY_TTL));
    Ok((jar.add(scratch_cookie(AUTH_COOKIE, aid)), Json(rcr)))
}

pub async fn login_finish(
    state: State<crate::web::AppState>,
    jar: CookieJar,
    Json(cred): Json<PublicKeyCredential>,
) -> Result<(CookieJar, StatusCode), (StatusCode, String)> {
    let a = state.auth.as_ref().ok_or((StatusCode::NOT_FOUND, "auth off".into()))?;
    let aid = jar.get(AUTH_COOKIE).map(|c| c.value().to_string())
        .ok_or((StatusCode::BAD_REQUEST, "no ceremony".into()))?;
    let auth_state = a.auth.lock().unwrap().remove(&aid).map(|(s, _)| s)
        .ok_or((StatusCode::BAD_REQUEST, "ceremony expired".into()))?;

    let result = a
        .webauthn
        .finish_passkey_authentication(&cred, &auth_state)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    {
        let mut s = a.store.lock().unwrap();
        for pk in s.passkeys.iter_mut() {
            pk.update_credential(&result);
        }
    }
    a.persist();

    let session = a.new_session();
    let jar = jar.remove(Cookie::from(AUTH_COOKIE)).add(session);
    Ok((jar, StatusCode::OK))
}

pub async fn logout(state: State<crate::web::AppState>, jar: CookieJar) -> impl IntoResponse {
    if let (Some(a), Some(tok)) = (&state.auth, jar.get(SESSION_COOKIE).map(|c| c.value().to_string())) {
        a.sessions.lock().unwrap().remove(&tok);
    }
    (jar.remove(Cookie::from(SESSION_COOKIE)), Redirect::to("/"))
}

// ------------------------------------------------------------------ pages --

const DASHBOARD_HTML: &str = include_str!("web/dashboard.html");
const LOGIN_HTML: &str = include_str!("web/login.html");
