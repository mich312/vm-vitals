//! Passkey (WebAuthn) auth for the dashboard. The first visitor bootstraps the
//! admin by enrolling a passkey; after that, sign-in requires a passkey. A
//! successful ceremony issues a session cookie. Enrolled credentials persist
//! to `<data_dir>/auth.json`; ceremony + session state is in memory.
//!
//! The programmatic API (/api/*, MCP) keeps its bearer token — this is only the
//! browser session layer.
//!
//! Two invariants worth stating, because getting either wrong is a full auth
//! bypass:
//!
//! 1. **Authorization is re-checked at `finish`, not just `start`.** Otherwise a
//!    ceremony begun during the pre-bootstrap window can be parked and redeemed
//!    after an admin exists, silently enrolling a second credential.
//! 2. **Ceremony and session expiry are absolute (`SystemTime`), not monotonic.**
//!    `Instant` stops advancing while a VM is suspended, which would silently
//!    extend every TTL across a snapshot/resume.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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

// `__Host-` forces the browser to enforce Secure + Path=/ + no Domain, which
// stops a sibling subdomain from shadowing our cookie with its own value.
const SESSION_COOKIE: &str = "__Host-v_session";
const REG_COOKIE: &str = "__Host-v_reg";
const AUTH_COOKIE: &str = "__Host-v_auth";

const SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 12);
const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Hard ceiling on in-flight ceremonies. `/auth/*/start` is unauthenticated, so
/// without a cap it is a free memory-exhaustion primitive against the daemon.
const MAX_CEREMONIES: usize = 64;
/// Hard ceiling on live sessions. Reached only by a real passkey login, so this
/// is a backstop rather than a defence.
const MAX_SESSIONS: usize = 1024;

/// Persisted credential store.
#[derive(Default, Serialize, Deserialize)]
struct Store {
    user_id: Option<Uuid>,
    passkeys: Vec<Passkey>,
}

/// What a pending registration ceremony was authorized to do. Recorded at
/// `start` and re-validated at `finish`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegMode {
    /// No admin existed: this ceremony may bootstrap one.
    Bootstrap,
    /// An authenticated admin is adding another device.
    AddDevice,
}

/// A pending registration: the library's ceremony state, what it was authorized
/// to do, and when it stops being redeemable.
type PendingReg = (PasskeyRegistration, RegMode, SystemTime);
type PendingAuth = (PasskeyAuthentication, SystemTime);

#[derive(Clone)]
pub struct AuthState {
    webauthn: Arc<Webauthn>,
    store: Arc<Mutex<Store>>,
    path: PathBuf,
    reg: Arc<Mutex<HashMap<String, PendingReg>>>,
    auth: Arc<Mutex<HashMap<String, PendingAuth>>>,
    sessions: Arc<Mutex<HashMap<String, SystemTime>>>,
}

impl AuthState {
    /// Build from config. Errors here are fatal to the caller by design — a
    /// dashboard that silently falls back to "no auth" is worse than one that
    /// refuses to start.
    pub fn new(rp_id: &str, rp_origin: &str, data_dir: &str) -> anyhow::Result<Self> {
        let origin = Url::parse(rp_origin).context("rp_origin must be a URL")?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?
            .rp_name("vitals")
            .build()?;

        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data_dir {data_dir}"))?;
        let path = PathBuf::from(data_dir).join("auth.json");
        let store = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&raw).with_context(|| {
                format!(
                    "parsing {} — refusing to start with unreadable credentials; \
                     move the file aside to re-bootstrap",
                    path.display()
                )
            })?
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

    /// Write `auth.json` atomically: temp file in the same directory, fsync,
    /// rename. A crash mid-write must never leave a truncated file, because a
    /// truncated file is an unparseable one and that blocks startup.
    fn persist(&self) -> anyhow::Result<()> {
        let json = {
            let s = self.store.lock().map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
            serde_json::to_string_pretty(&*s)?
        };

        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = open_private(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("replacing {}", self.path.display()))?;
        Ok(())
    }

    /// Is an admin enrolled? Fails **closed**: if we can't tell, assume yes, so
    /// a lock failure can never re-open the bootstrap path.
    fn registered(&self) -> bool {
        self.store.lock().map_or(true, |s| !s.passkeys.is_empty())
    }

    /// Is the request carrying a valid session cookie? This is the single
    /// session check — the API middleware builds a `CookieJar` and calls it too,
    /// so both surfaces agree on how a cookie header is parsed.
    pub fn session_valid(&self, jar: &CookieJar) -> bool {
        let Some(tok) = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()) else {
            return false;
        };
        let mut s = self.sessions.lock().unwrap();
        match s.get(&tok) {
            Some(exp) if *exp > SystemTime::now() => true,
            Some(_) => {
                s.remove(&tok);
                false
            }
            None => false,
        }
    }

    fn new_session(&self) -> Cookie<'static> {
        let token = hex32();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, exp| *exp > SystemTime::now());
        if s.len() >= MAX_SESSIONS {
            // Drop the soonest-to-expire rather than refuse a legitimate login.
            if let Some(oldest) = s.iter().min_by_key(|(_, e)| **e).map(|(k, _)| k.clone()) {
                s.remove(&oldest);
            }
        }
        s.insert(token.clone(), SystemTime::now() + SESSION_TTL);
        drop(s);
        build_cookie(SESSION_COOKIE, token)
    }

    /// Drop everything expired. Called on a timer from `main`, so state can't
    /// accumulate on a process that is never signed into again.
    pub fn sweep(&self) {
        let now = SystemTime::now();
        if let Ok(mut m) = self.reg.lock() {
            m.retain(|_, (_, _, exp)| *exp > now);
        }
        if let Ok(mut m) = self.auth.lock() {
            m.retain(|_, (_, exp)| *exp > now);
        }
        if let Ok(mut m) = self.sessions.lock() {
            m.retain(|_, exp| *exp > now);
        }
    }
}

#[cfg(unix)]
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::create(path)
}

fn hex32() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

/// A removal cookie must carry the same `Path` as the one it clears, or the
/// browser scopes the deletion to the request path and the original survives.
fn clear_cookie(name: &'static str) -> Cookie<'static> {
    Cookie::build((name, "")).path("/").build()
}

/// Insert a ceremony, refusing once the map is full. Expired entries are
/// dropped first so a burst of abandoned ceremonies can't wedge the endpoint.
fn insert_capped<V>(
    map: &Mutex<HashMap<String, V>>,
    key: String,
    val: V,
    exp_of: impl Fn(&V) -> SystemTime,
) -> Result<(), (StatusCode, String)> {
    let mut m = map.lock().unwrap();
    let now = SystemTime::now();
    m.retain(|_, v| exp_of(v) > now);
    if m.len() >= MAX_CEREMONIES {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "too many ceremonies in flight — try again shortly".into(),
        ));
    }
    m.insert(key, val);
    Ok(())
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
    let signed_in = a.session_valid(&jar);
    let mode = match (a.registered(), signed_in) {
        (false, _) => RegMode::Bootstrap,
        (true, true) => RegMode::AddDevice,
        (true, false) => {
            return Err((StatusCode::FORBIDDEN, "an admin already exists — sign in".into()))
        }
    };

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
    insert_capped(
        &a.reg,
        rid.clone(),
        (reg_state, mode, SystemTime::now() + CEREMONY_TTL),
        |(_, _, e)| *e,
    )?;
    Ok((jar.add(build_cookie(REG_COOKIE, rid)), Json(ccr)))
}

pub async fn register_finish(
    state: State<crate::web::AppState>,
    jar: CookieJar,
    Json(cred): Json<RegisterPublicKeyCredential>,
) -> Result<(CookieJar, StatusCode), (StatusCode, String)> {
    let a = state.auth.as_ref().ok_or((StatusCode::NOT_FOUND, "auth off".into()))?;
    let rid = jar
        .get(REG_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or((StatusCode::BAD_REQUEST, "no ceremony".into()))?;

    let (reg_state, mode) = {
        let mut m = a.reg.lock().unwrap();
        let (st, mode, exp) = m
            .remove(&rid)
            .ok_or((StatusCode::BAD_REQUEST, "ceremony expired".into()))?;
        if exp <= SystemTime::now() {
            return Err((StatusCode::BAD_REQUEST, "ceremony expired".into()));
        }
        (st, mode)
    };

    let passkey = a
        .webauthn
        .finish_passkey_registration(&cred, &reg_state)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    {
        let mut s = a.store.lock().unwrap();

        // Re-check authorization *now*, under the same lock as the mutation. A
        // ceremony started before any admin existed must not be redeemable once
        // one does — otherwise it silently enrols a second admin.
        let bootstrapping = s.passkeys.is_empty();
        let allowed = match mode {
            RegMode::Bootstrap => bootstrapping,
            RegMode::AddDevice => a.session_valid(&jar),
        };
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                "an admin already exists — sign in".into(),
            ));
        }

        // webauthn-rs requires the caller to assert the credential is new.
        if s.passkeys.iter().any(|p| p.cred_id() == passkey.cred_id()) {
            return Err((StatusCode::BAD_REQUEST, "credential already enrolled".into()));
        }

        s.passkeys.push(passkey);
    }

    // Only report success if the credential is durably on disk. Handing back a
    // session for a passkey that was never written means the next restart
    // re-opens the unauthenticated bootstrap path.
    if let Err(e) = a.persist() {
        a.store.lock().unwrap().passkeys.pop();
        tracing::error!("persisting credential failed: {e:#}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not save credential — check the data directory is writable".into(),
        ));
    }

    // A bootstrap just completed: drop every other pending registration so a
    // ceremony parked during the open window can't be redeemed afterwards.
    if mode == RegMode::Bootstrap {
        a.reg.lock().unwrap().clear();
    }

    let session = a.new_session();
    let jar = jar.remove(clear_cookie(REG_COOKIE)).add(session);
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
    insert_capped(
        &a.auth,
        aid.clone(),
        (auth_state, SystemTime::now() + CEREMONY_TTL),
        |(_, e)| *e,
    )?;
    Ok((jar.add(build_cookie(AUTH_COOKIE, aid)), Json(rcr)))
}

pub async fn login_finish(
    state: State<crate::web::AppState>,
    jar: CookieJar,
    Json(cred): Json<PublicKeyCredential>,
) -> Result<(CookieJar, StatusCode), (StatusCode, String)> {
    let a = state.auth.as_ref().ok_or((StatusCode::NOT_FOUND, "auth off".into()))?;
    let aid = jar
        .get(AUTH_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or((StatusCode::BAD_REQUEST, "no ceremony".into()))?;

    let auth_state = {
        let mut m = a.auth.lock().unwrap();
        let (st, exp) = m
            .remove(&aid)
            .ok_or((StatusCode::BAD_REQUEST, "ceremony expired".into()))?;
        if exp <= SystemTime::now() {
            return Err((StatusCode::BAD_REQUEST, "ceremony expired".into()));
        }
        st
    };

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
    // The signature counter advanced; losing that write weakens cloned-token
    // detection but must not block a legitimate sign-in.
    if let Err(e) = a.persist() {
        tracing::error!("persisting counter update failed: {e:#}");
    }

    let session = a.new_session();
    let jar = jar.remove(clear_cookie(AUTH_COOKIE)).add(session);
    Ok((jar, StatusCode::OK))
}

/// POST, not GET: a state-changing endpoint reachable by navigation is
/// CSRF-able (an `<img>` tag is enough to sign someone out).
pub async fn logout(state: State<crate::web::AppState>, jar: CookieJar) -> impl IntoResponse {
    if let (Some(a), Some(tok)) = (
        &state.auth,
        jar.get(SESSION_COOKIE).map(|c| c.value().to_string()),
    ) {
        a.sessions.lock().unwrap().remove(&tok);
    }
    (jar.remove(clear_cookie(SESSION_COOKIE)), Redirect::to("/"))
}

// ------------------------------------------------------------------ pages --

const DASHBOARD_HTML: &str = include_str!("web/dashboard.html");
const LOGIN_HTML: &str = include_str!("web/login.html");
