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

// ------------------------------------------------------------------ tests --

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header::COOKIE, HeaderMap};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;

    const RP_ID: &str = "localhost";
    const ORIGIN: &str = "https://localhost";

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    type Soft = WebauthnAuthenticator<SoftPasskey>;
    type Err = (StatusCode, String);

    fn soft() -> Soft {
        WebauthnAuthenticator::new(SoftPasskey::new(true))
    }

    /// A fresh AppState with passkey auth on and a scratch data dir.
    fn ctx() -> (crate::web::AppState, PathBuf) {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("vitals-auth-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let auth = AuthState::new(RP_ID, ORIGIN, dir.to_str().unwrap()).unwrap();
        let store =
            Arc::new(crate::store::Store::open(dir.join("t.db").to_str().unwrap()).unwrap());
        let state = crate::web::AppState {
            snapshot: Arc::new(tokio::sync::RwLock::new(None)),
            token: None,
            auth: Some(auth),
            store,
        };
        (state, dir)
    }

    fn a_of(s: &crate::web::AppState) -> &AuthState {
        s.auth.as_ref().unwrap()
    }

    fn jar(pairs: &[(&str, &str)]) -> CookieJar {
        let mut h = HeaderMap::new();
        if !pairs.is_empty() {
            let v = pairs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            h.insert(COOKIE, v.parse().unwrap());
        }
        CookieJar::from_headers(&h)
    }

    fn cookie_of(j: &CookieJar, name: &str) -> String {
        j.get(name).expect("cookie should be set").value().to_string()
    }

    fn passkey_count(s: &crate::web::AppState) -> usize {
        a_of(s).store.lock().unwrap().passkeys.len()
    }

    /// Begin a registration; returns the ceremony cookie and the signed credential.
    async fn reg_start(
        s: &crate::web::AppState,
        k: &mut Soft,
        session: Option<&str>,
    ) -> Result<(String, RegisterPublicKeyCredential), Err> {
        let in_jar = match session {
            Some(t) => jar(&[(SESSION_COOKIE, t)]),
            None => jar(&[]),
        };
        let (out, Json(ccr)) = register_start(State(s.clone()), in_jar).await?;
        let rid = cookie_of(&out, REG_COOKIE);
        let cred = k.do_registration(Url::parse(ORIGIN).unwrap(), ccr).unwrap();
        Ok((rid, cred))
    }

    async fn reg_finish(
        s: &crate::web::AppState,
        rid: &str,
        cred: RegisterPublicKeyCredential,
        session: Option<&str>,
    ) -> Result<String, Err> {
        let mut pairs = vec![(REG_COOKIE, rid)];
        if let Some(t) = session {
            pairs.push((SESSION_COOKIE, t));
        }
        let (out, _) = register_finish(State(s.clone()), jar(&pairs), Json(cred)).await?;
        Ok(cookie_of(&out, SESSION_COOKIE))
    }

    /// Full enrolment; returns the session token.
    async fn enroll(
        s: &crate::web::AppState,
        k: &mut Soft,
        session: Option<&str>,
    ) -> Result<String, Err> {
        let (rid, cred) = reg_start(s, k, session).await?;
        reg_finish(s, &rid, cred, session).await
    }

    async fn login(s: &crate::web::AppState, k: &mut Soft) -> Result<String, Err> {
        let (out, Json(rcr)) = login_start(State(s.clone()), jar(&[])).await?;
        let aid = cookie_of(&out, AUTH_COOKIE);
        let cred = k.do_authentication(Url::parse(ORIGIN).unwrap(), rcr).unwrap();
        let (out2, _) =
            login_finish(State(s.clone()), jar(&[(AUTH_COOKIE, &aid)]), Json(cred)).await?;
        Ok(cookie_of(&out2, SESSION_COOKIE))
    }

    fn expire_all_ceremonies(a: &AuthState) {
        let past = SystemTime::now() - Duration::from_secs(1);
        for v in a.reg.lock().unwrap().values_mut() {
            v.2 = past;
        }
        for v in a.auth.lock().unwrap().values_mut() {
            v.1 = past;
        }
    }

    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn bootstrap_enrols_and_issues_a_working_session() {
        let (s, _d) = ctx();
        let token = enroll(&s, &mut soft(), None).await.expect("bootstrap");
        assert_eq!(passkey_count(&s), 1);
        assert!(a_of(&s).session_valid(&jar(&[(SESSION_COOKIE, &token)])));
        // and it really landed on disk
        let raw = std::fs::read_to_string(&a_of(&s).path).unwrap();
        assert!(raw.contains("passkeys"));
    }

    #[tokio::test]
    async fn second_bootstrap_is_refused_once_an_admin_exists() {
        let (s, _d) = ctx();
        enroll(&s, &mut soft(), None).await.unwrap();
        let err = reg_start(&s, &mut soft(), None).await.unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(passkey_count(&s), 1);
    }

    /// The regression this whole change set exists for: a ceremony *started*
    /// during the pre-bootstrap window must not be redeemable after an admin
    /// enrols. Starting early used to be enough to become a second admin.
    #[tokio::test]
    async fn banked_pre_bootstrap_ceremony_cannot_enrol_after_admin_exists() {
        let (s, _d) = ctx();

        // Attacker starts (and signs) a ceremony while nobody is enrolled.
        let mut attacker = soft();
        let (evil_rid, evil_cred) = reg_start(&s, &mut attacker, None).await.unwrap();

        // Admin bootstraps normally.
        enroll(&s, &mut soft(), None).await.unwrap();
        assert_eq!(passkey_count(&s), 1);

        // Attacker redeems the banked ceremony.
        let res = reg_finish(&s, &evil_rid, evil_cred, None).await;
        assert!(res.is_err(), "banked ceremony was redeemed: {res:?}");
        assert_eq!(passkey_count(&s), 1, "attacker enrolled a second passkey");
    }

    /// The add-device branch must re-check the session at finish, not just at
    /// start — otherwise a ceremony begun while signed in stays redeemable
    /// after sign-out.
    #[tokio::test]
    async fn add_device_ceremony_is_refused_once_the_session_is_gone() {
        let (s, _d) = ctx();
        let token = enroll(&s, &mut soft(), None).await.unwrap();

        let mut second = soft();
        let (rid, cred) = reg_start(&s, &mut second, Some(&token)).await.unwrap();

        // Sign out between start and finish.
        a_of(&s).sessions.lock().unwrap().remove(&token);

        let err = reg_finish(&s, &rid, cred, Some(&token)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(passkey_count(&s), 1);
    }

    #[tokio::test]
    async fn add_device_works_while_signed_in() {
        let (s, _d) = ctx();
        let token = enroll(&s, &mut soft(), None).await.unwrap();
        enroll(&s, &mut soft(), Some(&token)).await.expect("add device");
        assert_eq!(passkey_count(&s), 2);
    }

    #[tokio::test]
    async fn expired_registration_ceremony_is_refused() {
        let (s, _d) = ctx();
        let (rid, cred) = reg_start(&s, &mut soft(), None).await.unwrap();
        expire_all_ceremonies(a_of(&s));
        let err = reg_finish(&s, &rid, cred, None).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(passkey_count(&s), 0);
    }

    #[tokio::test]
    async fn login_round_trip_issues_a_session() {
        let (s, _d) = ctx();
        let mut key = soft();
        let first = enroll(&s, &mut key, None).await.unwrap();

        let second = login(&s, &mut key).await.expect("login");
        assert_ne!(first, second, "a fresh session token per ceremony");
        assert!(a_of(&s).session_valid(&jar(&[(SESSION_COOKIE, &second)])));
    }

    #[tokio::test]
    async fn expired_authentication_ceremony_is_refused() {
        let (s, _d) = ctx();
        let mut key = soft();
        enroll(&s, &mut key, None).await.unwrap();

        let (out, Json(rcr)) = login_start(State(s.clone()), jar(&[])).await.unwrap();
        let aid = cookie_of(&out, AUTH_COOKIE);
        let cred = key.do_authentication(Url::parse(ORIGIN).unwrap(), rcr).unwrap();
        expire_all_ceremonies(a_of(&s));

        let err = login_finish(State(s.clone()), jar(&[(AUTH_COOKIE, &aid)]), Json(cred))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    /// A ceremony is single-use: the state is removed before verification, so a
    /// captured assertion cannot be replayed.
    #[tokio::test]
    async fn authentication_ceremony_cannot_be_replayed() {
        let (s, _d) = ctx();
        let mut key = soft();
        enroll(&s, &mut key, None).await.unwrap();

        let (out, Json(rcr)) = login_start(State(s.clone()), jar(&[])).await.unwrap();
        let aid = cookie_of(&out, AUTH_COOKIE);
        let cred = key.do_authentication(Url::parse(ORIGIN).unwrap(), rcr).unwrap();

        let first =
            login_finish(State(s.clone()), jar(&[(AUTH_COOKIE, &aid)]), Json(cred.clone())).await;
        assert!(first.is_ok());

        let replay = login_finish(State(s.clone()), jar(&[(AUTH_COOKIE, &aid)]), Json(cred)).await;
        assert!(replay.is_err(), "assertion was accepted twice");
    }

    #[tokio::test]
    async fn login_is_refused_before_any_enrolment() {
        let (s, _d) = ctx();
        let err = login_start(State(s.clone()), jar(&[])).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    /// A credential that cannot be stored must not yield a session — otherwise
    /// the next restart finds an empty store and re-opens bootstrap.
    #[tokio::test]
    async fn failed_persist_rolls_back_and_refuses_the_session() {
        let (mut s, _d) = ctx();
        {
            // Point persistence somewhere unwritable. (Running as root, so a
            // read-only directory would not be enough.)
            let a = s.auth.as_mut().unwrap();
            a.path = PathBuf::from("/nonexistent-dir-for-vitals-test/auth.json");
        }
        let (rid, cred) = reg_start(&s, &mut soft(), None).await.unwrap();
        let err = reg_finish(&s, &rid, cred, None).await.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(passkey_count(&s), 0, "credential should have been rolled back");
    }

    #[tokio::test]
    async fn ceremony_map_is_capped_against_unauthenticated_growth() {
        let (s, _d) = ctx();
        enroll(&s, &mut soft(), None).await.unwrap();
        for _ in 0..MAX_CEREMONIES {
            let _ = login_start(State(s.clone()), jar(&[])).await;
        }
        let err = login_start(State(s.clone()), jar(&[])).await.unwrap_err();
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(a_of(&s).auth.lock().unwrap().len() <= MAX_CEREMONIES);
    }

    #[tokio::test]
    async fn sweep_drops_expired_state() {
        let (s, _d) = ctx();
        let token = enroll(&s, &mut soft(), None).await.unwrap();
        let _ = login_start(State(s.clone()), jar(&[])).await.unwrap();

        let a = a_of(&s);
        assert_eq!(a.auth.lock().unwrap().len(), 1);
        expire_all_ceremonies(a);
        a.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), SystemTime::now() - Duration::from_secs(1));

        a.sweep();
        assert!(a.auth.lock().unwrap().is_empty());
        assert!(!a.session_valid(&jar(&[(SESSION_COOKIE, &token)])));
    }

    #[tokio::test]
    async fn unknown_or_absent_session_cookies_are_invalid() {
        let (s, _d) = ctx();
        enroll(&s, &mut soft(), None).await.unwrap();
        let a = a_of(&s);
        assert!(!a.session_valid(&jar(&[])));
        assert!(!a.session_valid(&jar(&[(SESSION_COOKIE, "deadbeef")])));
    }

    #[tokio::test]
    async fn registered_fails_closed_and_reflects_state() {
        let (s, _d) = ctx();
        assert!(!a_of(&s).registered());
        enroll(&s, &mut soft(), None).await.unwrap();
        assert!(a_of(&s).registered());
    }

    /// Credentials must survive a restart — the path that, when broken, silently
    /// re-opens the bootstrap window.
    #[tokio::test]
    async fn enrolment_survives_a_reload_from_disk() {
        let (s, dir) = ctx();
        enroll(&s, &mut soft(), None).await.unwrap();

        let reloaded = AuthState::new(RP_ID, ORIGIN, dir.to_str().unwrap()).unwrap();
        assert!(reloaded.registered());
        assert_eq!(reloaded.store.lock().unwrap().passkeys.len(), 1);
    }

    #[tokio::test]
    async fn corrupt_credential_file_is_an_error_not_an_empty_store() {
        let (s, dir) = ctx();
        enroll(&s, &mut soft(), None).await.unwrap();
        std::fs::write(dir.join("auth.json"), "{\"user_id\":").unwrap();

        // Must fail loudly: silently returning an empty store would drop the
        // dashboard to unauthenticated on the next start.
        assert!(AuthState::new(RP_ID, ORIGIN, dir.to_str().unwrap()).is_err());
    }
}
