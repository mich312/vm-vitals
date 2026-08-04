//! A small OAuth 2.1 authorization server so MCP clients (e.g. a claude.ai
//! custom connector) can connect with OAuth instead of a pasted token. vitals
//! is both the Authorization Server and the Resource Server; the login/consent
//! step reuses the existing passkey session — no third party.
//!
//! Flow: client discovers us (protected-resource + AS metadata), registers
//! dynamically (RFC 7591), sends the user to `/oauth/authorize` where they
//! approve with their passkey, gets a code, and exchanges it (PKCE S256) at
//! `/oauth/token` for an opaque bearer token that `/mcp` accepts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::web::AppState;

const CODE_TTL: u64 = 300; // authorization codes: 5 minutes
const TOKEN_TTL: u64 = 3600; // access tokens: 1 hour

const CONSENT_HTML: &str = include_str!("web/oauth.html");

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Clone, Serialize, Deserialize)]
struct Client {
    redirect_uris: Vec<String>,
    name: String,
    created: u64,
}
#[derive(Clone)]
struct Code {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    scope: String,
    expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Token {
    client_id: String,
    scope: String,
    expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct RefreshTok {
    client_id: String,
    scope: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Persist {
    clients: HashMap<String, Client>,
    tokens: HashMap<String, Token>,
    refresh: HashMap<String, RefreshTok>,
}

pub struct OAuthState {
    /// Public issuer/resource, e.g. https://status.mich312.com
    pub issuer: String,
    path: String,
    clients: Mutex<HashMap<String, Client>>,
    codes: Mutex<HashMap<String, Code>>,
    tokens: Mutex<HashMap<String, Token>>,
    refresh: Mutex<HashMap<String, RefreshTok>>,
}

impl OAuthState {
    pub fn new(issuer: &str, data_dir: &str) -> Self {
        let path = format!("{data_dir}/oauth.json");
        let p: Persist = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            path,
            clients: Mutex::new(p.clients),
            codes: Mutex::new(HashMap::new()),
            tokens: Mutex::new(p.tokens),
            refresh: Mutex::new(p.refresh),
        }
    }
    fn save(&self) {
        let p = Persist {
            clients: self.clients.lock().unwrap().clone(),
            tokens: self.tokens.lock().unwrap().clone(),
            refresh: self.refresh.lock().unwrap().clone(),
        };
        if let Ok(s) = serde_json::to_string(&p) {
            let _ = std::fs::write(&self.path, s);
        }
    }
    /// Is this an unexpired access token?
    pub fn validate(&self, token: &str) -> bool {
        self.tokens
            .lock()
            .unwrap()
            .get(token)
            .map(|t| t.expires > now())
            .unwrap_or(false)
    }
}

fn authed(state: &AppState, headers: &HeaderMap) -> bool {
    state
        .auth
        .as_ref()
        .map(|a| a.session_valid_in(headers.get(header::COOKIE).and_then(|h| h.to_str().ok())))
        .unwrap_or(false)
}

fn oauth_err(code: StatusCode, err: &str, desc: &str) -> Response {
    (code, Json(json!({ "error": err, "error_description": desc }))).into_response()
}
fn redirect_err(uri: &str, state: Option<&String>, err: &str) -> Response {
    let sep = if uri.contains('?') { '&' } else { '?' };
    let st = state.map(|s| format!("&state={}", urlenc(s))).unwrap_or_default();
    Redirect::to(&format!("{uri}{sep}error={err}{st}")).into_response()
}

// --- discovery ---------------------------------------------------------------

pub async fn protected_resource(State(s): State<AppState>) -> Response {
    match &s.oauth {
        Some(o) => Json(json!({
            "resource": o.issuer,
            "authorization_servers": [o.issuer],
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn authorization_server(State(s): State<AppState>) -> Response {
    match &s.oauth {
        Some(o) => Json(json!({
            "issuer": o.issuer,
            "authorization_endpoint": format!("{}/oauth/authorize", o.issuer),
            "token_endpoint": format!("{}/oauth/token", o.issuer),
            "registration_endpoint": format!("{}/oauth/register", o.issuer),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// --- dynamic client registration (RFC 7591) ----------------------------------

pub async fn register(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Response {
    let Some(o) = &s.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if redirect_uris.is_empty() {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_redirect_uri", "redirect_uris required");
    }
    let name = body
        .get("client_name")
        .and_then(|v| v.as_str())
        .unwrap_or("MCP client")
        .to_string();
    let client_id = format!("vitals-{}", rand_hex(12));
    o.clients.lock().unwrap().insert(
        client_id.clone(),
        Client { redirect_uris: redirect_uris.clone(), name: name.clone(), created: now() },
    );
    o.save();
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": now(),
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": name,
        })),
    )
        .into_response()
}

// --- authorize + consent -----------------------------------------------------

pub async fn authorize(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(o) = &s.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let client_id = q.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
    let Some(client) = o.clients.lock().unwrap().get(&client_id).cloned() else {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "unknown client_id");
    };
    // redirect_uri must be pre-registered — never redirect to an unvetted URI.
    if !client.redirect_uris.contains(&redirect_uri) {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uri not registered");
    }
    if q.get("response_type").map(|x| x.as_str()) != Some("code") {
        return redirect_err(&redirect_uri, q.get("state"), "unsupported_response_type");
    }
    let challenge = q.get("code_challenge").cloned().unwrap_or_default();
    if challenge.is_empty() || q.get("code_challenge_method").map(|x| x.as_str()) != Some("S256") {
        return redirect_err(&redirect_uri, q.get("state"), "invalid_request");
    }
    let data = json!({
        "authed": authed(&s, &headers),
        "client": client.name,
        "params": {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": q.get("scope").cloned().unwrap_or_default(),
            "state": q.get("state").cloned().unwrap_or_default(),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    });
    Html(CONSENT_HTML.replace("__OAUTH_DATA__", &data.to_string())).into_response()
}

pub async fn decision(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let Some(o) = &s.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !authed(&s, &headers) {
        return oauth_err(StatusCode::UNAUTHORIZED, "access_denied", "not signed in");
    }
    let client_id = f.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = f.get("redirect_uri").cloned().unwrap_or_default();
    let Some(client) = o.clients.lock().unwrap().get(&client_id).cloned() else {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "unknown client_id");
    };
    if !client.redirect_uris.contains(&redirect_uri) {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uri not registered");
    }
    let state = f.get("state").cloned().unwrap_or_default();
    if f.get("decision").map(|x| x.as_str()) != Some("allow") {
        return redirect_err(&redirect_uri, Some(&state), "access_denied");
    }
    let code = rand_hex(24);
    o.codes.lock().unwrap().insert(
        code.clone(),
        Code {
            client_id,
            redirect_uri: redirect_uri.clone(),
            challenge: f.get("code_challenge").cloned().unwrap_or_default(),
            scope: f.get("scope").cloned().unwrap_or_default(),
            expires: now() + CODE_TTL,
        },
    );
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{redirect_uri}{sep}code={}&state={}", urlenc(&code), urlenc(&state)))
        .into_response()
}

// --- token -------------------------------------------------------------------

pub async fn token(State(s): State<AppState>, Form(f): Form<HashMap<String, String>>) -> Response {
    let Some(o) = &s.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match f.get("grant_type").map(|x| x.as_str()).unwrap_or("") {
        "authorization_code" => {
            let code = f.get("code").cloned().unwrap_or_default();
            let Some(c) = o.codes.lock().unwrap().remove(&code) else {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown code");
            };
            if c.expires < now() {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code expired");
            }
            if f.get("redirect_uri").map(|x| x.as_str()) != Some(c.redirect_uri.as_str()) {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
            }
            if f.get("client_id").map(|x| x.as_str()) != Some(c.client_id.as_str()) {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "client mismatch");
            }
            let verifier = f.get("code_verifier").cloned().unwrap_or_default();
            if b64url(&Sha256::digest(verifier.as_bytes())) != c.challenge {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
            }
            issue(o, &c.client_id, &c.scope)
        }
        "refresh_token" => {
            let rt = f.get("refresh_token").cloned().unwrap_or_default();
            let Some(r) = o.refresh.lock().unwrap().get(&rt).cloned() else {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown refresh_token");
            };
            issue(o, &r.client_id, &r.scope)
        }
        _ => oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type", "grant not supported"),
    }
}

fn issue(o: &OAuthState, client_id: &str, scope: &str) -> Response {
    let at = rand_hex(32);
    let rt = rand_hex(32);
    {
        let mut toks = o.tokens.lock().unwrap();
        toks.retain(|_, t| t.expires > now()); // prune expired
        toks.insert(
            at.clone(),
            Token { client_id: client_id.into(), scope: scope.into(), expires: now() + TOKEN_TTL },
        );
    }
    o.refresh
        .lock()
        .unwrap()
        .insert(rt.clone(), RefreshTok { client_id: client_id.into(), scope: scope.into() });
    o.save();
    Json(json!({
        "access_token": at,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "refresh_token": rt,
        "scope": scope,
    }))
    .into_response()
}
