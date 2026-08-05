//! Config loading. M0 needs the tick interval + web settings. Passkey auth for
//! the dashboard needs the relying-party identity (rp_id/rp_origin) and a data
//! dir to persist enrolled credentials.
//!
//! Unknown keys *inside* an implemented section are a hard error: a silently
//! ignored `trust_proxy_auth` or `socket` reads to the operator as a security
//! control that took effect. Unknown top-level sections are still ignored —
//! `[alert]`, `[thresholds]`, `[retention]` and `[[endpoint]]` are documented
//! for later milestones and must not break a config written ahead of them.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Raw {
    #[serde(default = "default_interval", with = "humantime_serde")]
    interval: Duration,
    #[serde(default)]
    web: WebRaw,
    #[serde(default)]
    docker: DockerRaw,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebRaw {
    #[serde(default = "default_bind")]
    bind: String,
    /// Bearer token required on /api/* (or $VITALS_TOKEN). None = no token gate.
    #[serde(default)]
    token: Option<String>,
    /// WebAuthn relying-party id — the dashboard's hostname, e.g.
    /// "status.example.com". Passkeys are bound to it. None = dashboard auth off.
    #[serde(default)]
    rp_id: Option<String>,
    /// The dashboard's HTTPS origin, e.g. "https://status.example.com".
    #[serde(default)]
    rp_origin: Option<String>,
    /// Where enrolled passkeys + the history DB live.
    #[serde(default = "default_data_dir")]
    data_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DockerRaw {
    /// Path to the Docker API socket, or a `tcp://`/`http://` endpoint. Point
    /// this at a read-only socket proxy to avoid granting root-equivalent
    /// access — see docs/security.md.
    #[serde(default = "default_docker_socket")]
    socket: String,
}

impl Default for WebRaw {
    fn default() -> Self {
        WebRaw {
            bind: default_bind(),
            token: None,
            rp_id: None,
            rp_origin: None,
            data_dir: default_data_dir(),
        }
    }
}

impl Default for DockerRaw {
    fn default() -> Self {
        DockerRaw {
            socket: default_docker_socket(),
        }
    }
}

fn default_interval() -> Duration {
    Duration::from_secs(15)
}
fn default_bind() -> String {
    "127.0.0.1:9110".to_string()
}
fn default_data_dir() -> String {
    "/var/lib/vitals".to_string()
}
fn default_docker_socket() -> String {
    "/var/run/docker.sock".to_string()
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interval: Duration,
    pub web_bind: SocketAddr,
    pub web_token: Option<Secret>,
    pub rp_id: Option<String>,
    pub rp_origin: Option<String>,
    pub data_dir: String,
    pub docker_socket: String,
}

/// A secret that never renders its value through `Debug`, so a stray
/// `tracing::debug!("{cfg:?}")` can't put the API token in the journal.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Shortest token we'll accept. Anything less is a typo or a placeholder, and
/// silently honouring it would leave `/api/*` effectively open.
const MIN_TOKEN_LEN: usize = 16;

/// Load config from `--config <path>` (or `-c`), falling back to
/// `/etc/vitals/config.toml`, and to built-in defaults if the file is absent.
pub fn load() -> anyhow::Result<Config> {
    let mut path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" || a == "-c" {
            path = args.next();
        }
    }
    let path = path.unwrap_or_else(|| "/etc/vitals/config.toml".to_string());

    let raw: Raw = if std::path::Path::new(&path).exists() {
        toml::from_str(&std::fs::read_to_string(&path)?)
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?
    } else {
        tracing::warn!("config {path} not found — using defaults");
        toml::from_str("")?
    };

    // An empty token is not "no token": it would make `Bearer ` (empty value)
    // a valid credential. Treat empty/blank as unset on both paths.
    let from_env = std::env::var("VITALS_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let from_file = raw.web.token.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let web_token = from_env.or(from_file);

    if let Some(t) = &web_token {
        anyhow::ensure!(
            t.len() >= MIN_TOKEN_LEN,
            "web token is {} chars; need at least {MIN_TOKEN_LEN} \
             (generate one with `openssl rand -hex 32`)",
            t.len()
        );
    }

    Ok(Config {
        interval: raw.interval,
        web_bind: raw.web.bind.parse()?,
        web_token: web_token.map(Secret),
        rp_id: raw.web.rp_id,
        rp_origin: raw.web.rp_origin,
        data_dir: raw.web.data_dir,
        docker_socket: raw.docker.socket,
    })
}
