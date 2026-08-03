//! Config loading. M0 needs the tick interval + web settings. Passkey auth for
//! the dashboard needs the relying-party identity (rp_id/rp_origin) and a data
//! dir to persist enrolled credentials. Extra sections in the file are ignored.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Raw {
    #[serde(default = "default_interval", with = "humantime_serde")]
    interval: Duration,
    #[serde(default)]
    web: WebRaw,
}

#[derive(Debug, Deserialize)]
struct WebRaw {
    #[serde(default = "default_bind")]
    bind: String,
    /// Bearer token required on /api/* (or $VITALS_TOKEN). None = open (loopback).
    #[serde(default)]
    token: Option<String>,
    /// WebAuthn relying-party id — the dashboard's hostname, e.g.
    /// "status.mich312.com". Passkeys are bound to it. None = dashboard auth off.
    #[serde(default)]
    rp_id: Option<String>,
    /// The dashboard's HTTPS origin, e.g. "https://status.mich312.com".
    #[serde(default)]
    rp_origin: Option<String>,
    /// Where enrolled passkeys + sessions persist.
    #[serde(default = "default_data_dir")]
    data_dir: String,
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

fn default_interval() -> Duration {
    Duration::from_secs(15)
}
fn default_bind() -> String {
    "127.0.0.1:9110".to_string()
}
fn default_data_dir() -> String {
    "/var/lib/vitals".to_string()
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interval: Duration,
    pub web_bind: SocketAddr,
    pub web_token: Option<String>,
    pub rp_id: Option<String>,
    pub rp_origin: Option<String>,
    pub data_dir: String,
}

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
        toml::from_str(&std::fs::read_to_string(&path)?)?
    } else {
        tracing::warn!("config {path} not found — using defaults");
        toml::from_str("")?
    };

    let web_token = std::env::var("VITALS_TOKEN").ok().filter(|s| !s.is_empty()).or(raw.web.token);

    Ok(Config {
        interval: raw.interval,
        web_bind: raw.web.bind.parse()?,
        web_token,
        rp_id: raw.web.rp_id,
        rp_origin: raw.web.rp_origin,
        data_dir: raw.web.data_dir,
    })
}
