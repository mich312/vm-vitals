//! Config loading. M0 only needs the tick interval and the web bind address;
//! extra sections in the file (alerts, thresholds, endpoints…) are ignored for
//! now — serde skips unknown fields, so the full config.example.toml parses.

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
    /// Bearer token required on /api/*. Also read from $VITALS_TOKEN (env wins).
    /// If neither is set, the API is unauthenticated (fine on loopback only).
    #[serde(default)]
    token: Option<String>,
}

impl Default for WebRaw {
    fn default() -> Self {
        WebRaw {
            bind: default_bind(),
            token: None,
        }
    }
}

fn default_interval() -> Duration {
    Duration::from_secs(15)
}
fn default_bind() -> String {
    "127.0.0.1:9110".to_string()
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interval: Duration,
    pub web_bind: SocketAddr,
    /// Bearer token for the API; None = unauthenticated (loopback dev).
    pub web_token: Option<String>,
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

    // $VITALS_TOKEN overrides the config file (keeps the token out of the TOML).
    let web_token = std::env::var("VITALS_TOKEN").ok().filter(|s| !s.is_empty()).or(raw.web.token);

    Ok(Config {
        interval: raw.interval,
        web_bind: raw.web.bind.parse()?,
        web_token,
    })
}
