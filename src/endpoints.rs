//! Endpoint monitor: periodically GET each configured URL and record
//! reachability, HTTP status, latency, and — for HTTPS — the days remaining on
//! the presented TLS certificate.
//!
//! Cert expiry without a second handshake: the client accepts *any* certificate
//! (`danger_accept_invalid_certs`) — we're inspecting, not trusting — and reads
//! the leaf cert off the response via `tls_info`, so an already-expired cert is
//! reported as expired rather than failing the check outright.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::config::Endpoint;

/// Latest per-endpoint results, shared with the web layer.
pub type Shared = Arc<RwLock<Vec<Status>>>;

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub name: String,
    pub url: String,
    /// Reachable and returned a non-error status (2xx/3xx).
    pub up: bool,
    /// HTTP status code, or 0 if unreachable.
    pub status: u16,
    pub latency_ms: u64,
    /// Days until the TLS certificate expires (negative = already expired).
    pub cert_days: Option<i64>,
    pub error: Option<String>,
    pub checked: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Days until the DER-encoded cert's notAfter (negative if expired).
fn cert_days(der: &[u8]) -> Option<i64> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let not_after = cert.validity().not_after.timestamp();
    Some((not_after - now() as i64) / 86_400)
}

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // we read expiry ourselves; don't fail on it
        .tls_info(true)
        .redirect(reqwest::redirect::Policy::none()) // report the endpoint's own status
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("vitals/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn check(client: &reqwest::Client, ep: &Endpoint) -> Status {
    let start = Instant::now();
    let res = client.get(&ep.url).send().await;
    let latency_ms = start.elapsed().as_millis() as u64;
    match res {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let cert_days = resp
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|t| t.peer_certificate())
                .and_then(cert_days);
            Status {
                name: ep.name.clone(),
                url: ep.url.clone(),
                // Responding at all (incl. 4xx auth walls) counts as reachable;
                // 5xx and connection failures are down. The UI shades by band.
                up: status < 500,
                status,
                latency_ms,
                cert_days,
                error: None,
                checked: now(),
            }
        }
        Err(e) => {
            let error = if e.is_timeout() {
                "timeout".to_string()
            } else if e.is_connect() {
                "connection failed".to_string()
            } else {
                e.to_string()
            };
            Status {
                name: ep.name.clone(),
                url: ep.url.clone(),
                up: false,
                status: 0,
                latency_ms,
                cert_days: None,
                error: Some(error),
                checked: now(),
            }
        }
    }
}

/// Check-all loop: every `interval`, probe all endpoints concurrently and
/// publish the results.
pub async fn run(endpoints: Vec<Endpoint>, out: Shared, interval: Duration) {
    let client = build_client();
    let mut iv = tokio::time::interval(interval);
    loop {
        iv.tick().await;
        let results = join_all(endpoints.iter().map(|ep| check(&client, ep))).await;
        *out.write().await = results;
    }
}
