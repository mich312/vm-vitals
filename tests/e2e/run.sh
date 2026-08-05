#!/usr/bin/env bash
# End-to-end passkey test against a real browser.
#
# The Rust tests drive the ceremonies with a software authenticator, which
# proves the protocol logic but not the browser contract: __Host- cookie
# acceptance, whether the CSP blocks our own inline scripts, POST logout, and
# the dashboard's poll loop. This runs the real thing — Chromium with a CDP
# virtual authenticator — against the real deployment shape (TLS in front,
# vitals on loopback).
set -euo pipefail
cd "$(dirname "$0")"
BIN=${VITALS_BIN:-../../target/release/vitals}
DIR=$(mktemp -d)
trap 'kill ${VP:-} ${PP:-} 2>/dev/null || true; rm -rf "$DIR"' EXIT

[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 2; }

openssl req -x509 -newkey rsa:2048 -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
  -days 1 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

cat > "$DIR/c.toml" <<EOF
interval = "5s"
[web]
bind = "127.0.0.1:9110"
rp_id = "localhost"
rp_origin = "https://localhost:8443"
data_dir = "$DIR/data"
EOF

"$BIN" --config "$DIR/c.toml" > "$DIR/vitals.log" 2>&1 & VP=$!
CERT_DIR="$DIR" node proxy.js > "$DIR/proxy.log" 2>&1 & PP=$!

for _ in $(seq 1 20); do
  curl -sk -o /dev/null https://localhost:8443/healthz && break || sleep 1
done

NODE_PATH=${NODE_PATH:-/opt/node22/lib/node_modules} node e2e.js
