#!/usr/bin/env bash
# Build + install vitals on the server from origin/main, restart the systemd
# service, and health-check it. Rolls back both the binary and the checkout on
# failure. Streamed in over SSH by .github/workflows/deploy.yml — idempotent, so
# it's also safe to run by hand. Requires the repo already cloned at ~/vitals
# and the Rust toolchain in ~/.cargo.
set -euo pipefail

REPO_DIR="$HOME/vitals"
BIN=/usr/local/bin/vitals
HEALTH=http://127.0.0.1:9110/healthz

cd "$REPO_DIR"
# shellcheck disable=SC1090
source "$HOME/.cargo/env"

PREV_COMMIT=$(git rev-parse HEAD)
BACKUP=$(mktemp /tmp/vitals.bak.XXXXXX)
cp "$BIN" "$BACKUP"

echo "fetching origin/main…"
git fetch --quiet origin main
TARGET=$(git rev-parse origin/main)
echo "deploying ${PREV_COMMIT:0:8} -> ${TARGET:0:8}"
git reset --hard --quiet origin/main

echo "building (release)…"
if ! cargo build --release; then
  echo "❌ build failed — restoring ${PREV_COMMIT:0:8}"
  git reset --hard --quiet "$PREV_COMMIT"
  rm -f "$BACKUP"
  exit 1
fi

restart_and_check() {
  install -m755 "$REPO_DIR/target/release/vitals" "$BIN"
  systemctl restart vitals
  for _ in $(seq 1 15); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$HEALTH" || echo 000)
    echo "  health $HEALTH -> $code"
    [ "$code" = "200" ] && return 0
    sleep 2
  done
  return 1
}

if restart_and_check; then
  echo "✅ deploy OK: ${TARGET:0:8}"
  rm -f "$BACKUP"
else
  echo "❌ unhealthy — rolling back to ${PREV_COMMIT:0:8}"
  git reset --hard --quiet "$PREV_COMMIT"
  install -m755 "$BACKUP" "$BIN"
  systemctl restart vitals
  rm -f "$BACKUP"
  exit 1
fi
