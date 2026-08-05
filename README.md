<div align="center">

<img src="assets/logo.svg" alt="vitals" width="88" height="88">

# vitals

**Know how your servers are doing.**

A single small binary that watches one host and its Docker containers — resource
usage, container health, your public endpoints and their TLS certs — keeps a
little history for graphs, streams logs, and *tells you* the moment something's
off. Calm, lightweight, self-hosted. Not enterprise observability.

<!-- badges (add on first release): build · release · license · docker -->

</div>

---

## Why

You don't want a Prometheus + Grafana + Loki stack to babysit one VM. You want
one thing that:

- **tells you when something breaks** — disk filling, memory pressure, a
  container down or crash-looping, a site not returning its expected status, a
  cert about to expire — pushed to your phone, *only* on real problems.
- **shows the essentials at a glance** — CPU, memory, disk, load, and every
  container, on one page.
- **keeps enough history** to see a trend, with simple graphs.
- **streams container logs** in the browser, so you're not SSH-ing to `docker logs`.
- **stays out of the way** — one static binary, tens of MB of RAM, and a
  history DB sized to your container count (see Footprint).

It runs as a **host service, not a container** — so if the Docker daemon itself
wedges, vitals is still up and can tell you.

## Features

- 📊 Host metrics — CPU, memory, swap, disk, load, uptime
- 📦 Per-container — state, health, CPU, memory, restarts (catches crash loops)
- 🌐 Endpoint checks — asserts each URL returns the status *you* expect (so a
  green deploy that actually serves a 502 still pages you)
- 🔒 TLS cert expiry warnings
- 📈 Small built-in time-series store + graphs (no external database)
- 📜 Live container logs over SSE, in the browser
- 🔔 Alerting that only fires on real problems — debounced, transition-only,
  with recovery notices and flap-dampening; pluggable channels (Telegram, ntfy)
- 💓 Heartbeat to a dead-man's-switch, so a dead monitor doesn't fail silently
- 🔑 Passkey (WebAuthn) sign-in for the dashboard — no password to leak
- 🪶 One static binary · runs as a host `systemd` service · see Footprint

## Quickstart

> **Status: early — building in the open.** The spec is in [`SPEC.md`](SPEC.md);
> the milestones below track what's live.

**Binary (recommended — host-native, survives Docker outages):**

```sh
# Pin a version and verify the checksum — `| sh` on an unpinned `latest`
# executes whatever that URL serves, and a truncated download runs a partial
# script.
VER=v0.1.0
base=https://github.com/mich312/vm-vitals/releases/download/$VER
curl -fsSLO $base/install.sh && curl -fsSLO $base/install.sh.sha256
sha256sum -c install.sh.sha256 && sh ./install.sh

sudo install -D -o root -g vitals -m 0640 config.example.toml /etc/vitals/config.toml
sudo editor /etc/vitals/config.toml     # set rp_id/rp_origin or a token
sudo systemctl enable --now vitals
```

**Docker (if you'd rather):**

```sh
docker run -d --name vitals \
  --user 65532:$(getent group docker | cut -d: -f3) \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=8m \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --pids-limit 64 --memory 128m \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ./config.toml:/etc/vitals/config.toml:ro \
  -v vitals-data:/var/lib/vitals \
  -p 127.0.0.1:9110:9110 ghcr.io/mich312/vitals:latest
```

Configure authentication before exposing it: set `web.rp_id` + `web.rp_origin`
for passkey sign-in, or `web.token` for the API. vitals refuses to start if it
would serve a non-loopback address with neither. Then open the dashboard and
enroll a passkey — do that immediately, because until the first credential
exists the sign-in page enrolls whoever reaches it.

Host disk metrics are only meaningful in the host-binary deployment; in a
container `sysinfo` measures the container's own filesystem.

## Configuration

Everything lives in one `config.toml` — thresholds, the endpoints to check, the
alert channel, retention. See [`config.example.toml`](config.example.toml) and
[docs/configuration.md](docs/configuration.md).

```toml
interval = "15s"

[alert]
channel = "ntfy"                       # or "telegram"
ntfy = { url = "https://ntfy.sh/your-topic", priority = "high" }
heartbeat_url = "https://hc-ping.com/…" # dead-man's-switch

[[endpoint]]
name = "my-app"; url = "https://app.example.com/"; expect = 200
```

## Footprint

Measured, not aspirational:

| | RSS | history DB @ 180d |
| --- | --- | --- |
| idle, no containers | ~10 MB | ~1 MB |
| ~5 containers | ~16 MB | ~17 MB |
| ~50 containers | ~24 MB | ~120 MB |

Retention (48h raw · 30d 5-min · 180d hourly) is what drives the DB size; shorten
it in `[retention]` if you'd rather trade history for disk.

## How it compares

| | vitals | Netdata | Beszel | Prometheus + Grafana |
| --- | --- | --- | --- |
| Footprint | one ~15 MB binary | agent (heavier) | small (hub + agent) | ~1 GB stack |
| Runs as | host service | agent | 2 containers | several services |
| Survives Docker down | ✅ (host binary) | ✅ | ✗ (containers) | ✗ |
| Alert-first | ✅ | add-on | ✅ | via Alertmanager |
| History | some (built-in) | lots | some | lots |
| Setup | one binary + one file | package | compose | a project |

vitals is deliberately the *small* one: a single host, alert-first, no stack to
run. If you need long-term metrics, dashboards for a fleet, or full APM, reach
for the bigger tools — vitals won't try to be them.

## Security

- **Docker socket access is equivalent to root on the host.** Mounting it `:ro`
  does not change that — `:ro` gates filesystem writes, not socket traffic, and
  the Engine API behind it stays read-write. vitals only ever issues read calls,
  but that is its own restraint, not an enforced boundary. Point `[docker]
  socket` at a read-only proxy to make it one.
- **vitals fails closed**: it will not start unauthenticated on a non-loopback
  bind, and aborts rather than degrading to "open" if passkey init fails.
- The dashboard binds to loopback; front it with TLS (passkeys require HTTPS).
- The history DB holds no credentials, but metric names include your **container
  names**, kept for 180 days — treat the file as sensitive.

See [docs/security.md](docs/security.md).

## Roadmap

- [ ] **M0** — host + container metrics, JSON status
- [ ] **M1** — alerting engine + notifiers + heartbeat
- [ ] **M2** — history + graphs + live logs
- [ ] **M3** — passkey auth + production deploy
- [ ] **M4** — release: docs, container image, installer

## License

MIT © mich312. (Happy to dual-license MIT/Apache-2.0 if that helps adoption.)
