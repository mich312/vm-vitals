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
- **stays out of the way** — one static binary, a few MB of RAM, a few MB of DB.

It runs as a **host service, not a container** — so if the Docker daemon itself
wedges, vitals is still up and can tell you.

## Features

- 📊 Host metrics — CPU, memory, swap, disk, load, uptime
- 📦 Per-container — state, health, CPU, memory, restarts (catches crash loops)
- 🌐 Endpoint checks — reachability, HTTP status + response time for each public
  URL (a 5xx or a dead host shows down; a 401 auth wall still counts as up)
- 🔒 TLS cert expiry — days remaining on each endpoint's certificate
- 📈 Small built-in time-series store + graphs (no external database)
- 📜 Live container logs over SSE, in the browser
- 🔔 Alerting that only fires on real problems — debounced, transition-only,
  with recovery notices and flap-dampening; pluggable channels (Telegram, ntfy)
- 💓 Heartbeat to a dead-man's-switch, so a dead monitor doesn't fail silently
- 🔑 Passkey (WebAuthn) sign-in for the dashboard — no password to leak
- 🪶 One static binary · runs as a host `systemd` service · < 25 MB RSS

## Quickstart

> **Status: early — building in the open.** The spec is in [`SPEC.md`](SPEC.md);
> the milestones below track what's live.

**Binary (recommended — host-native, survives Docker outages):**

```sh
curl -fsSL https://github.com/mich312/vm-vitals/releases/latest/download/install.sh | sh
sudo cp config.example.toml /etc/vitals/config.toml   # then edit it
sudo systemctl enable --now vitals
```

**Docker (if you'd rather):**

```sh
docker run -d --name vitals \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc:/host/proc:ro -v /:/host/root:ro \
  -v ./config.toml:/etc/vitals/config.toml:ro \
  -v vitals-data:/var/lib/vitals \
  -p 127.0.0.1:9110:9110 ghcr.io/mich312/vitals:latest
```

Then open the dashboard (put it behind your own TLS + auth, or use the built-in
passkey login) and enroll a passkey on first run.

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

[[endpoints]]
name = "my-app"
url = "https://app.example.com/"
```

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

- The Docker socket is mounted **read-only**; access to it is effectively root,
  so vitals never exposes it and the dashboard is authenticated.
- The dashboard binds to loopback; front it with TLS (passkeys require HTTPS).
- No secrets are stored in the history DB.

See [docs/security.md](docs/security.md).

## Roadmap

- [ ] **M0** — host + container metrics, JSON status
- [ ] **M1** — alerting engine + notifiers + heartbeat
- [ ] **M2** — history + graphs + live logs
- [ ] **M3** — passkey auth + production deploy
- [ ] **M4** — release: docs, container image, installer

## License

MIT © mich312. (Happy to dual-license MIT/Apache-2.0 if that helps adoption.)
