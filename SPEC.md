# vitals — a small self-hosted watchdog

> _Vitals — know how your servers are doing._

A single Rust binary that watches one host and its Docker containers: collects
host + container metrics, checks the public endpoints and their TLS certs,
keeps a little history for graphs, and **pushes an alert the moment something
crosses a line** — then again when it recovers.

Runs as a **host `systemd` service, not a container**, on purpose: if the
Docker daemon wedges, a containerized monitor dies with the thing it watches;
a host binary keeps running and can still tell you Docker is down.

Target box: 1 host, 2 cores / 3.7 GB, ~10 containers behind the `edge` Caddy
proxy. Footprint budget: **< 25 MB RSS, < 2% CPU, a few MB of DB.**

---

## Goals

- Tell me — via push — when: disk is filling, memory/swap is under pressure, a
  container is down or crash-looping, a site stops returning its expected
  status, a TLS cert is near expiry, or the monitor itself has died.
- Show current state at a glance (host gauges + per-container table + endpoint
  and cert status + active alerts) on one authed page.
- Keep **some** history (hours→weeks) and draw simple time-series graphs.
- Be one small thing I own, tailored to exactly this fleet.

## Non-goals

- Multi-host / fleet management (single host only).
- Long-term metrics retention or a real TSDB (weeks, not years).
- Log storage/search/retention — vitals does live *tailing* (§7), not a
  searchable log store; point a log stack at it if you need that.
- APM / tracing / per-request metrics. Full Grafana/Prometheus parity.
- An alert-routing rules engine. One channel, a fixed rule set in config.

---

## 1. Architecture

One `tokio` binary, a handful of modules, a fixed tick (default **15 s**):

```
             ┌────────────── tick (15s) ──────────────┐
 collectors  │ host (sysinfo) · docker (bollard) ·     │
             │ endpoints (reqwest) · tls (rustls)      │
             ▼                                          │
 store    SQLite (WAL): append samples ── compactor ── rollup + prune
             ▼                                          │
 evaluator  per-check state machine (debounce, flap-dampen, severity)
             ▼                                          │
 notifier  Telegram / ntfy  (on transitions only, + re-alert cooldown)
             │                                          │
 heartbeat  ping dead-man's-switch each tick ◄──────────┘
             ▲
 web (axum, loopback :9110)  status page · /api · graphs · optional SSE logs
```

Modules: `config`, `collect/{host,docker,endpoint,tls}`, `store`, `eval`,
`notify`, `heartbeat`, `web`. Everything shares one `AppState` (config +
db handle + in-memory current snapshot + alert states).

### Crates
- `tokio` (rt + macros), `axum` + `tower-http` (web, basic-auth, compression)
- `sysinfo` (host cpu/mem/disk/load), `bollard` (Docker API over the socket)
- `reqwest` (endpoint checks; `rustls` backend), `tokio-rustls`/`x509-parser`
  (cert expiry via a handshake)
- `rusqlite` (bundled SQLite) *or* `sqlx` (sqlite) — lean toward `rusqlite`
- `serde` + `toml` (config), `tracing` (logs), `rust-embed` (bundle the
  dashboard assets into the binary — no external CDN, matches the CSP posture)

---

## 2. What it collects (each tick)

**Host** (`sysinfo`): cpu % (overall), mem used/avail %, swap used + swap-in
rate, disk used % for `/`, load1/5/15, uptime.

**Docker** (`bollard`, `/var/run/docker.sock` read-only): per container —
state (`running`/`exited`/`restarting`), health (if a healthcheck exists),
`RestartCount`, cpu %, mem usage + limit, net i/o. Discovery: all containers,
or filter by compose-project label.

**Endpoints** (`reqwest`, from the host): for each configured URL — status
code, response time, TLS handshake ok. Checks go to the **public** URL so they
exercise the whole path (edge → app), same as the deploy health checks.

**TLS** (`tokio-rustls` handshake + `x509-parser`): notAfter → days-to-expiry
per hostname. (Caddy auto-renews; this is the safety net.)

**Self**: collector error counts; tick duration; last-successful-tick time.

---

## 3. Storage & history (SQLite)

One file (`/var/lib/vitals/vitals.db`, WAL mode). "Some history" = a tiered
rollup so the DB stays a few MB while covering hours→weeks.

```sql
CREATE TABLE series  (id INTEGER PRIMARY KEY, metric TEXT, labels TEXT,
                      UNIQUE(metric, labels));           -- e.g. metric='container.cpu', labels='name=gta'
CREATE TABLE samples (series_id INT, ts INT, value REAL, res INT,
                      PRIMARY KEY(series_id, res, ts)) WITHOUT ROWID;
-- res = resolution bucket in seconds: 15 (raw), 300 (5-min), 3600 (1-hour)
```

**Retention / downsampling** (compactor task, runs every few minutes):

| resolution | kept for | rows/series |
| ---------- | -------- | ----------- |
| 15 s (raw) | 48 h     | ~11.5 k     |
| 5 min      | 30 d     | ~8.6 k      |
| 1 h        | 180 d    | ~4.3 k      |

Downsample = `avg`, plus `min`/`max` for the graph band (store as extra series
or extra columns). With ~30 series total the DB stays well under ~10 MB.
Prune with `DELETE ... WHERE ts < now-window` per resolution; `VACUUM` weekly.

Graph query API picks the coarsest resolution that satisfies the requested
range so a 30-day view isn't 170 k points.

---

## 4. Evaluation & alerting (the highest-value part)

Each **check** is a small state machine — this is what separates a useful
alerter from a noise machine:

```
OK ──breach≥ debounce ──▶ FIRING ──recovered──▶ OK
        (N ticks)              │
                              re-alert every `reminder` while still FIRING
```

- **Debounce**: a threshold must hold for `debounce` (default 3 ticks / ~45 s)
  before FIRING — kills transient spikes (a build briefly pegging CPU).
- **Alert only on transitions**: notify on `OK→FIRING` and `FIRING→OK`
  (recovery). Never on every tick.
- **Reminder**: if still FIRING after `reminder` (default 6 h), re-notify.
- **Severity**: `warn` / `crit` with separate thresholds; crit can page harder.
- **Flap dampening**: if a check flips >K times in an hour, coalesce and note
  "flapping" instead of spamming.

### Rule set (defaults; all in config)
| check | warn | crit |
| --- | --- | --- |
| `host.disk_pct` | > 80 | > 90 |
| `host.mem_avail_mb` | < 400 | < 200 |
| `host.swap_in` sustained | present | heavy |
| `host.load1` | > cores×1.5 | > cores×3 |
| `container.state` | — | ≠ running |
| `container.restarts` (Δ in 10 m) | — | > 0 (crash loop) |
| `container.cpu_pct` (10 m avg) | > 85 | — |
| `container.mem` vs limit | > 85% | > 95% |
| `endpoint.status` | slow (>2 s) | ≠ expected code |
| `cert.days_left` | < 14 | < 3 |
| `self.stale_tick` | — | no successful tick in 3× interval |

Each endpoint declares its **expected** code (quorum 200, lounge 302,
support 401, gta 200, mmo 200, worktime 200) — so a 502/404/401-where-200-
expected fires. This is the "deploy went green but the site is actually
broken" class.

### Notifier
Telegram (`sendMessage`) or ntfy (POST to a topic). Messages are compact and
stateful: `🔴 CRIT lounge-mcp: restarting (3 restarts/10m)` … `🟢 OK
lounge-mcp: recovered (up 4m)`. Retry with backoff; queue if the channel is
briefly unreachable.

### Heartbeat / dead-man's-switch
Every tick, ping an external URL (healthchecks.io, Uptime Kuma push, or a
second ntfy topic with an expected cadence). If vitals dies, *that* service
alarms — because a monitor that can fail silently is worse than none.

---

## 5. Surface: API-first, then MCP, dashboard optional

The primary surface is a **REST/JSON API** (axum, loopback `:9110`, fronted by
the `edge` proxy at **`status.mich312.com`**). An **MCP server** is a thin
adapter over the same data so an agent (Claude) can ask about the box. A human
**dashboard is a nice-to-have** that just renders the REST API. All three read
one shared snapshot + the history store.

**Auth — bearer token** (config `web.token` or `$VITALS_TOKEN`) on `/api/*`
and the MCP endpoint; `/healthz` open. Simple, standard, and exactly what MCP
clients expect (like the lounge-mcp token). For the optional dashboard, layer
**passkeys** (WebAuthn via `webauthn-rs`) for a browser session later; a
`trust_proxy_auth` mode skips built-in auth when an upstream proxy authenticates.

**REST API**
- `GET /api/status` — current snapshot (host + containers) as JSON. _(M0, live.)_
- `GET /api/containers`, `GET /api/alerts` — detail views.
- `GET /api/series?metric=…&labels=…&from=…&to=…` — chart points; server picks
  the resolution.
- `GET /api/logs/:container` — SSE stream of `docker logs -f` (§7).

**MCP** (streamable-HTTP, e.g. `/mcp`) — tools over the same data:
`host_metrics`, `list_containers`, `container_logs`, `active_alerts`,
`query_history`. Read-only; token-authed.

**Dashboard (optional)** — `GET /` overview (host gauges · container table ·
endpoint/cert status · active alerts) and `/graphs` (uPlot, embedded via
`rust-embed`, no CDN). Built once the API + MCP are solid.

---

## 6. Config (`/etc/vitals/config.toml`)

```toml
interval = "15s"

[alert]
channel = "telegram"          # or "ntfy"
telegram = { bot_token_env = "VITALS_TG_TOKEN", chat_id = "..." }
# ntfy   = { url = "https://ntfy.sh/…", priority = "high" }
debounce = 3                  # ticks a breach must hold before firing
reminder = "6h"
heartbeat_url = "https://hc-ping.com/…"

[thresholds]
disk_warn = 80; disk_crit = 90
mem_avail_warn_mb = 400; mem_avail_crit_mb = 200
# … (table in §4, all overridable)

[docker]
socket = "/var/run/docker.sock"
# watch all, or: projects = ["discord","durst-lounge","edge","gta-2", …]

[[endpoint]]
name = "quorum"; url = "https://quorum.mich312.com/"; expect = 200
[[endpoint]]
name = "lounge"; url = "https://lounge.mich312.com/"; expect = 302
# … support 401, gta 200, mmo 200, worktime 200

[retention]                    # §3
raw = "48h"; five_min = "30d"; hour = "180d"

[web]
bind = "127.0.0.1:9110"
```

Secrets (bot token) come from the environment / a systemd `EnvironmentFile`,
never the TOML.

---

## 7. Live logs (SSE)

`GET /logs/:container` attaches to the Docker socket's log-follow stream
(`bollard` `logs { follow: true, tail }`), demuxes the stdout/stderr framing,
and relays lines over **Server-Sent Events** to a small in-browser tail view.
Details: a ring buffer of the last N lines per container (seed on connect),
backpressure (drop-oldest if a client stalls), auto-reconnect, and a level/
substring filter client-side. **In scope** — you get per-container live logs
from the same binary, so no separate Dozzle. Multi-container "follow all" is a
later nice-to-have.

---

## 8. Deployment (fits the existing pipeline pattern, binary-style)

Not a container — a static musl binary under systemd:

- **CI**: GitHub Actions builds `x86_64-unknown-linux-musl` (fully static),
  uploads the binary as a release asset / artifact.
- **Deploy** (same `DEPLOY_SSH_KEY`/`DEPLOY_HOST` secret pattern): ship the new
  binary to the host (`scp`/`curl` the asset), `systemctl restart vitals`,
  health-check `http://127.0.0.1:9110/api/status`, roll back to the previous
  binary if it doesn't come up. Seconds, no build on the box.
- **systemd unit** (`/etc/systemd/system/vitals.service`): runs as a
  dedicated `vitals` user in the `docker` group (socket read access), with
  `ReadWritePaths=/var/lib/vitals`, `EnvironmentFile=/etc/vitals/vitals.env`,
  `Restart=always`. Hardening: `ProtectSystem=strict`, `NoNewPrivileges`,
  `PrivateTmp`.
- **edge**: add `status.mich312.com { basic_auth {…}; reverse_proxy
  host.docker.internal:9110 }` — note the backend is a **host** port, not a
  container, so the block uses the host gateway rather than a service name.

### Security notes
- Docker socket access ≈ root. Mount/read it **read-only**; never expose it.
- Dashboard: loopback bind + Basic Auth at the edge (or localhost + SSH tunnel
  if you'd rather it not be public at all).
- No secrets in the DB or in graphs.

---

## 9. Open-source packaging

It's a public GitHub project, so it needs the trimmings and a couple of design
choices that differ from a private tool:

- **Dual deployment.** Recommend the host `systemd` binary (survives Docker
  outages), but many users will want a **container** — so also ship an image
  that mounts `/var/run/docker.sock:ro`, `/proc:ro`, `/:/host:ro` and reads a
  config volume. Document the host-binary reliability trade-off honestly.
- **License**: dual **MIT OR Apache-2.0** (idiomatic for Rust; permissive +
  patent grant). `LICENSE-MIT`, `LICENSE-APACHE`.
- **README**: logo + one-line pitch + a short animated GIF/screenshot of the
  dashboard, feature bullets, 30-second quickstart (both binary and Docker), a
  config reference link, a security section (Docker-socket = root, auth,
  loopback), and a "how it compares" note (vs Netdata/Beszel/Prometheus:
  smaller, single-binary, host-native, alert-first).
- **`docs/`**: `install.md`, `configuration.md`, `alerting.md`,
  `architecture.md`, `deployment.md` (systemd + Docker), `security.md`.
- **CI/CD** (GitHub Actions): fmt + clippy + test on PRs; on tag, build static
  `x86_64`/`aarch64` musl binaries + a multi-arch container image, attach to a
  GitHub Release, publish the crate (optional). Renovate/dependabot.
- **Community files**: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR
  templates, `SECURITY.md` (responsible disclosure), `CHANGELOG.md`.
- **Config over hardcoding**: nothing mich312-specific in the code — the
  endpoints/thresholds/hostnames all come from `config.toml`; ship an
  `config.example.toml`.
- **Install ergonomics**: a one-line `curl | sh` installer (fetches the right
  musl binary + writes a sample unit), plus `cargo install` and the image.

## 10. Milestones

- **M0 — skeleton**: config load, host + docker collectors, `/api/status`
  JSON on loopback. Prove the data is right.
- **M1 — alerting** (*the value*): evaluator state machine + a **pluggable
  notifier** (trait; Telegram + ntfy first, channel TBD) + heartbeat. Earns
  its keep with no UI.
- **M2 — history + graphs + logs**: SQLite store + compactor + `/api/series`,
  the `/graphs` page (uPlot), and SSE **live logs** (§7). Endpoint + cert
  checks folded in.
- **M3 — auth + production**: overview page, **passkey (WebAuthn) auth** +
  sessions, edge route, CI musl build + systemd deploy + rollback.
- **M4 — open-source release**: README + logo + docs + license + CI release
  pipeline + container image + example config.

Ship M0+M1 first: alerting is 80% of the value at 20% of the code, and it's
useful the day it runs. Harden + brand for the public release last.

---

## Decisions

Resolved:
- **Alert channel** — deferred; build a **pluggable notifier trait** (Telegram
  + ntfy implemented first), pick the default later.
- **History depth** — keep the 48 h / 30 d / 180 d tiers.
- **Auth** — **full app-level auth with passkeys** (WebAuthn), plus a
  trust-proxy mode for OSS operators (§5).
- **Live logs** — **in scope now**, streamed from the Docker socket over SSE
  (§7); no Dozzle dependency.

Still open:
- **Name + logo** — see the shortlist we're picking from.
- Default alert channel (once the trait exists).
