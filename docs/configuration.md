# Configuration

vitals reads one file: `/etc/vitals/config.toml`. Start from
[`../config.example.toml`](../config.example.toml).

Sections:

- **`interval`** — collect + evaluate cadence (default `15s`).
- **`[web]`** — `bind` (loopback), `trust_proxy_auth` (skip built-in auth when a
  front proxy authenticates).
- **`[alert]`** — `channel` (`ntfy` | `telegram`), `debounce`, `reminder`,
  `heartbeat_url` (dead-man's-switch), and the channel block. Secrets (e.g. a
  Telegram token) come from the environment via `*_env`, never this file.
- **`[thresholds]`** — warn/crit levels for disk, memory, load, container CPU,
  and cert days-to-expiry. See the [alerting](alerting.md) page for how they
  turn into notifications.
- **`[docker]`** — socket path; optionally narrow to specific compose projects.
- **`[retention]`** — the three history tiers (raw / 5-min / 1-hour).
- **`[[endpoint]]`** — one block per URL to check, each with the `expect`ed
  status code.

_This page fills in with the full reference as the config surface stabilises._
