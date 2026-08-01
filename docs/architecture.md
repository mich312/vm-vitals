# Architecture

One `tokio` binary on a fixed tick (default 15s):

```
collectors → store (SQLite) → evaluator → notifier
   host        history+rollups   state       Telegram/ntfy
   docker                        machine
   endpoints                                 heartbeat → dead-man's-switch
   tls
        └────────────── web (axum, loopback) : status · graphs · logs
```

- **collectors** — host (`sysinfo`), docker (`bollard`), endpoint (`reqwest`),
  tls (handshake + `x509-parser`).
- **store** — SQLite with tiered rollups (raw 48h / 5-min 30d / 1-hour 180d).
- **evaluator** — a per-check state machine: debounce, transition-only alerts,
  reminders, flap-dampening.
- **notifier** — pluggable trait; Telegram + ntfy first.
- **web** — embedded dashboard (status page, uPlot graphs, SSE logs), passkey
  auth.

Full detail: [`../SPEC.md`](../SPEC.md).
