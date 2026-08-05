# Deployment

## Host binary (recommended)

vitals runs as a `systemd` service so it stays up even if the Docker daemon
does not — a containerised monitor dies with the thing it watches.

```ini
# /etc/systemd/system/vitals.service
[Unit]
Description=vitals — host + Docker watchdog
Wants=network-online.target
# `After=` alone does not pull the target in; and without docker.socket a boot
# race would otherwise start vitals before the daemon is listening.
After=network-online.target docker.socket

[Service]
ExecStart=/usr/local/bin/vitals --config /etc/vitals/config.toml
User=vitals
Group=vitals
# NOTE: this is root-equivalent — see docs/security.md. Drop it and use a
# read-only socket proxy via `[docker] socket` where you can.
SupplementaryGroups=docker
# No leading `-`: a missing env file must fail the unit rather than silently
# starting without $VITALS_TOKEN.
EnvironmentFile=/etc/vitals/vitals.env
StateDirectory=vitals
StateDirectoryMode=0700
UMask=0077
Restart=always
RestartSec=5

# --- sandboxing ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
DevicePolicy=closed
ProtectProc=invisible
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @mount @debug @swap @reboot @module
CapabilityBoundingSet=
AmbientCapabilities=

# --- resource ceilings ---
MemoryMax=128M
TasksMax=64
LimitNOFILE=1024

[Install]
WantedBy=multi-user.target
```

### Three directives to *not* add

These look like obvious next hardening steps and each one silently breaks the
monitor:

- **`ProcSubset=pid`** hides `/proc/meminfo`, `/proc/stat` and `/proc/loadavg`
  — exactly what `sysinfo` reads. Every host metric would read zero and the
  disk/memory/load alerts would never fire again. (`ProtectProc=invisible`
  above is safe: it hides *other processes'* directories, not the global files.)
- **`PrivateUsers=true`** remaps the supplementary GID and breaks Docker socket
  access.
- **`PrivateNetwork=true`** cuts off the alert channel, the heartbeat, and every
  endpoint check.

`IPAddressDeny=any` with an explicit allow-list is worthwhile, but only if you
enumerate the alert channel, heartbeat, resolver and every endpoint target —
otherwise alerting fails closed and silently.

Verify with `systemd-analyze security vitals.service`, then confirm host metrics
are still non-zero in `/api/status` before you walk away.

### Files

```sh
sudo install -D -o root -g vitals -m 0640 config.example.toml /etc/vitals/config.toml
sudo install -D -o root -g root  -m 0600 /dev/null /etc/vitals/vitals.env
```

`vitals.env` is read by systemd as root before dropping privileges, so it should
*not* be group-readable; `config.toml` must be, since the service reads it.

## Docker (alternative)

You lose the "survives Docker being down" property, but it's convenient. Run it
unprivileged and drop capabilities:

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

Two deliberate differences from the obvious command:

- **No `/proc` or `/` mounts.** Earlier docs mounted `-v /:/host/root:ro` and
  `-v /proc:/host/proc:ro`; nothing in the code ever read them. They handed a
  root container the entire host filesystem — including every other container's
  volumes — and, via `/host/proc/<pid>/environ`, the environment of every host
  process running as root.
- **No `:ro` on the socket.** It restricts nothing (see docs/security.md) and
  stating it implies a protection that does not exist.

Consequence of dropping the host mounts: inside a container, `sysinfo` measures
the *container's* filesystem, so `disk_used_pct` describes the overlay, not the
host. **Host disk alerting is not meaningful in the Docker deployment** — use
the host-binary deployment if you want it.

## Upgrades

The history DB carries a schema version. If an upgraded binary meets an older
file it logs a warning and rebuilds the store — metrics history is derived data
and will be re-collected. Enrolled passkeys in `auth.json` are unaffected.

_Expands as M3 lands._
