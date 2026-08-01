# Deployment

## Host binary (recommended)

vitals runs as a `systemd` service so it stays up even if the Docker daemon
does not — a containerised monitor dies with the thing it watches.

```ini
# /etc/systemd/system/vitals.service
[Unit]
Description=vitals — host + Docker watchdog
After=network-online.target

[Service]
ExecStart=/usr/local/bin/vitals --config /etc/vitals/config.toml
User=vitals
SupplementaryGroups=docker           # read /var/run/docker.sock
EnvironmentFile=-/etc/vitals/vitals.env
StateDirectory=vitals                # /var/lib/vitals (the history DB)
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vitals
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

CI builds a static `musl` binary; deploy ships it to the host and restarts the
service (same key/secret pattern as any SSH deploy), then health-checks
`http://127.0.0.1:9110/api/status` and rolls back the binary on failure.

## Docker (alternative)

See the image usage in the [README](../README.md#quickstart). You lose the
"survives Docker being down" property, but it's convenient.

_Expands as M3 lands._
