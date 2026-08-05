# Security

vitals watches a whole host, so treat it with care.

## The Docker socket is root

Access to `/var/run/docker.sock` is equivalent to root on the host. Two claims
that are commonly made about this — and are **both false** — are worth stating
plainly, because believing them leads to under-protecting the socket:

- **Mounting the socket `:ro` restricts nothing.** `:ro` sets `MS_RDONLY` on the
  *mount*, which gates operations that modify the filesystem. Talking to a Unix
  socket is `socket()` → `connect()` → `write()` on the socket fd, and the
  kernel checks only the inode's permission bits for that. The Docker Engine API
  behind a `:ro`-mounted socket is fully read-write. There is no read-only mode
  in the Engine API, and `:ro` cannot create one.
- **`SupplementaryGroups=docker` is not "read access".** Group membership grants
  the entire Engine API. Anything holding it can `POST /containers/create` with
  `Binds:["/:/host"]` and `Privileged:true`, then `POST /containers/start`, and
  have uid 0 on the host in two calls. That executes inside `dockerd`, so every
  hardening directive in the vitals unit — `NoNewPrivileges`, `ProtectSystem`,
  seccomp — is bypassed.

**The accurate statement is:** vitals holds credentials equivalent to root on
this host, and voluntarily issues only read calls (`GET` on `/containers/json`,
`/containers/{id}/json`, `/containers/{id}/stats`, `/containers/{id}/logs`,
`/_ping`, `/version`). That is a property of vitals' own code, not a restriction
anyone is enforcing on it. If vitals is compromised, the host is compromised.

### Reducing it

Because vitals needs only those five read endpoints, a socket proxy is a real
mitigation rather than a fig leaf. Run one, deny `POST` entirely, and point
vitals at it with `[docker] socket`:

```yaml
docker-socket-proxy:
  image: tecnativa/docker-socket-proxy
  read_only: true
  environment: [ CONTAINERS=1, VERSION=1, PING=1, POST=0, EXEC=0, IMAGES=0,
                 NETWORKS=0, VOLUMES=0, BUILD=0, COMMIT=0, INFO=0, AUTH=0,
                 SECRETS=0, CONFIGS=0, SWARM=0, NODES=0, SERVICES=0, TASKS=0,
                 SYSTEM=0, PLUGINS=0, SESSION=0, DISTRIBUTION=0 ]
  volumes: [ "/var/run/docker.sock:/var/run/docker.sock" ]
  ports: [ "127.0.0.1:2375:2375" ]
```

```toml
[docker]
socket = "tcp://127.0.0.1:2375"
```

Then drop `SupplementaryGroups=docker` from the vitals unit entirely.

**Residual risk, even with a perfect read-only allowlist:** `GET
/containers/{id}/json` returns `Config.Env` — every environment variable of
every container, which is usually the complete secret inventory of the host.
vitals reads only `restart_count` and `state.health` from that response, but the
*credential* to read all of it is what the proxy grants. A path-prefix proxy
with `CONTAINERS=1` also permits `GET /containers/{id}/archive`, i.e. reading
files out of any container.

## Dashboard auth

- **vitals fails closed.** It refuses to start if it would serve a non-loopback
  address with neither `web.rp_id`/`web.rp_origin` nor `web.token` configured,
  and it aborts rather than continuing unauthenticated if passkey
  initialisation fails. On loopback it starts with a warning, for development.
- **Passkeys need HTTPS.** Credentials are bound to `rp_id`/`rp_origin`, so
  serve the dashboard over TLS at a stable hostname *before* enrolling.
  Changing either value later invalidates every enrolled credential.
- **Enrolment requires a one-time code.** On first start, with no credential
  enrolled, vitals generates a code and prints it to the log
  (`journalctl -u vitals`). The sign-in page will not enrol a passkey without
  it, so reaching the URL first is not enough to claim the account. The code is
  burned on the first successful enrolment and is never written to disk — if
  you lose it before enrolling, restart the service for a new one.
- **Sessions** last 12 hours, are held server-side, and are invalidated on sign
  out. Cookies are `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite=Lax`.

There is no `trust_proxy_auth` setting. It was previously documented here and
never implemented; putting it in `[web]` is now a startup error rather than
something silently ignored. If you front vitals with your own authenticating
proxy, bind vitals to loopback and let the proxy be the only route to it.

## Secrets

- `web.token` (or `$VITALS_TOKEN`) gates `/api/*`. Minimum 16 characters —
  `openssl rand -hex 32`. An empty value is treated as unset, not as a token
  that matches an empty `Bearer`.
- Prefer the systemd `EnvironmentFile` over `config.toml` for the token. Note
  the unit uses `EnvironmentFile=` **without** a leading `-`: a missing env file
  must fail the unit, because silently starting without `$VITALS_TOKEN` is an
  authentication downgrade.
- `/etc/vitals/config.toml` → `0640 root:vitals`. `/etc/vitals/vitals.env` →
  `0600 root:root` (systemd reads it as root before dropping privileges).
- `/var/lib/vitals` → `0700`, via `StateDirectoryMode=`. `auth.json` is written
  `0600` and replaced atomically.

## Data at rest

The history DB stores metric values only — but **metric names include your
container names**, retained at 1-hour resolution for 180 days. That is a
persistent inventory of what runs on the box plus a six-month load profile, so
treat the file as sensitive even though it holds no credentials. Series whose
containers are gone are garbage-collected during compaction.

Found a vulnerability? See `SECURITY.md` (responsible disclosure) once the repo
is public.
