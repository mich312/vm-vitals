# Security

vitals watches a whole host, so treat it with care.

- **Docker socket = root.** Access to `/var/run/docker.sock` is equivalent to
  root on the host. vitals mounts/opens it **read-only** and never exposes it.
  If you run vitals in a container, that container is privileged-adjacent — the
  host-binary deployment is preferable partly for this reason.
- **Dashboard auth.** The dashboard binds to loopback and is meant to sit behind
  TLS. Auth is passkey-first (WebAuthn); enroll on first run. If you front it
  with your own authenticating proxy, set `trust_proxy_auth = true`.
- **Passkeys need HTTPS.** They're bound to the origin (`RP_ID`), so serve the
  dashboard over TLS at a stable hostname before enrolling.
- **No secrets in history.** The time-series DB stores metrics only; alert
  tokens come from the environment.

Found a vulnerability? See `SECURITY.md` (responsible disclosure) once the repo
is public.
