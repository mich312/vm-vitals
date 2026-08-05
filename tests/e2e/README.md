# Browser end-to-end test

`./run.sh` — needs `cargo build --release`, Node, Playwright, and openssl.

Covers what the Rust tests structurally cannot: that a real browser accepts the
`__Host-`-prefixed session cookie, that the Content-Security-Policy does not
block the pages' own inline scripts, that POST logout actually clears the
cookie, that the dashboard's poll loop stays single-instance across tab
visibility changes, and that an unreachable Docker daemon renders as a critical
state rather than "all systems healthy".

WebAuthn is driven through Chrome DevTools Protocol's virtual authenticator, so
no physical security key is needed. TLS is terminated by `proxy.js` with a
throwaway self-signed certificate, because `__Host-` and `Secure` only behave
correctly over HTTPS — testing over plain-HTTP localhost would exercise a
configuration nobody deploys.
