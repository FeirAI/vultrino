# Security Model

What Vultrino defends, the invariants it upholds, its authn/authz, its trust
boundaries, and what it deliberately does **not** do. Every guarantee is stated
with its bounds. Verified against `src/egress.rs`, `src/plugins/http.rs` (SSRF),
`src/crypto/`, `src/policy/`, `src/auth/`, `src/server/mod.rs`, and
`src/web/`.

## Threat model

Vultrino sits **in-path** between a (semi-trusted or untrusted) automated caller —
typically an AI agent or LLM tool — and the credentialed resources it must act on.
The primary adversary is the **caller itself**: a prompt-injected, buggy, or
compromised agent that should be able to *use* a credential for sanctioned actions
but must never *exfiltrate* the secret, exceed its grant, or act after it has been
revoked.

In scope:

- An agent trying to read back the injected secret (reflection, echo endpoints,
  open redirects, compressed bodies).
- An agent trying to use a credential or action outside its grant (wrong
  credential, wrong action, over a spend/rate cap, after a kill).
- An agent trying to reach internal infrastructure via the proxy (SSRF).
- A compromised agent that must be **stopped immediately** mid-incident.
- Brute-force / enumeration against the admin login.

Out of scope (relied on the deployment): the host OS and disk integrity, the
vault password's secrecy, TLS termination at the edge, and the correctness of any
WASM plugin you install.

## Invariants Vultrino upholds

1. **The caller never sees the secret.** Secrets are stored encrypted, injected
   server-side, and never returned by any endpoint (credential reads return
   metadata only). A credential's own reflected secret is scrubbed from the
   response body and headers before it reaches the caller (egress layer 1), and a
   response that can't be scrubbed (still-compressed body) is **withheld
   entirely** (fail-closed).
2. **Default-deny.** A credential matching no policy is denied (`no_policy`
   reason). Fail-open is opt-in (`[enforcement] default_action = "allow"`) and
   warned about loudly at startup.
3. **A use token cannot exceed its grant.** Credential scope and action scope are
   enforced authoritatively at the execution seam (not only at the edge); use
   consumption is atomic and fail-closed (reserve-on-execute) so a token can never
   drive more than `max_uses` executions, even on a downstream error.
4. **A halt takes effect immediately and cannot be ordered around.** Token
   revocation is storage-authoritative (re-checked under the lock on every gated
   call, across processes); the kill policy is `kill = true` and short-circuits
   ahead of any allow rule. Observe mode never downgrades a halt.
5. **An approval is not a policy bypass.** The deferred post-approval path
   re-evaluates policy read-only and re-enforces hard `Deny`/kill gates — a policy
   revoked or a Deny pushed between approval and execution stops the action. An
   approved action runs **at most once** across all polls (claimed under the lock).
6. **Security/financial boundaries hold even in observe mode.** Cross-tenant
   isolation, halts, and SpendCap/RateLimit resource guards always enforce; only
   ordinary policy denials are observable-away.
7. **Events are signed and ordered.** Every outbox delivery (and replay) carries
   `Govder-Signature: sha256=HMAC-SHA256(secret, body)`; the sequence is monotonic
   and gap-free, so a consumer detects a dropped *delivery*.
8. **The admin surface is API-key-only.** Use tokens can never reach the admin API
   (`403 not_admin`), and admin authentication is checked before the request body
   is parsed.

## Authentication & authorization

- **Storage / vault:** AES-256-GCM with an Argon2-derived key from the storage
  password + a random per-vault salt. The key is never stored; the password is
  required by every vault-touching command.
- **API keys (`vk_`):** hashed (SHA-256) at rest; the plaintext is shown once at
  creation. A key maps to a **role** carrying a `Permission` set
  (`read`/`write`/`update`/`delete`/`execute`/`admin`) and `credential_scopes`
  (globs). `/execute` requires `execute` plus a role scope covering the credential.
- **Use tokens (`vut_`):** hashed at rest; carry their own credential glob, action
  scope, use count, expiry, and optional `agent_label`/`owner`/`tenant`. Backed by
  an ephemeral `read`+`execute` grant scoped to the token's credential.
- **Web admin login:** username + bcrypt password hash (`admin.json`), constant-
  time comparison, username-enumeration-resistant, rate-limited per client IP
  (honoring `X-Forwarded-For`/`X-Real-IP`), CSRF-protected write forms,
  session cookies.
- **Out-of-band approval links:** authorized by a high-entropy **random capability
  token** in the link (`OsRng`-generated). The server stores only the token's
  **hash** and verifies a presented token by hashing it and **constant-time
  comparing** the hashes (`subtle::ConstantTimeEq`) — it is a hashed bearer
  capability, *not* an HMAC. A link prefetch only renders a confirmation page —
  the decision requires a POST. The verdict is attributed to the configured
  `oob_approver_identity` (required when a notifier is set, else config load
  fails).
- **Inbound workload identity (V10/R6):** optional SPIFFE/OIDC resolution of a
  header the deployment has *already verified* at the edge. It **refines** the
  principal (adds a `workload_id` policy match dimension and binds the owner for
  separation of duty) but never replaces the `vk_`/`vut_` id — a halt keyed on the
  id always holds, and a bad document can only fail to refine, never elevate.

## Trust boundaries

| Boundary | Trusted? | Notes |
|----------|----------|-------|
| The calling agent | **No** | The primary adversary. Sees only aliases + scrubbed responses. |
| The bearer token presented | Authenticated | `vk_`/`vut_` validated by hash; scope enforced server-side. |
| The `[identity]` header | **Trusted (edge-verified)** | The deployment MUST terminate mTLS / verify the token and pass the verified document. Vultrino does not itself verify the SVID/OIDC signature. |
| The host / disk / vault password | Trusted | Vault confidentiality rests on the password's secrecy and OS file protection. |
| Installed WASM plugins | Trusted code | A plugin runs with the credential's secret; install only plugins you trust. |
| The upstream the proxy calls | **No** | Treated as hostile for read-back: secret scrubbing + egress block/redact + SSRF guard. |
| The outbox consumer | Authenticated by HMAC | Deliveries are signed; the consumer verifies. |

## SSRF protection

The built-in HTTP plugin validates every target URL **after** policy admission
(`validate_url_ssrf` in `src/plugins/http.rs`): it requires the host not resolve to
a private/internal address. It blocks IPv4 loopback (`127.0.0.0/8`), RFC1918
private ranges, link-local (`169.254.0.0/16`, which covers cloud metadata
`169.254.169.254`), IPv6 loopback/link-local/ULA, and IPv4-mapped IPv6 forms of
those — checking **every** resolved IP, not just an IP literal. OAuth2 token URLs
get the same guard and must be HTTPS. So a proxied request to `127.0.0.1` or a
metadata endpoint is denied at the transport step.

## Egress / read-back defense (V7)

Two layers at the execution seam, run by `egress::scrub_response` before the body
reaches the caller:

1. **Always-on secret scrubbing.** The credential's own injected secret — and its
   percent-encoded and JSON-escaped forms, and derived forms like the Basic-auth
   base64 — is replaced with `[REDACTED:<alias>]` in the body and headers.
   Framing headers (`Content-Length`/`Transfer-Encoding`) a redaction invalidates
   are stripped so a stale length can't leak the original.
2. **Operator egress classification.** `[[egress]]` rules `block` a secret-bearing
   endpoint's body+headers entirely, or `redact_patterns` extra regexes.

**Honest bounds (defense-in-depth, not absolute):** scrubbing operates on the
plaintext response. An endpoint that *transforms* the secret (re-encodes,
hashes, gzips a reflected copy beyond what the client decompressed) can still leak
it — use a `block` rule for endpoints you don't trust. Secrets shorter than
`MIN_REDACT_LEN = 5` are not byte-scrubbed (they'd over-redact and carry little
entropy); credential-store time warns about these, and they should use a `block`
rule. A still-compressed body is withheld entirely (fail-closed).

## Defaults that fail safe

- Engine default `deny`; SpendCap unparseable → deny; cross-tenant + untenanted
  principal → enforce; a malformed egress/policy/identity glob is a hard config
  error (no silent degrade to never-matching).
- An outbox push with no URL or no signing secret is a hard config error
  (an unsigned/undeliverable outbox is rejected).
- A halt label must be a literal id (no glob), so a halt can't deny a fleet.

## What Vultrino deliberately does NOT do

- **No cumulative spend/budget accounting.** Only per-action, stateless SpendCap.
  Windowed budgets, ledgers, and reconciliation live in the metering plane;
  enforcement returns as a pushed `Deny` policy. (See [METERING.md](METERING.md).)
- **No tamper-evident audit ledger (yet).** Admin mutations are logged via
  structured `tracing`; the signed outbox is the durable event history. A
  cryptographic, append-only audit ledger is a future plane concern.
- **No in-path token ceiling.** The meter emit is fail-open and out-of-band, so it
  bounds (does not eliminate) overshoot. A zero-overshoot in-path hard ceiling is
  not built in v1.
- **No SVID/OIDC signature verification.** The `[identity]` header is trusted as
  edge-verified; Vultrino does not validate the token signature itself.
- **No streaming/SSE awareness.** Response bodies are buffered whole; token
  metering is non-streaming-only.
- **No built-in TLS/network exposure hardening.** Serve plaintext HTTP behind a
  TLS-terminating reverse proxy; bind to localhost unless fronted.
- **No keychain / HashiCorp Vault storage backend.** Declared in config, not
  implemented (the file vault is the only backend).
