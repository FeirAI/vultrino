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
vault password's secrecy, TLS termination at the edge, the trusted built-in
connector implementations, and covert channels controlled by an authorized
upstream.

## Invariants Vultrino upholds

1. **Raw credential material is confined from caller-visible sinks.** Secrets are
   stored encrypted, injected server-side, and never returned by credential-read
   endpoints. A credential's declared raw/derived forms are scrubbed from response
   bodies and headers; responses that cannot be safely scrubbed (including a
   still-compressed body or a secret shorter than five bytes) are **withheld
   entirely**. The fail-closed buffered value has no body or headers, because no
   fixed diagnostic can exclude every possible non-empty credential string.
   Connector-provided post-dispatch error detail is also withheld from live and
   persisted approval responses.
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
   approved action runs **at most once** across all polls: execution is claimed
   under the lock and fenced by a monotonic `execution_epoch`, and a worker that
   crashes mid-flight is finalized terminally as `outcome unknown` (re-approve to
   retry) rather than re-run — the crash cannot cause a duplicate side effect.
   A canonical plugin verb shared by configured business labels also cannot erase
   which Govder recipe applies: without an exact canonical rule, approval open
   fails closed before the numeric fallback.
6. **Security/financial boundaries hold even in observe mode.** Cross-tenant
   isolation, halts, and SpendCap/RateLimit resource guards always enforce; only
   ordinary policy denials are observable-away.
7. **Events are signed and ordered.** Every outbox delivery (and replay) carries
   `Govder-Signature: sha256=HMAC-SHA256(secret, body)`; the sequence is monotonic
   and gap-free, so a consumer detects a dropped *delivery*.
8. **The admin surface is API-key-only.** Use tokens can never reach the admin API
   (`403 not_admin`), and admin authentication is checked before the request body
   is parsed.
9. **A tenant-scoped admin key is partitioned; it can never act on another tenant.**
   An admin key is either **global** (operator/root, `tenant == None`) or
   **tenant-scoped** (`tenant == Some(t)`; e.g. a product aggregator like
   feir-os). A tenant-scoped key is confined to its own tenant on every admin
   surface:
   - **Operator-only surfaces** — resources with no tenant field (policy CRUD,
     role CRUD, the shared signed event outbox: list/dead-letters/replay) and the
     label-addressed kill switch (agent `halt`/`unhalt`) — reject a tenant-scoped
     key with `403 operator_key_required`. They require the global operator key.
   - **Tenant-scoped surfaces** — resources that carry a tenant (use-token revoke,
     approval-token revoke, credential create/delete, and token/credential mint) —
     let a tenant-scoped key self-serve its OWN tenant (or an untenanted/shared
     resource) but return `404` for a cross-tenant id (no existence oracle) and
     `403 cross_tenant_denied` when minting for a different tenant. The tenant is
     re-checked **under the storage lock** (no read-then-act TOCTOU). A use token's
     `tenant` resolves to that tenant's principal at execution, so cross-tenant mint
     is blocked to prevent cross-tenant credential access.
   - The **global operator key is unrestricted** (govder's cross-plane kill/revoke
     and the operator console depend on this). The tenant partition is the same
     `tenant_may_act` primitive the approvals JSON API uses.

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
- **Web admin login:** username + bcrypt password hash (`admin.json`, stored
  `0600`), constant-time comparison, username-enumeration-resistant, rate-limited
  per client IP, CSRF-protected write forms, session cookies. The throttle keys on
  the **socket peer** by default; it honors `X-Forwarded-For`/`X-Real-IP` (rightmost
  hop) **only** when `VULTRINO_TRUST_FORWARDED_FOR=1` — because those headers are
  client-controlled, trusting them without a trusted proxy in front lets an attacker
  mint a fresh bucket per request. In server mode without that flag, all logins
  behind a proxy share one bucket (a startup warning is emitted).
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
- **Workload token exchange (`vwa_` assertions):** the optional exchange endpoint
  (`POST /api/v1/workload/exchange`, gated off by default behind
  `VULTRINO_WORKLOAD_EXCHANGE_ENABLED`) authenticates a framework runtime by an
  HMAC-SHA256 assertion signed with `VULTRINO_WORKLOAD_ASSERTION_SECRET` (≥32
  bytes per verifier). When enabled, the production `web` command validates the
  verifier before vault access or listener bind and carries that exact snapshot
  into request state; it does not reread the environment or file per request. A
  forged/tampered or expired assertion is rejected (`401 invalid_workload_identity`);
  a replayed `jti` is rejected (`409 assertion_replay`, durable + fd-locked so the
  guard holds across processes); the assertion's issuer/subject/audience/tenant/agent
  must match the admin-authored grant template or the exchange is denied
  (`403 identity_binding_mismatch`). A successful exchange mints only short-lived
  (TTL ≤ 3600s) MCP + per-channel model **use tokens** — never an admin credential —
  and a partial mint failure revokes every token already minted for that exchange.
  Startup establishes presence and shape, not that the external signer has the
  matching key; deployment alignment remains an operator responsibility.

## Trust boundaries

| Boundary | Trusted? | Notes |
|----------|----------|-------|
| The calling agent | **No** | The primary adversary. Sees only aliases + scrubbed responses. |
| The bearer token presented | Authenticated | `vk_`/`vut_` validated by hash; scope enforced server-side. |
| The `[identity]` header | **Trusted (edge-verified)** | The deployment MUST terminate mTLS / verify the token and pass the verified document. Vultrino does not itself verify the SVID/OIDC signature. |
| The host / disk / vault password | Trusted | Vault confidentiality rests on the password's secrecy and OS file protection. |
| Built-in Rust plugins | **Trusted declassification boundary** | They receive `CredentialData` to inject/use it. Review them as part of Vultrino's TCB. |
| Installed WASM plugins | **No** | ABI v2 receives only alias + credential type, never `CredentialData`; ABI v1 is rejected. No secret-using host capability exists yet. |
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

Two layers at the execution seam, obtained through the private
`egress::confine_response` constructor before a buffered body reaches the caller:

1. **Always-on secret scrubbing.** The credential's own injected secret — and its
   percent-encoded and JSON-escaped forms, and derived forms like the Basic-auth
   base64 — is replaced with the constant `[REDACTED]` marker in the body and headers.
   Framing headers (`Content-Length`/`Transfer-Encoding`) a redaction invalidates
   are stripped so a stale length can't leak the original.
2. **Operator egress classification.** `[[egress]]` rules `block` a secret-bearing
   endpoint's body+headers entirely, or `redact_patterns` extra regexes.

Post-dispatch plugin failures cross the same finite secret-form boundary. A safe
operator-authored refusal remains visible; a diagnostic containing any declared
raw/derived credential form—or paired with an unredactable short secret—is
replaced wholesale by a constant error before it can reach the caller or an
approval record.

**Honest bounds (defense-in-depth, not absolute):** scrubbing operates on the
plaintext response. An endpoint that *transforms* the secret (re-encodes,
hashes, gzips a reflected copy beyond what the client decompressed) can still leak
it — use a `block` rule for endpoints you don't trust. Secrets shorter than
`MIN_REDACT_LEN = 5` are not byte-scrubbed (they'd over-redact); any execution
using one is forced through the buffered path and its entire response is withheld.
A still-compressed body is also withheld entirely (fail-closed).

**Streaming (SSE).** A streamed LLM-proxy turn (`{"stream": true}`) is scrubbed
**incrementally** — each raw SSE chunk is passed through the always-on
credential-secret scrub before it reaches the caller, with a carry-buffer sized off
the longest secret form so a secret split across chunk boundaries is still caught.
Each scrubbed output candidate, response header set, and terminal frame then passes
a second declared-form postcondition. That check includes the last
`max_form_len - 1` released bytes, so neither a replacement marker nor a transport
boundary can reconstruct a credential form after the raw input was scrubbed; an
unsafe candidate is withheld before release.
The stricter whole-body controls (an operator `block`/`redact_patterns` rule, or a
compressed body) cannot be honored at a chunk boundary, so a capability that needs
them is served **buffered** instead. An operator can force buffered service for
every turn with `[llm_proxy] streaming_enabled = false`. See
[METERING.md](METERING.md) for the streamed token-metering residuals.

## Defaults that fail safe

- Engine default `deny`; SpendCap unparseable → deny; cross-tenant + untenanted
  principal → enforce; a malformed egress/policy/identity glob is a hard config
  error (no silent degrade to never-matching).
- An outbox push with no URL or no signing secret is a hard config error
  (an unsigned/undeliverable outbox is rejected).
- A halt label must be a literal id (no glob), so a halt can't deny a fleet.
- The metered LLM proxy's provider-protocol gate is **default-deny**: each of the
  seven provider families (openai, nvidia, azure-openai, anthropic-messages,
  bedrock, gemini, vertex-ai) requires its explicit `VULTRINO_PROVIDER_*_ENABLED`
  switch, and any unmapped protocol — including the validated `observed-only`
  telemetry protocol — fails closed, so no credential-injected proxy traffic
  flows for a protocol an operator hasn't turned on.
- A browser-originated MCP request's `Origin` must match the request `Host` or an
  entry in `VULTRINO_MCP_ALLOWED_ORIGINS`, else the MCP transport rejects it (`403`).

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
  edge-verified; Vultrino does not validate the token signature itself. (The
  workload-exchange `vwa_` assertion, by contrast, **is** cryptographically verified
  by Vultrino against `VULTRINO_WORKLOAD_ASSERTION_SECRET` — see above.)
- **No built-in TLS/network exposure hardening.** Serve plaintext HTTP behind a
  TLS-terminating reverse proxy; bind to localhost unless fronted.
- **No keychain / HashiCorp Vault storage backend.** Declared in config, not
  implemented (the file vault is the only backend).
