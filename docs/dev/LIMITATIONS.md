# Limitations, Non-Goals & Deferred

The honest v1 limits of the shipped binary, stated plainly. None of these are
hidden in the other docs; this collects them. Vultrino is **alpha** (`0.1.0`).

## v1 limitations (real, in the code today)

- **`vultrino serve` is a stub.** It loads storage + plugins, prints "server
  running", and blocks — it does **not** serve the JSON API (the source comment is
  `// TODO: Implement JSON API server`). Use `vultrino web` for the HTTP API.
- **Only the file storage backend is implemented.** `[storage] backend =
  "keychain"` and `"vault"` parse but error at runtime ("not yet implemented").
  The encrypted file vault is the only working backend.
- **Streamed metering has honest residuals.** A `{"stream": true}` LLM call is now
  forwarded as incremental SSE with a streamed token meter (V13b), but: a capability
  whose `(credential, action)` matches an operator `block`/`redact_patterns` egress
  rule, or whose response is compressed, is served **buffered** (the incremental
  scrubber runs only the always-on literal credential-secret scrub, not arbitrary
  whole-body regex/block); a client that sets `stream_options.include_usage:false`,
  or a truncated/halted stream, meters the V13a `api-calls=1` event only (no V13b
  token counts). See [METERING.md](METERING.md).
- **The meter emit is fail-open / out-of-band.** A swallowed `append_event`
  produces no event and **no sequence gap**, so a consumer's gap detector cannot
  see it — the swallowed-append case must be mitigated consumer-side
  (stale-watermark) and reconciled by the authoritative source. An out-of-band
  meter bounds, but does not eliminate, overshoot. (See METERING.md "Honest
  bounds".)
- **No cumulative spend / budget state.** SpendCap is **per-action and stateless**
  only — there is no ledger. Windowed budgets are a metering-plane concern returned
  as a pushed `Deny` policy.
- **Policy propagation across processes is bounded-staleness, not instant.** An
  admin policy push is synchronous on the web process but reaches the MCP server /
  other replicas only on the periodic refresh (`POLICY_REFRESH_SECS = 5`). For an
  immediate kill, revoke the use token (storage-authoritative).
- **Idempotency is at-least-once on a mid-operation crash.** Reserve → operate →
  complete are three atomic writes, not one transaction; a crash between them can
  re-run the operation after the ~60s stale window. Exactly-once would need
  transactional storage.
- **Egress scrubbing is defense-in-depth, not absolute (byte-exact match against
  derived forms).** It scrubs the credential's own secret and the common *single-pass*
  encoder dialects an upstream might ACCIDENTALLY reflect it through: raw, percent-encoding
  (full, both hex cases + form-url `+`-for-space + the common library DEFAULT safe-sets — JS
  `encodeURIComponent`'s `!~*'()` and Python `urllib.parse.quote`'s `/`), JSON string escaping
  (`\"`/`\\`/control), slash-escaping (`\/`), ensure_ascii `\uXXXX` (both hex cases), and
  HTML-safe `</3e/26`, composed where realistic. This catches a buggy upstream echoing the request. It does NOT
  defend against an **adversarially-encoding** upstream: byte-exact matching cannot beat
  arbitrary re-encoding (base64, hashing, chunk-reordering, a novel escape dialect). The
  real protections there are that vultrino never trusts the upstream beyond the injected
  credential, the **buffered-block fallback** for unparseable/compressed bodies, and an
  operator `block`/`redact_patterns` rule. Secrets shorter than `MIN_REDACT_LEN = 5` are
  not byte-scrubbed (use a `block` rule). A structural fix (decode-then-match normalization)
  is a deferred follow-up.
- **Halt abort callbacks are per-process.** The in-flight session registry is
  in-memory per process, so leg 3 of a halt (firing abort callbacks) only preempts
  in-flight work *in the process that received the halt*. The cross-process
  guarantee is "deny the next gated call" (token revoke + kill policy), which is
  immediate.
- **Plugin hot-reload is limited.** The `web` server scans plugins from disk
  **once at startup**; a plugin installed via the CLI while `web` is running is not
  picked up until restart. `vultrino plugin reload` validates a plugin but does not
  hot-swap it into a running server.
- **Inbound workload identity trusts the edge.** Vultrino does **not** verify the
  SVID/OIDC signature; the deployment must terminate mTLS / verify the token and
  pass the verified document in the configured header.
- **In-memory, per-process state resets on restart.** Rate-limit counters, the
  unauthorized-attempt metric, and the in-flight session registry are per-process
  and reset on restart. The durable history is the signed outbox.
- **No built-in TLS / network hardening.** The server speaks plaintext HTTP;
  terminate TLS at a reverse proxy and bind to localhost unless fronted.
- **Audit-to-file is not implemented.** `[logging] audit_file` is parsed but unused;
  the web "audit log" page is a TODO. Admin mutations are logged via structured
  `tracing`; the durable event history is the signed outbox.

## Documented-not-enforced / posture notes

- **Observe mode is a deliberate downgrade.** A tenant in `observe` mode lets
  ordinary policy denials through (logged + emitted as `policy.observed_denial`).
  Security/financial boundaries (halt, cross-tenant isolation, SpendCap/RateLimit)
  still enforce — but operators must understand observe mode is non-blocking for
  ordinary denials.
- **Resume does not re-check tenant isolation or the observe downgrade.**
  Cross-tenant isolation is enforced at open time (a cross-tenant request can't
  create an approval); a credential whose `tenant` tag changes *between* approval
  and resume is not re-validated (a narrow operator-action window — push a
  Deny/halt to stop an in-flight approval, which resume does honor).

## Non-goals (out of scope for this plane)

- **Pricing, rate-cards, ledgers, budgets, reconciliation** — the metering plane's
  job; Vultrino emits raw observations only.
- **Cryptographic, tamper-evident audit proofs** — a proof-plane concern; Vultrino
  emits an HMAC-signed, ordered event stream for a proof plane to elevate.
- **A control/decision policy author UI** — Vultrino enforces and brokers; the
  decision logic (who may do what, budget verdicts) is authored elsewhere and
  pushed through the admin API.
- **Being the four-plane OS.** Vultrino is the enforce plane, published and usable
  standalone. The combined OS is a separate product; Vultrino exposes only the
  contracts an integrator needs.

## Deferred (acknowledged, not yet built)

- Incremental `redact_patterns` regex on the streaming path (arbitrary regex can't
  be applied correctly at a chunk boundary, so such capabilities are served
  buffered — see the streamed-metering residual above).
- GET `/v1/models`, inbound query-string forwarding, and provider selection by the
  request `model` field on the LLM proxy (one key → one provider stays canonical).
- An in-path zero-overshoot hard token ceiling.
- Keychain and HashiCorp Vault storage backends.
- Outbox push fan-out (today a single push subscriber; additional consumers poll).
- A transactional storage layer for exactly-once idempotency.
