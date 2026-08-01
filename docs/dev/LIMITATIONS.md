# Limitations, Non-Goals & Deferred

The honest v1 limits of the shipped binary, stated plainly. None of these are
hidden in the other docs; this collects them. Vultrino is **alpha** (`0.1.0`).

## v1 limitations (real, in the code today)

- **Only the file storage backend is implemented.** `[storage] backend =
  "keychain"` and `"vault"` parse but error at runtime ("not yet implemented").
  The encrypted file vault is the only working backend.
- **Streamed metering has honest residuals.** A `{"stream": true}` LLM call is now
  forwarded as incremental SSE with a streamed token meter (V13b), but: a capability
  whose `(credential, action)` matches an operator `block`/`redact_patterns` egress
  rule is served **buffered** (the incremental scrubber runs only the always-on
  literal credential-secret scrub, not arbitrary whole-body regex/block); a
  residual-compressed response is withheld at the streamed head before any body
  byte is released; a client that sets `stream_options.include_usage:false`,
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
- **At-most-once execution sacrifices automatic recovery after an ambiguous
  crash.** Reserve → operate → complete are not one external transaction. If a
  worker disappears after claiming an approved action, a stale claim is finalized
  as `outcome unknown` and is never run automatically again. A human must inspect
  the target and explicitly re-approve if retry is appropriate.
- **Legacy approved records without sign-off evidence fail closed on upgrade.**
  Vault load now revalidates approval shapes before exposing any record. A pre-V12
  `Approved` entry with an empty `signoffs` array is indistinguishable from a vault
  edit that forged the status byte, so Vultrino refuses to open that vault rather
  than execute it. Resolve or export such pending legacy approvals with the prior
  binary before upgrading; denied, expired, pending, and evidence-bearing records
  remain readable when their stored lifecycle fields are internally consistent.
- **Vault shape validation proves consistency, not provenance.** The authenticated
  vault ciphertext detects edits by a party without the vault key, and the loader
  plus execution witness reject impossible or unsatisfied approval shapes. A party
  that already controls the vault encryption key can still create a new,
  internally consistent ciphertext containing fabricated sign-off identities;
  preventing that requires independently signed decision evidence and belongs to
  the cross-plane Govder/Averin composition proof.
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
  operator `block`/`redact_patterns` rule. Secrets shorter than `MIN_REDACT_LEN = 5`
  force buffered execution and content-free whole-response withholding. Buffered
  and streamed output receive a final exact-form check after replacement; the
  streamed check includes the preceding released suffix, so neither the redaction
  marker nor a chunk boundary can reconstruct a declared form. A structural fix
  (decode-then-match normalization) is a deferred follow-up.
- **Halt abort callbacks are per-process.** The in-flight session registry is
  in-memory per process, so leg 3 of a halt (firing abort callbacks) only preempts
  in-flight work *in the process that received the halt*. The cross-process
  guarantee is "deny the next gated call" (token revoke + kill policy), which is
  immediate.
- **Plugin hot-reload is limited.** The `web` server scans plugins from disk
  **once at startup**; a plugin installed via the CLI while `web` is running is not
  picked up until restart. `vultrino plugin reload` validates a plugin but does not
  hot-swap it into a running server.
- **WASM ABI v2 has no secret-using host capabilities yet.** An untrusted guest
  receives only a non-secret credential handle (alias + type), and ABI v1 modules
  are rejected at installation/loading. Consequently, external WASM actions that
  need private key or token bytes are unavailable until Vultrino provides a
  narrow host-side operation for that credential type. The repository's former
  PGP module is retained only as an ABI v1 rejection fixture, not a deployable
  plugin.
- **Inbound workload identity trusts the edge.** Vultrino does **not** verify the
  SVID/OIDC signature; the deployment must terminate mTLS / verify the token and
  pass the verified document in the configured header.
- **In-memory, per-process state resets on restart.** Rate-limit counters, the
  unauthorized-attempt metric, and the in-flight session registry are per-process
  and reset on restart. The durable history is the signed outbox. Rate-limit
  counters are keyed per `(rule, credential, principal)` — distinct caps and
  distinct principals each get their own counter (so two agents sharing a
  credential no longer drain one shared budget).
- **Layered `RateLimit` Allow rules are first-match-wins, not conjunctive.** If a
  credential/principal matches more than one Allow-`RateLimit` rule (e.g. a
  per-minute AND a per-day cap), only the first-iterated rule is charged and
  enforced on a given request — the evaluator short-circuits on the first matching
  Allow (`Deny > Prompt > Allow` precedence is preserved). Each cap still has its
  own counter (they don't corrupt each other), but "every layered cap must pass"
  is not enforced for Allow-`RateLimit` rules. Express a hard ceiling as a single
  rule, or as a `Deny` rule (Deny is evaluated first and is authoritative). Making
  layered Allow-`RateLimit` rules conjunctive is a deferred follow-up.
- **No built-in TLS / network hardening.** The server speaks plaintext HTTP;
  terminate TLS at a reverse proxy and bind to localhost unless fronted.
- **Audit-to-file is not implemented.** `[logging] audit_file` is parsed but unused;
  the web "audit log" page is a TODO. Admin mutations are logged via structured
  `tracing`; the durable event history is the signed outbox.
- **Durable-queue compaction and delivered-prefix pruning are best-effort GC that
  run on the periodic tick and yield to in-flight commits.** They wait up to
  `COMMITTING_DRAIN_TIMEOUT` (5s) for the `committing` set to drain, and skip the
  tick if it doesn't. Under sustained append saturation (the committing set never
  fully empties within the window) they skip every tick, so journal segments and
  delivered records' raw params can grow and are retained past the retention
  window until append traffic quiesces. Each skipped tick is logged at `warn`
  (target `averin_seal`) so the condition is observable. This is a deliberate
  bound: the queue never blocks the GC/delivery worker and never risks losing or
  resurrecting an in-flight event — it defers reclamation until a lull. Averin
  durable sealing is default-OFF.

- **Workload-exchange token multiplication is BOUNDED, not eliminated: the honest
  invariant is ≤2 live generations DURING ROTATION, not "exactly one".** Predecessor-retire
  (mint-then-retire, expired-token-skipping, one bulk `locked_mutate` pass) is the primary
  control, and it is deliberately **best effort**: if the retire fails, the exchange still
  returns the credential it already stored, because failing there would hand a retrying
  workload an error for a mint that succeeded — which produces *more* generations, the
  opposite of the goal. The failure is logged at `warn` and backstopped by
  `max_live_generations` (grant-declared; `None` means the default **4**, never
  "unbounded"), which **refuses** the next exchange once that many live, unrevoked,
  unexpired generations exist. That refusal is fail-closed and self-healing: expired
  tokens do not count, so the cap clears within one TTL. Steady state is 1; the default
  leaves headroom for a pod restarting while its predecessor is still unexpired.
  Why the bound exists at all, measured: an unbounded live set grows **linearly in
  uptime** (`revoked_tokens: 38` after 19 minutes at a 60s refresh, ~1,150 tokens/day/agent
  at a realistic L3 TTL), and grant-delete revoke is one full-vault rewrite per token
  (4.6s at 120 tokens, 20.8s at 240) against govder's 10s enforce-client timeout — so past
  roughly 150–200 accumulated tokens the **W2 containment leg stops completing inside its
  own budget.** A sidecar restart cap is an availability guard, never a security bound: the
  multiplier is workload-controlled and unthrottled (120 exchanges in 22.4s measured), and
  jti replay protection forbids replay, not fresh minting.
- **The rate-limit counter now keys on the agent, not the token — which is a change of
  meaning, not just a fix.** It previously charged `principal_id`, which for a use token is
  the token id, so every rotation minted a fresh counter and a compiled cap reset per
  generation (measured: 6 requests in ~1s under a 2-per-hour cap). The doc comment already
  stated per-agent isolation as the intent. It is now keyed on `agent_label` with an id
  fallback, so a rotating workload shares one window. The **per-process, per-replica** bound
  below still applies on top of it.
- **Workload-verifier shape is checked at startup, but signer alignment is still an operator
  obligation.** When workload exchange is enabled, `vultrino web` refuses an absent, blank,
  unreadable, or <32-byte verifier before vault access or listener bind. A comma-separated
  overlap list is accepted (every entry trimmed and ≥32 bytes; a match against any entry
  verifies), validated once, and frozen in `AppState`. This proves the running process has a
  stable verifier snapshot; it cannot prove that the external identity-edge signer holds the
  matching key. A validly shaped but mismatched key therefore starts successfully and rejects
  every assertion with `401 invalid_workload_identity`.
- **Policy-hash presence is checked at startup, but stability across restarts is still an
  operator obligation.** `VULTRINO_POLICY_HASH_SECRET` remains env-only; putting it in
  `config.toml` looks plausible but does nothing because unknown TOML keys are ignored.
  Production `vultrino web` refuses an unset/blank value before touching the vault. It cannot
  prove cross-process key continuity: rotating the value makes every previously authored hash
  mismatch, i.e. false drift. The reusable embedded/test constructor remains permissive and
  emits an empty hash when no key is supplied; it never falls back to a bare digest.
- **There is no per-policy rules read-back.** `GET /api/v1/policies/{id}` does not exist and
  the collection GET returns a reduced DTO with no rules, so an external verifier cannot
  read back what a policy actually enforces. It can only compare `content_hash` (see above)
  and assert on the grant set the decide plane reports. Any claim of the form "we verified
  the compiled rules" is really "we verified the hash and the grant set".

## Documented-not-enforced / posture notes

- **Reversibility truth remains operator authority.** Production `vultrino web`
  forces strict catalog posture: a catalog outage or missing exact declaration is
  refused, a presented label cannot borrow a canonical sibling, a request cannot
  borrow another credential's declaration, and a shared bare canonical verb cannot
  dispatch directly. Thus every production-web direct path has an exact stored
  `reversible` declaration for the executing credential and action. Approval resume
  also refuses if that catalog authority class changed since open. Production strict
  approval-open refuses an inconclusive Govder recipe answer even for a reversible
  action, and resume requires the exact authority class, normalized recipe, and
  Govder risk facts frozen at open. The parser/library default remains
  non-strict for compatibility with older stdio/embedded callers (new `vultrino
  init` files opt in); those callers must set
  `require_declared_capabilities = true` for the same guarantee. Lean and the
  refinement gate prove that the declared class plus recipe authority and their
  open-to-resume continuity are enforced. They cannot establish that an operator
  truthfully labeled the real-world side effect reversible, that Govder's stored
  recipe is organizationally correct, or detect an external semantic change not
  reflected in either authority store; those remain explicit operational assumptions.
- **Observe mode is a deliberate downgrade.** A tenant in `observe` mode lets
  ordinary policy denials through (logged + emitted as `policy.observed_denial`).
  Security/financial boundaries (halt, cross-tenant isolation, SpendCap/RateLimit)
  still enforce — but operators must understand observe mode is non-blocking for
  ordinary denials.
- **An `internal_http` capability's HTTP verb is operator authority, and the agent
  may not send one.** The transport requires `method`, so a capability registered
  through the admin API must make it decidable: exactly one `target.methods` entry,
  or an explicit `target.plugin_params.method` pin (govder writes the pin). Neither,
  both-in-disagreement, or two declared methods is refused at registration
  (`POST`/`PUT /capabilities` 400s), because a verb resolved at call time is a verb
  resolved by the agent. A `tools/call` that carries a `method` argument is refused
  before the use token is consumed — not silently overridden, since executing a
  money action the caller did not ask for is its own defect. This is asymmetric with
  the `http` plugin on purpose: there the caller may still supply `method`/`url`
  within the target scope and policy enforces them independently.
- **A capability's `input_schema` is not checked against the plugin it composes
  into.** vultrino surfaces the operator's schema verbatim in `tools/list`; nothing
  in this plane refuses a schema declaring an argument the backing plugin drops
  (`http`) or refuses (`internal_http`, which deserializes with
  `deny_unknown_fields`). The check exists one plane over, in feir-os's
  `orgpack validate` (`capability-schema-uninvokable`), and only for org packs — a
  capability registered by any other client is unchecked.
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
- GET `/v1/models` and provider selection by the request `model` field on the LLM
  proxy (one key → one provider stays canonical; an explicit `/llm/channels/{channel}`
  route already covers deliberate cross-provider fallback). Inbound provider
  query parameters (e.g. Azure OpenAI's `api-version`) **are** forwarded — appended
  onto the capability-fixed upstream URL, with credential-like keys (`key`,
  `api_key`, `access_token`, `sig`, …) rejected so a query can't smuggle a credential.
- An in-path zero-overshoot hard token ceiling.
- Keychain and HashiCorp Vault storage backends.
- Outbox push fan-out (today a single push subscriber; additional consumers poll).
- A transactional storage layer for exactly-once idempotency.

## Rate-limit windows are per-process and per-replica (vultrino#6)

RateLimit rule state (the fixed-window counter) is in-memory and per-process: it resets on restart and
does NOT coordinate across HA replicas, so a rate cap of N/window effectively becomes N*(replica count)
across a horizontally-scaled deployment. RateLimit is a coarse abuse/burst guard, NOT a hard financial
ceiling. For a hard global cap either run vultrino single-replica, front it with a shared external
rate limiter, or rely on the per-agent BUDGET (leria/govder, which IS global and durable) as the
authoritative spend boundary. (Item-6 vultrino#10 fixed the separate bug where layered/per-principal
rules shared ONE counter — they are now keyed per (rule, alias, principal); this bound is the
remaining per-replica multiplication, which is inherent to in-process counters.)
