# Vultrino — full-repository review (2026-06-09)

**Scope:** design, architecture, code quality, security, tests/CI, plus feature proposals.
**Method:** 12-dimension multi-agent review (crypto/vault, authn/authz, secret-leak sweep, approvals/tokens, storage concurrency, built-in plugins, WASM/installer, web UI, policy/router, MCP server, architecture, code quality, testing/CI) + a completeness critic that opened 3 gap areas (audit logging, CLI argv hygiene, dead TLS config). Every finding was then adversarially verified by 1–2 independent skeptic agents (2 for high severity). Raw output: 103 findings → **98 confirmed, 3 refuted, 2 accepted observations**. Severities below are post-calibration; duplicates found by multiple dimensions are merged.

---

## Implementation status — `expansion-integration.md` V1–V12 (updated 2026-06-19)

**All twelve requirements (V1–V12) are implemented, tested, and documented** on branch `fix/policy-engine`. Each feature was built then **adversarially reviewed per-commit by two independent models — Opus (via the Agent tool) then glm-5.2 (via opencode) — blocking on every finding** until both returned CLEAN; review-fix and review-polish commits follow each feature commit. Whole-repo state: `cargo build` + `cargo clippy --all-targets` clean; **370 tests pass** (264 lib + 57 approval-integration + 23 web-smoke + 14 auth + 12 outbox).

| V | Feature | Key commits |
|---|---------|-------------|
| V1 | Runtime config-write admin API (policies/tokens/roles, idempotent, audited) | `9a69c6f`…`c9f0d50` |
| V2 | Engine-level default-deny mode | `7e7d324`…`4e3ef66` |
| V3+V4 | SpendCap condition + principal/agent dimension | `a10f941`…`609a52e` |
| V5 | Approval SLA/escalation, continuous re-auth, approver identity + SoD | `8143144` + 3 review rounds |
| V6 | Kill/halt + session registry (authoritative `kill` policy) | `c93160c` + 2 review rounds |
| V7 | Held-secret egress + downstream-cred model + OAuth rotation | `842a655`… + round-4 hardening |
| V8 | Action-namespace contract + strictness compilation | `8e01786` + 2 review rounds |
| V9 | Ordered, replayable, signed event outbox (HMAC, DLQ, lease) | `0f9f929` + 2 review rounds |
| V10 | Workload-identity resolution (SPIFFE/OIDC/cloud) + owner binding | `51f27ac` + 2 review rounds |
| V11 | Multi-tenancy / per-team partition (enforce vs observe, isolation) | `ec1158e` + 3 review rounds |
| V12 | Dual-control (M-of-N) approvals + metrics read-back | `303d195` + 2 review rounds |

Notable invariants enforced during review: a V6 halt/kill switch and V11 SpendCap/RateLimit resource guards are **never** observed-away by V11 observe mode; V12 dual-control forces gating even on an Allow and is authoritative over a stale `required_approvals`; V9 delivery is cross-process-exclusive via an atomic lease and gap-free under GC; V10 resolvers trust an already-verified document (verification is integration-time, documented).

---

## Executive summary

The security core that vultrino's pitch rests on — the vault, the cross-process storage layer, and the approval/use-token state machines — is genuinely well built. Verifiers repeatedly failed to break the things that matter most: AES-256-GCM with fresh OsRng nonces and a `SecretBox` master key; every storage mutation as an fd-locked read-modify-write that re-reads authoritative disk state (no lost updates between web and MCP processes); an approval state machine with no path from Denied/Expired to execution; 256-bit tokens stored hash-only and compared in constant time; askama templates with zero `|safe` filters; consistent CSRF + SameSite=Strict on the admin UI; psql/ssh invocations that are structurally injection-proof (no shell, args vector, secrets via env not argv).

The confirmed problems cluster at the **edges of that core**, in four bands:

1. **The agent-facing boundary is leakier than the vault** (most of the high findings): credential read-back via reflector/redirect, an unauthenticated MCP `resources/list`, WASM plugins sharing the MCP server's stdio, revocation that doesn't reach running processes.
2. **The policy engine is the weakest security-critical module**: fail-open by default, a literal-prefix URL matcher that silently breaks interior wildcards, double-charged rate limits, no URL normalization.
3. **Promised-but-missing operational features**: audit logging is advertised in README/docs/UI and entirely unimplemented; `[server.tls]` is parsed but no TLS acceptor exists; `vultrino serve` is a stub that prints success.
4. **No engineering safety net**: zero CI, no dependency auditing, no leak-canary tests for the core invariant, no negative-authz tests.

None of the confirmed findings is a remotely exploitable break of the vault itself; the highest-impact items all require either a credentialed agent (the product's own threat model: a prompt-injected agent) or local/operator preconditions. That is exactly the threat model a credential proxy must win against, so the high/medium list below should be treated as the real roadmap.

---

## What's strong (verified, not assumed)

- **Crypto core** (`src/crypto/encrypt.rs`): RustCrypto AES-256-GCM, fresh 12-byte OsRng nonce per encryption, random per-vault salt, Argon2id KDF, master key in `SecretBox<[u8;32]>` (zeroize-on-drop). No home-rolled crypto.
- **Storage concurrency** (`src/storage/file.rs:258-294`): `locked_mutate` takes an exclusive fd-lock, re-reads on-disk state, applies, atomically renames, then refreshes cache. Verifiers found no lost-update path between web and MCP for any write. `consume_use_token` and `store_approval_reserving` are correct atomic gates.
- **Approvals/use tokens**: decisions funnel through `decide_approval` under the lock; `transition()` enforces Pending-only + TTL; execution requires an atomic claim; double-decide → `AlreadyDecided`; ownership checked before resume. Decision tokens: 32 bytes OsRng, SHA-256 at rest, `subtle` constant-time compare.
- **Secret hygiene at the type level**: `Secret` debug-prints `[REDACTED]`; metadata types (`CredentialMetadata`, `ApiKeyMetadata`, `UseTokenMetadata`) consistently separate listing from secret-bearing types; MCP strips the caller's bearer secret from params before they reach plugins or persisted approvals (`src/mcp/server.rs:589-596`); the Telegram notifier scrubs its bot token from transport errors.
- **Web UI**: askama auto-escaping everywhere (zero `|safe`), per-session CSRF with constant-time compare + regeneration, HttpOnly/SameSite=Strict cookies, RequireAuth on all HTML routes, solid security-header stack, bcrypt cost 12 with username-enumeration defense.
- **Plugin invocation hygiene**: SQL via `-f`/stdin (never `-c` concatenation), argv arrays (no shell), `PGPASSWORD`/`SSHPASS` env (not visible in `ps`), wall-clock timeouts on subprocesses, thorough `is_private_ip` (loopback, RFC1918, link-local, CGNAT, 240/4, IPv4-mapped — in the **http** plugin).
- **Test substance**: 224 real tests, no flaky sleeps; `tests/approval_token_integration.rs` includes genuine multi-threaded race tests (e.g. exactly 1 of 8 concurrent racers wins a max_uses=1 reservation) and cross-process fd-lock tests.
- **PR #5 seams**: `ExecAuth` as single source of truth at the spend point; atomic storage verbs (`consume_use_token`, `decide_approval`, `claim_approval_for_execution`, `store_approval_reserving`) pushing invariants into the lock-holding layer; `evaluate` vs `evaluate_readonly` split verified correct and well-tested.

---

## High-severity findings (6, consolidated)

### H1. API-key revocation never reaches running servers (stale `AuthManager` snapshot)
`src/main.rs:862` (MCP), `src/main.rs:890` (web), `src/storage/file.rs:330`
API keys are validated against an in-memory `AuthManager` built **once at startup** from a storage snapshot. `vultrino auth revoke` writes only to storage (`main.rs:1789`). The web process refreshes only after mutations made through its own UI; the MCP process **never** refreshes. A revoked or role-downgraded key keeps working in every running server until restart. Use tokens don't have this problem — their gate is storage-authoritative. Related (#25): `FileStorage` reads on the API-key execute path serve a never-refreshed process-local cache, and `reload()` failures are swallowed with `let _ =`.
**Fix:** make storage authoritative for API keys exactly like use tokens: at each authz edge `reload()` + `get_api_key_by_hash()` (the hash index already exists), reject if absent/expired. Propagate reload errors at auth edges instead of ignoring them.

### H2. Credential read-back: http plugin returns the full upstream response for an agent-chosen URL
`src/plugins/http.rs:495`, `src/mcp/server.rs` (`http_request`)
`execute_request` returns body+headers verbatim, the agent controls the URL, policy is **allow by default** (`src/policy/mod.rs:138-140`), and a credential has no inherent host binding. An agent holding only execute capability points `http_request` at any header-echoing endpoint (httpbin-style or attacker-hosted) and reads back the injected `Authorization`/API-key header — the core invariant falls. This is the single most direct break of "agents never see secrets."
**Fix (layered):** (a) egress redaction — scan response bytes for the exact injected secret material and replace with `[REDACTED:<alias>]` before returning/persisting (small, catches every reflector); (b) per-credential `allowed_hosts` binding enforced in the plugin independent of policy; (c) default-deny destination policy for execute (see M-group "policy engine").

### H3. Redirects followed with credentials, bypassing SSRF and policy
`src/plugins/http.rs:62`, `src/plugins/hmac.rs:55`
Both clients use reqwest's default `Policy::limited(10)`. SSRF validation and the policy allowlist run only against the **initial** URL; a 3xx from an allowed host redirects the request — with custom credential headers attached (reqwest only strips standard `Authorization`/`Cookie` cross-host, not `X-API-Key`-style headers) — to any host, including private/internal addresses.
**Fix:** `.redirect(Policy::none())` on both clients; surface 3xx to the caller, or implement a custom policy that re-runs SSRF + policy per hop and strips credential headers on host change.

### H4. WASM plugins inherit the host's stdio — which in MCP mode *is* the agent channel
`src/plugins/wasm/runtime.rs:91`
`WasiCtxBuilder::new().inherit_stdio()` wires plugin stdin/stdout/stderr to the process's real fds. The MCP server speaks JSON-RPC over those same fds. A malicious/buggy plugin that receives a decrypted credential can write it straight to stdout — i.e., to the agent — or inject arbitrary JSON-RPC messages into the protocol stream. The rest of the WASI sandbox is tight (no fs, no net, no env), which makes this the one hole.
**Fix:** never inherit stdio; leave streams unset or capture stderr to a buffer for diagnostics.

### H5. WASM execution is unbounded and blocks the async runtime
`src/plugins/wasm/runtime.rs:68` (+ duplicate finding from code-quality)
No `consume_fuel`/epoch interruption, no `ResourceLimiter`, and `execute_action` runs synchronously on the tokio worker. An infinite loop or unbounded allocation in a plugin hangs or OOMs the whole proxy — including the ABI version probe at load time.
**Fix:** epoch interruption with a watchdog (or fuel), `store.limiter()` memory caps, and `spawn_blocking` around execution with a `tokio::time::timeout`.

### H6. X-Forwarded-For trusted unconditionally — login lockout bypass
`src/web/routes.rs:29`
`get_client_ip()` honors `X-Forwarded-For`/`X-Real-IP` from any client and takes the **first** (client-controlled) entry; the login rate limiter keys exclusively on it. An attacker rotates the header per attempt and brute-forces the admin password without ever locking out (and can also lock out arbitrary spoofed IPs). Mitigated today only by the loopback default bind.
**Fix:** honor forwarding headers only when a `trusted_proxies` config lists the direct socket IP, and take the rightmost non-trusted entry; add a global attempt budget as backstop.

---

## Medium-severity findings, by theme

### Policy engine (the weakest security-critical module)
- **Fail-open default** (#56, `src/policy/mod.rs:138`): no matching policy → Allow; matching policies with no terminating rule → Allow. A typo in `credential_pattern` silently removes all gating. **Fix:** configurable default with fail-closed default, or warn loudly on zero-match credentials.
- **Interior wildcards silently broken** (#54, `src/policy/mod.rs:304`): any pattern ending in `*` is matched by *literal prefix* after stripping the `*` — so `https://*.internal.corp/*` becomes the literal prefix `https://*.internal.corp/` and matches nothing (deny rules with subdomain wildcards silently never fire). Glob semantics only apply to patterns *not* ending in `*`. Two divergent copies of `url_matches` exist (`policy/mod.rs:304`, `plugins/mod.rs:357`). **Fix:** parse URL + pattern structurally (host/path via the `url` crate, lowercased host), or always use `glob::Pattern` with `MatchOptions`; delete the duplicate.
- **No URL normalization** (#55): matching runs on the raw string — host case, default ports, percent-encoding, userinfo (`https://user@evil.com`) all defeat pattern intent.
- **Rate limit double-charged** (#57, `src/policy/mod.rs:265` + `src/server/mod.rs:506`): `evaluate()` charges via `check_rate_limit`, then `run_action()` calls `record_request()` which charges **again** — a `max=10` policy allows ~5 requests. (Independently confirmed by hand.) **Fix:** one charging point; make the condition check pure or drop `record_request`.
- **Mutating condition in a pure tree** (#58) and **fixed window keyed only by credential alias, in-memory, reset on restart** (#59): two agents sharing a credential share one bucket; `Not(RateLimit)` charges on evaluation. Fold into the same refactor as #57.

### MCP surface
- **`resources/list` requires no auth at all** (#60, `src/mcp/server.rs:627`): returns every credential's alias+description to any MCP client, bypassing role scoping entirely (tools correctly authenticate per-call; this method forgot). **Fix:** authenticate + filter via `can_access_credential`, or drop the capability until `resources/read` exists.
- **DEBUG logging writes the raw JSON-RPC line** (#15/#74, `src/mcp/server.rs`): includes the agent's `api_key`/use-token plaintext; one `RUST_LOG=debug` away from bearer secrets in logs. **Fix:** redact known secret fields before logging, never log the raw line.
- **Internal error strings verbatim to the model** (#62), **no message-size bound on stdio framing** (#63), **`get_credential_info` discloses internal IDs/all metadata** (#64) — all low-ish hardening items in the same file.

### Approvals
- **Decision token in GET query string** (#9/#16/#18/#48/#81, `src/approval/mod.rs:266`, `src/web/server.rs:160`): the live approve/deny capability appears in reverse-proxy/access logs, axum `TraceLayer` request-URI spans, browser history, and is replayable until TTL. **Fix:** opaque single-use link id (`/approvals/d/<128-bit id>`) with the capability server-side, or exchange-for-cookie + 302.
- **No fencing epoch on execution claims** (#19/#28, `src/storage/file.rs:670`): a >120s-stale claim can be re-taken while the original worker is alive; heartbeat failures are ignored (`let _ =`); the finalizing `update_approval` blindly overwrites. Can double-run a non-idempotent action under pathological timing. **Fix:** epoch counter incremented on claim; heartbeat and finalize CAS on it.
- **Approved-but-unexecuted approvals never expire** (#20): TTL gates only Pending. An approval granted once is executable forever. **Fix:** enforce deadline at the claim gate.
- **Unbounded pending flood for API keys / decided approvals never GC'd** (#21).

### Storage & vault
- **Not crash-durable** (#26, `src/storage/file.rs:237`): no `sync_all()` on the temp file, no parent-dir fsync → power loss can leave a zero-length vault (total credential loss). **Fix:** fsync file + dir; keep a `.bak` generation.
- **Missing vault file silently treated as empty** (#27): runtime deletion of the vault yields a fresh empty state instead of an error — quiet data loss masking.
- **World-readable artifacts** (#1/#30): vault, temp, lock, and `admin.json` written with default umask (0644). **Fix:** `OpenOptionsExt::mode(0o600)` everywhere + `create_dir_all` with 0700.
- **Argon2 params unpinned** (#2): `Argon2::default()` — a crate upgrade silently changes KDF params and bricks existing vaults (no params persisted in the header). **Fix:** pin explicit params, store them in the vault header, derive accordingly.
- **`Secret` serializes plaintext globally** (#6/#17): exists for vault serialization but is reachable from any serde path (e.g. `ExecuteResponse.updated_credential`). **Fix:** redact by default; serialize real values only via a private storage-layer wrapper.
- **`VULTRINO_PASSWORD` inherited by subprocesses** (#0): notably `cargo build` of third-party plugin code during `vultrino plugin install` (build.rs = native code + the master password + the vault file). **Fix:** `remove_var` after read; `env_clear()` + allowlist on every spawned `Command`.

### Plugin supply chain & built-ins
- **Installer: zero integrity verification** (#41): git/tar.gz sources fetched, built, and loaded with no checksum, signature, or commit pinning. **Plus** plaintext `http://` accepted (#43), `cargo build` executes untrusted build scripts (#42), tar symlink handling pulls external content into the plugin dir (#44).
- **Loader: no integrity pin at load** (#45): anything in the plugins dir with a `plugin.toml` + `.wasm` loads (enabled defaults true when metadata is missing); the `.wasm` is re-read at load with nothing tying it to install time. A local writer to `~/.vultrino/plugins` gets plaintext credentials handed to its code. **Fix:** store a digest at install, re-verify on every load.
- **HMAC plugin's SSRF check misses IPv4-mapped IPv6** (#33): `https://[::ffff:127.0.0.1]/` reaches localhost (the http plugin's check handles this; the hmac copy doesn't — another argument for deduplication).
- **SSRF DNS check is TOCTOU** (#34): validated via one resolution, reqwest re-resolves unpinned (the code comments acknowledge it). **Fix:** pin via `Client::resolve()` to the validated IP.
- **No timeouts / response caps on any reqwest client** (#35/#75): http, hmac, Telegram, webhook clients have no timeout; bodies buffered unbounded; notifier dispatch is awaited inline in the execute path — a hung webhook blocks the agent's call indefinitely.
- **ECDSA recovery id hardcoded to 27** (#36): correctness bug — produced signatures have wrong `v` for half of all keys/messages; use `sign_prehash_recoverable`.
- **SSH host-key `accept-new` default, `no` allowed** (#37): first-connect MITM captures the SSH password (made tractable by `sshpass`).
- **Postgres TLS mode passed through without cert verification enforcement** (#38).

### Configuration theater & web ops (gap-finder area)
- **`[server.tls]` is dead config** (#99): cert/key paths parsed, never opened; no TLS stack exists; meanwhile docs tell users to set `public_base_url` to HTTPS for decision links. Worse (#100): setting `tls` (or `mode="server"`) flips the session cookie to `Secure` on a plaintext server — **admin login silently breaks** (browser never returns the cookie). And (#101) HSTS is emitted over plain HTTP. **Fix:** implement TLS via `axum-server`/rustls or fail fast on `tls` config; align cookie/HSTS behavior with actual transport.
- **Corrupt default config silently replaced with defaults** (#72, `main.rs:527-536`): `Config::load(...).unwrap_or_default()` — a one-character TOML typo silently drops every policy (and the engine is fail-open, see #56) and disables approvals. Also `config.server.bind` is dead (CLI flag always wins). **Fix:** hard-fail on parse errors of an existing config file.
- **No graceful shutdown** (#102); **login rate-limiter maps never cleaned** (#53); **CSP allows `unsafe-inline` scripts** (#49) while htmx is loaded from unpkg without SRI and currently blocked by that same CSP (#50 — dead weight); **token-display pages lack `Cache-Control: no-store`** (#52); **4-char admin password minimum** (#11).

### Audit logging — advertised, entirely absent (gap-finder area)
README line 35 promises "Audit Logging — Track all credential usage"; the `/audit` page is routed and stubbed (`routes.rs:882: // TODO`), the dashboard hardcodes `recent_requests: 0`, `[logging].audit_file` is parsed and never consumed (#90–94). **No execute path persists any record**; even the transient tracing line omits the acting principal. For this product this is the single most important missing feature (see Features F1).

### CLI secret hygiene (gap-finder area)
Every credential secret is accepted as a plaintext argv flag (`--key`, `--password`, `--client-secret`, `--refresh-token`, `--hmac-secret`, `--private-key`, `--ssh-password`, `--pg-password`) — visible in `ps`/`/proc/<pid>/cmdline`/shell history **on exactly the host the agent shares** (#95). The `api_key` type has no secure input path at all (#96), the agent bearer key is argv-only too (#98), and the docs teach the insecure form everywhere, including the security-best-practices section (#97). **Fix:** prompt/stdin-only for secrets (`--password-stdin` pattern), `VULTRINO_API_KEY` env for the agent key, docs sweep.

---

## Architecture assessment

- **`src/main.rs` is a 2,556-line monolith** (#66): clap definitions + dispatch + business logic (credential construction duplicated with the web UI, an ~80-line approval wait/resume state machine, password/init logic) in one untestable file (zero tests, confirmed #88). **Recommendation:** `src/cli/` with one module per command family, delegating to library functions; keep `main.rs` to arg parsing + dispatch.
- **Secret-to-principal resolution exists in 4 hand-rolled copies** (#22/#67/#80) across MCP and HTTP (and read-vs-execute variants); per-status approval guidance text is duplicated across **six** surfaces (#68) — a `web/api.rs` comment even admits the sync is manual. **Recommendation:** one `resolve_principal(secret, intent) -> ExecAuth` in `auth`, one `ApprovalGuidance::for_status()` in `approval`, consumed by all transports.
- **`VultrinoServer` carries dead auth state** (#69): its `AuthManager` and `require_auth` are never used; real auth happens at transport edges with **three** divergent `AuthManager` instances. The latent trap: implementing the `serve` stub (`main.rs:844`, #78 — it currently prints success and listens on nothing) "naturally" via `server.execute()` would run unauthenticated. **Recommendation:** delete the dead fields or make `execute_gated` consult them; unify on one auth path.
- **`StorageBackend` default impls degrade silently** (#70): safety-critical verbs (`store_approval_reserving`, `claim_approval_for_execution`, `get_use_token_by_hash`) have runtime defaults — mostly fail-closed, but a partially-implemented future backend that forgets `store_approval_reserving` silently reintroduces the TOCTOU PR #5 closed. **Recommendation:** split a required `AtomicStorageBackend` trait (compile-time enforcement) or remove the defaults.
- **Error taxonomy collapses at the edges** (#71): web API maps every `VultrinoError` to 400 `execute_error` (storage/IO text reaches response bodies); `RunError::terminal` vs `::committed` are bit-identical, erasing the "may have side-effected" distinction the type was built to carry.
- **Dependency hygiene** (#73): `askama_axum` is pinned against axum-0.7-era core — unusable with axum 0.8, which is why all 20+ render sites are manual `Html(template.render()...)`; `bytes`, `once_cell`, `regex`, `zeroize` are unused; `tower` belongs in dev-deps; wasmtime is compiled unconditionally (feature-gate it for binary size/build time).

---

## Testing & CI

Confirmed gaps (all verified empirically — e.g. the GitHub API shows zero workflows and no branch protection on `main`):
- **No CI at all** (#82): 224 tests run only voluntarily; a PR regressing the core invariant merges with nothing in the way. **No cargo-deny/cargo-audit** (#83) despite wasmtime/reqwest/axum/crypto in the tree.
- **The MCP server — the primary agent surface — has one vacuous test** (#84) that asserts two JSON literals are objects.
- **Zero leak-canary tests for the core invariant** (#85): nothing asserts a secret does **not** appear in any response/error/log; a regression of `Secret`'s redaction or a handler serializing `Credential` would pass the full suite.
- **No negative-authz HTTP tests** (#87): per-handler `RequireAuth` extractor pattern means one dropped extractor ships silently; CSRF rejection path untested.
- **WASM ABI unit test endorses helpers whose bit-packing contradicts the real runtime** (#86) — a latent trap for refactors.
- **No fuzz/property tests** on `url_matches`, `EncryptedData::decode`, JSON-RPC framing, manifest parsing (#89).

**Recommended CI (1 day):** GitHub Actions with fmt + clippy `-D warnings` + test + `cargo-deny` (advisories/licenses) + branch protection. Highest-value new tests, in order: leak-canary suite (grep-style negative assertions over every response/error path with a planted high-entropy secret), MCP `handle_message` table tests (auth required per tool, error shapes, no secret echo), router-level negative-authz oneshot tests, policy-matcher property tests.

---

## Refuted by adversarial verification (for the record)

- **"ECDSA `sign` is a blind signing oracle"** — k256's high-level `Signer::sign` SHA-256-hashes input before signing (confirmed empirically against the pinned crate), so a precomputed tx-hash cannot be signed directly; reachable paths add further gates. (The recovery-id bug #36 stands.)
- **"Session fixation — no `cycle_id()` on login"** (×2) — tower-sessions 0.14 `MemoryStore` discards unknown cookie IDs server-side, so a planted ID never becomes an authenticated session.

Plus 2 accepted observations: committed-but-failed execution burns a use (correct fail-closed design, #23); plugin-relayed content reaching the model is inherent but should be documented as a prompt-injection surface (#65).

---

## Prioritized fix roadmap

**PR A — agent-boundary hardening (the highs; ~2-3 days)**
Redirects off + per-hop revalidation (H3) · egress secret redaction + `allowed_hosts` (H2) · authenticate `resources/list` (M/#60) · WASM: drop `inherit_stdio`, add epoch/memory limits + `spawn_blocking` (H4/H5) · storage-authoritative API-key validation (H1) · trusted-proxy gating for XFF (H6) · redact MCP debug logging (#15) · timeouts + response caps on all reqwest clients (#35).

**PR B — policy engine correctness (~2 days)**
Structural URL matching with normalization (#54/#55, dedupe the two `url_matches`) · fail-closed default or zero-match warnings (#56) · single rate-limit charge point (#57/#58) · per-principal keying + persistence consideration (#59) · property tests over the matcher (#89).

**PR C — vault & storage durability (~1-2 days)**
fsync + `.bak` (#26) · missing-vault guard (#27) · 0600/0700 modes (#1/#30/#11) · pinned+persisted Argon2 params (#2) · `Secret` redacted-by-default serialization (#6) · env-var scrubbing + `env_clear` on Commands (#0) · approved-approval deadline (#20) + claim fencing epoch (#19).

**PR D — supply chain (~2 days)**
Installer digest/signature verification + commit pinning + https-only (#41/#43) · loader re-verification against stored digest (#45) · tar/copy hardening (#44) · document that `plugin install` builds native code (#42).

**PR E — ops & truthfulness (~3-4 days)**
Audit ledger at the `run_action` chokepoint + `/audit` page + CLI tail/verify (#90–94, F1) · implement TLS or fail fast on dead config; fix Secure-cookie/HSTS mismatch (#99–101) · hard-fail corrupt config (#72) · graceful shutdown (#102) · secrets-via-stdin CLI + `VULTRINO_API_KEY` env + docs sweep (#95–98) · implement or remove `vultrino serve` (#78).

**PR F — engineering safety net (~1 day + ongoing)**
CI (fmt/clippy/test/deny) + branch protection (#82/#83) · leak-canary suite (#85) · MCP handler tests (#84) · negative-authz router tests (#87) · CLI extraction from main.rs as refactors allow (#66, #22/#67/#68).

---

## Feature proposals (from a 3-lens product panel, grounded in the code)

**Top recommendations (do these first):**

| # | Feature | Value/Effort | Why |
|---|---------|--------------|-----|
| F1 | **Tamper-evident audit ledger** — hash-chained JSONL at the `run_action` chokepoint, `vultrino audit tail/verify`, wire the stubbed `/audit` page & dashboard | high/medium | Closes the advertised-but-missing flagship gap (#90); prerequisite for anomaly detection; enterprise table stakes |
| F2 | **Egress secret redaction** — scrub injected secret material from plugin responses before they reach the agent | high/**small** | Directly mitigates H2 (read-back); cheap, sits at one seam |
| F3 | **`vultrino connect claude-code`** — one command: scoped role+key, MCP registration, `VULTRINO_API_KEY` env-bound principal so the key leaves tool arguments (and the agent's context) | high/medium | Fixes both onboarding DX and a real invariant gap — today the durable `vk_` key lives in every tool call in the conversation |
| F4 | **OAuth2 authorization-code + device-flow brokering** — vultrino runs the connect dance; agent never sees refresh tokens | high/medium | Extends the proven OAuth2 refresh machinery in `http.rs`; unlocks Google/GitHub/Microsoft APIs for agents safely |
| F5 | **Agent-mintable scoped sub-tokens** — `mint_use_token` MCP tool capped by the parent's role (TTL/uses/scope) | high/medium | Natural extension of the use-token system; enables sub-agent delegation patterns |
| F6 | **`describe_capabilities` discovery tool** — per-principal: accessible credentials, allowed actions, policy preview, approval-gating flags | high/medium | Agents currently discover capabilities by trial-and-error; also fixes the broken-by-half resources story (`resources/read` is unrouted, #60) |

**Also strong (enterprise lens):** envelope encryption with OS-keychain/TPM-wrapped DEK (the `keyring` dep is already commented in Cargo.toml; kills the env-var password story, #0) · zero-downtime credential rotation with dual-validity (alias-stable swap; the OAuth2 refresh path proves in-place update is safe) · M-of-N dual-control approvals + break-glass (per-channel decision tokens; `decide_approval` is already an atomic CAS) · behavioral anomaly detection routing into the existing approval flow (`PolicyCondition::Anomaly` → Prompt) · SIEM event sink (model on `ApprovalNotifier`) · native TLS/mTLS with cert-bound API keys (#99 makes this urgent anyway).

**Also strong (ecosystem lens):** signed release pipeline + Dockerfile + Homebrew/crates.io (docs already reference a ghcr.io image that doesn't exist) · GitHub App installation-token minting + AWS SigV4 plugins (top-2 real agent targets; both need request-time derivation that static credentials can't express) · plugin SDK crate + `cargo generate` template + installer signature verification (pairs with PR D) · secret import bridges (1Password/Vault/k8s/.env) and a `vultrino scan` secrets-sprawl scanner → import funnel · per-principal budgets/spend limits (generalizes the atomic use-token seam) · readable MCP resources (implement `resources/read`, scoped) · browser-session credential injection via CDP for computer-use agents (large, but the biggest unserved agent modality).

---

*Generated by a multi-agent adversarial review (138 + 42 agents, ~5.6M tokens). Full machine-readable findings: `/tmp/vultrino_findings_final.json`; ideas: `/tmp/vultrino_ideas.json`.*
