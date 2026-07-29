# Architecture

This describes how the shipped `vultrino` binary is structured, which run modes
actually serve what, the request lifecycle through the Policy Enforcement Point,
the core algorithms, and the storage model. Everything here is verified against
`src/`.

## The binary and its run modes

`vultrino` is a single Rust binary (`src/main.rs`, a `clap` CLI). The subcommands
that *run a process* are:

| Subcommand | Default bind | What it actually does |
|------------|--------------|-----------------------|
| `vultrino web` | `127.0.0.1:7879` | The **HTTP server**: admin panel (HTML) **and** the JSON API under `/api/v1/`. This is the process that serves `/api/v1/execute`, the admin/kill/policy surface, and the signed-outbox replay endpoints. It also runs the background outbox-delivery, policy-refresh, and approval-sweep loops. |
| `vultrino mcp` (or `vultrino serve --mcp`) | n/a (stdio) | The **MCP server** for LLM tool integration over stdio. Also runs the policy-refresh, approval-sweep, and outbox-delivery loops. |
| `vultrino serve` (bare, no `--mcp`) | n/a | **Refuses to start.** The former fail-open stub (`run_server` printed "server running" and bound nothing — a footgun: an operator could point agents at a port that silently refused everything) was removed. Bare `serve` now exits immediately with an error naming `serve --mcp` (MCP stdio) and `vultrino web` (JSON API) as the real surfaces; `--bind` is rejected as inapplicable outside `web`. |

> **Accuracy note.** Older guide docs (`docs/src/components/proxy.md`,
> `docs/src/api/http.md`) describe a header-driven proxy on port 7878 served by
> `vultrino serve` and a `GET /api/v1/credentials/{alias}` route. Those do not
> match the current code: bare `serve` now errors loudly (row above) instead of stubbing, and the JSON API is served
> by `vultrino web` on 7879 (routes in `src/web/server.rs::build_router`). This
> dev set documents the shipped routes — see [API.md](API.md).

All other subcommands (`add`, `list`, `key`, `role`, `token`, `approval`,
`plugin`, `meta`, `init`, `request`, `action`) are one-shot CLI operations that
open the encrypted vault directly (they require the storage password) and exit.

## Component model

```
                 ┌──────────────────────────────────────────────┐
   agent /       │                 vultrino web                  │
   integration   │  axum router (src/web/server.rs)              │
   ───────────▶  │   ├─ HTML admin panel (session auth)          │
   Bearer vk_/   │   └─ JSON API /api/v1/* (API-key / use-token) │
   vut_          │            │                                  │
                 │            ▼                                  │
                 │     VultrinoServer  (src/server/mod.rs)       │
                 │     the PEP core: execute_gated → run_action  │
                 │      ├─ AuthManager   (auth/)                 │
                 │      ├─ PolicyEngine  (policy/)               │
                 │      ├─ CredentialResolver (router/)          │
                 │      ├─ PluginRegistry (plugins/)  ──────────▶ external API / DB / host
                 │      ├─ egress scrub  (egress.rs)             │
                 │      └─ signed outbox (outbox.rs)  ──────────▶ consumer (push) / poll
                 │            │                                  │
                 │            ▼                                  │
                 │     StorageBackend (storage/file.rs)          │
                 │     AES-256-GCM encrypted vault on disk       │
                 └──────────────────────────────────────────────┘
```

`VultrinoServer` is the heart: it is shared (as `Arc`) across all API requests in
the `web` process, with plugins loaded once at startup.

## Request lifecycle (the PEP)

The authoritative path is `VultrinoServer::execute_gated` → `run_action` in
`src/server/mod.rs`. For a `POST /api/v1/execute`:

1. **Authenticate** the bearer secret. `vk_…` → API key (via `AuthManager`);
   `vut_…` → use token (looked up by hash). A revoked/expired/exhausted token is
   rejected up front. Local CLI callers have no principal.
2. **Permission + role-scope check** (authenticated requests only): the principal
   must hold `Execute` and its role's `credential_scopes` must cover the
   credential alias.
3. **Resolve the credential** by alias (then by id) via `CredentialResolver`, and
   **resolve the action**: a configured govder *action label* (V8) maps to a
   canonical `plugin.action`; otherwise the presented string is used. Format is
   `plugin.action` (e.g. `http.request`); a bare action defaults to the `http`
   plugin.
4. **Use-token scope enforcement** (if a use token drives the request): the
   token's `credential_scope` glob must allow the credential alias, and its
   `action_scope` (if set) must allow the action — enforced here at the seam where
   the token is spent, not only at the edge.
5. **Tenant isolation (V11):** a principal may use only credentials in its own
   tenant; an untenanted credential is shared. A cross-tenant use is denied
   regardless of the tenant's enforce/observe mode (isolation is not
   observable-away) and emits a `policy.denied` detect event.
6. **Policy evaluation** (`PolicyEngine::evaluate_full`): URL / method / rate /
   principal / spend. The result is `Allow`, `Deny(reason)`, or `Prompt`.
   - `Deny` in **enforce** mode → emit `policy.denied`, return `PolicyDenied`.
   - `Deny` in **observe** mode → log + emit `policy.observed_denial` and **fall
     through to Allow** — *except* a halt/kill, cross-tenant isolation, or a
     SpendCap/RateLimit resource guard, which always enforce.
   - `Prompt` → route into the approval flow.
7. **Approval gating.** An approval is required if any of: the credential is
   flagged `require_approval=true`, policy returned `Prompt`, the use token forces
   it (`require_approval`), or the token is dual-control. When gated, **the action
   does not run**: an `ApprovalRequest` is opened, persisted, announced to
   notifiers, a `approval.requested` event is emitted, and `202`/Pending is
   returned. The use token is **not** consumed yet (reserved for the eventual run).
8. **Run the action** (`run_action`), if not gated:
   - **Preflight (no side effects):** resolve the plugin, validate params. A
     not-loaded plugin is *retryable*; bad params are *terminal*.
   - **Reserve the use token** atomically, fail-closed, immediately before the
     side effect (`storage.consume_use_token`). The use is counted even if the
     downstream call later errors — a token can never drive more than `max_uses`.
   - **Register the in-flight session** (V6), so a halt can see and abort it.
   - **`plugin.execute`** — the point of no return (the external call happens).
   - **Parse token usage from the RAW body** (V13b) *before* scrubbing.
   - **`egress::scrub_response`** — fail-closed on a still-compressed body, scrub
     the credential's own reflected secret, apply operator egress rules.
   - **Persist any credential update** (e.g. OAuth2 token refresh) → emit
     `credential.rotated`.
   - **Emit `meter.observed`** (V13a `api-calls=1`, and V13b token event if a
     usage block was parsed) onto the signed outbox.
   - Return the response (full body to the live caller).

Approval-gated actions run later via the **deferred path** (`resume_approved`),
triggered when the requester polls the approval after a human decides. The resume
re-evaluates policy **read-only** (it re-enforces hard `Deny`/kill gates — a
policy revoked or a kill pushed mid-flight stops the action — but does not
re-charge the rate limiter or re-prompt). Execution is claimed under the storage
lock and fenced by a monotonic `execution_epoch`, so the action runs **at most
once**: two concurrent polls can't double-run, and a worker that crashes
mid-flight is NOT re-run — because its side effect may already have fired, the
stale claim is finalized terminally as `outcome unknown` (the requester
re-approves to retry) rather than re-executed. The terminal write is a
compare-and-set on the epoch (`finalize_execution`), so a recovered-but-superseded
worker can never overwrite the re-taker's outcome.

## Core algorithms

### Policy evaluation (`src/policy/mod.rs`)

`PolicyEngine` holds an ordered `Vec<Policy>` and an atomic `default_deny` flag.
`evaluate_inner`:

1. Filter to policies matching **both** the credential glob (`credential_pattern`)
   **and** the principal (`principal_pattern` matches the principal's id, agent
   label, **or** resolved workload-id; `None` pattern matches everyone; a `Some`
   pattern never matches a principal-less request).
2. **Kill switch short-circuit:** if any matching policy has `kill = true`, return
   `Deny("denied: this principal has been halted")` — evaluated **before** any
   normal rule, so an allow rule ordered first can never let a halted principal
   through.
3. **No match → engine default:** `default_deny` → `Deny("no_policy: …")`;
   otherwise `Allow`.
4. Otherwise walk each matching policy's rules in order; the first matching rule's
   action (`Allow`/`Deny`/`Prompt`) wins; if no rule matches, the policy's
   `default_action` applies.

Conditions: `UrlMatch` (glob; a trailing `*` is a prefix match), `MethodMatch`
(case-insensitive), `RateLimit { max, window_secs }` (in-memory, per-process,
per-credential sliding window), `SpendCap { asset, per_action_max }`
(**per-action, stateless** — no cumulative ledger), `TimeWindow`, `And`/`Or`/`Not`,
`Always`. **SpendCap fails closed:** a missing/unparseable amount or a mismatched
asset → deny. A `SpendCap` must be a rule's top-level condition (not nested) and
its policy must be `default_action = deny` — enforced by `Policy::validate` at load.

> **No cumulative spend state lives in vultrino.** Windowed/budget accounting is
> the metering plane's job (leria); a budget exhaustion comes back as a pushed
> `Deny` policy via the admin API. See [METERING.md](METERING.md).

### Engine policy set = config ∪ stored (`merge_policies`)

The live engine is loaded from the **union** of static `[[policies]]` from
`config.toml` and the admin-API-managed *stored* policies (kept in the vault).
Merge is config-first, then stored, and **never dedups by id** — dropping a stored
`Deny` on an id collision would be fail-open in a default-deny system.

A write through the admin API hot-reloads the engine **synchronously on the web
process**. Other processes sharing the vault (the MCP server, a second replica)
pick it up on a periodic refresh (`POLICY_REFRESH_SECS = 5`). So policy
propagation is **bounded-staleness, not instant**. For an *immediate* kill, revoke
the use token — that is storage-authoritative and re-checked under the lock on
every gated call in every process.

### Use-token consumption (`src/auth/tokens.rs` + storage)

A use token authorizes one kind of action against one credential (or glob),
optionally `max_uses`-bounded and time-boxed. Consumption is **fail-closed /
reserve-on-execute**: the atomic check-and-increment (`consume_use_token`) lives
in the storage backend and runs immediately before `plugin.execute`, so the use
counts even if the downstream call errors. A token presented past `max_uses`,
expiry, or revocation is rejected.

For approval-gated tokens, opening a pending approval *reserves* a future use
(`store_approval_reserving`) bounded by `max_uses`, so a single-use token cannot
spawn an unbounded approval flood; the use is finally consumed only when the
approved action runs.

### Approval lifecycle (`src/approval/`, `src/server/mod.rs`)

States (`ApprovalStatus`): `Pending` → `Escalated` (past the first SLA window) →
`Approved` / `Denied` / `Expired`. An open approval carries a criticality class
(V5) that selects the escalate/expire SLA windows. Two drivers advance the
lifecycle: a **lazy** advance on each agent poll, and a **background sweep**
(`APPROVAL_SWEEP_SECS = 15`) so requests nobody is polling still escalate/expire.
Dual-control (V12) requires *M* distinct approvers (default 2). Decisions are made
in the admin panel, via a signed out-of-band link (Telegram/webhook), or the CLI.
A delegate agent can also decide via a `vap_` token at
`POST /api/v1/approvals/{id}/delegate-decision`, gated by govder-evaluated D3
floors (irreversible => human-only, Medium risk => veto window); the sign-off
records `approver_kind = delegate-agent` plus a `delegation_grant_ref`.
Self-approval (separation of duty) is recorded and, if
`enforce_separation_of_duty`, rejected.

### Halt / kill switch (`halt_agent`, V6)

`POST /api/v1/agents/{label}/halt` runs three legs:

1. **Revoke** the agent's use tokens (matched by agent label or token id) —
   storage-authoritative, immediate across processes.
2. **Install** an authoritative per-agent kill policy (`kill = true`,
   `principal_pattern = label`, fixed id `halt:<label>` so it is idempotent) —
   short-circuits ahead of any allow rule, propagates via the policy refresh.
3. **Fire** registered abort callbacks for the agent's in-flight sessions *in this
   process* (the session registry is per-process), each time-bounded
   (`HALT_CALLBACK_TIMEOUT_SECS = 5`).

The label must be a literal identifier (`[A-Za-z0-9._-]`, ≤128) — never a glob —
so a halt can't accidentally deny a whole fleet. An `agent.halted` event is
emitted. `DELETE …/halt` lifts the kill policy; already-revoked tokens stay
revoked (mint fresh tokens to resume). Leg 1's principal-scoped bulk revocation
(every token matching the target's `agent_label`/id) is the same revoke-by-target
mechanism a decision plane's W2 kill drives; `delete_workload_grant` performs the
analogous revoke-by-`(tenant, agent_label)` when an exchange grant is deprovisioned.

### Metered LLM proxy & streaming (connector M1)

`POST /llm` (`src/web/llm_proxy.rs`) points a harness's OpenAI-compatible model
`base_url` at Vultrino so the provider key stays out of the harness/model request;
the trusted connector injects it only on the bound upstream request, and token spend is
metered (V13). The inbound `vut_`/`vk_` bearer resolves the principal's bound
LLM-proxy capability, and the request is driven through the **same** `execute_gated`
→ `run_action` path as a named tool (default-deny policy, single-use consumption,
egress scrub, V13a/V13b emit). Three enforcement steps run **above** the
buffered-vs-streaming branch, so a `{"stream": true}` body cannot evade any of them:
the provider-protocol gate (`VULTRINO_PROVIDER_*_ENABLED`, default-deny — an unmapped
protocol including `observed-only` fails closed), the per-capability model allowlist
(a channel with no parseable `model` fails closed), and the per-call output-token
clamp (`max_tokens`/`max_completion_tokens`/`max_output_tokens` plus `n`/`best_of`/
prompt-array multiplicity). A streamed turn is then forwarded incrementally as SSE
via `execute_gated_streaming` (which shares the buffered path's decision step),
bounded by the `[llm_proxy]` idle/total timeouts and byte/line caps, and gated by the
`streaming_enabled` kill-switch (when off, the stream flags are stripped and the turn
is served buffered).

### Workload token exchange (connector M1)

`POST /api/v1/workload/exchange` (`src/web/workload_exchange.rs`, gated by
`VULTRINO_WORKLOAD_EXCHANGE_ENABLED`) lets a framework-native runtime trade a signed
`vwa_` assertion — HMAC-SHA256-verified against `VULTRINO_WORKLOAD_ASSERTION_SECRET`
(≥32 bytes) — for short-lived MCP + per-channel model use tokens. It fails closed on
a forged/expired assertion (`401`), a cross-process fd-locked `jti` replay (`409`),
or an identity-binding mismatch against the admin-authored grant template (`403`);
a partial mint failure revokes every token already minted. A runtime then holds a
non-consuming liveness lease via `GET /api/v1/runtime/control`, which returns
`409 runtime_cancelled` once the token is revoked/expired (W2) or the principal is
halted (W3) — the in-process teardown signal for cooperative framework execution.

### Signed event outbox (`src/outbox.rs`, V9)

An append-only event log in the vault with a process-global **monotonic
`sequence`** assigned under the storage lock. Properties:

- **Per-subject ordering:** the delivery worker never delivers a later event for a
  subject while an earlier one for that subject is still undelivered.
- **Gap-free replay:** a consumer replays strictly after its last-seen `sequence`
  via `GET /api/v1/events?after=N` with no gaps/dupes.
- **Dead-letter queue:** an event that fails `max_attempts` times is parked
  (`DeadLettered`) and operator-replayable.
- **Signed:** every push delivery carries `Govder-Signature: sha256=<hex>` =
  HMAC-SHA256(secret, body); the replay endpoint returns the same signature.

The background delivery loop (`OUTBOX_DELIVERY_SECS = 5`) claims and POSTs one
event at a time under a lease, recording success/failure and GC'ing delivered
events past `retention_secs`. Event types include `approval.*`, `agent.halted`,
`policy.changed`, `policy.denied`, `policy.observed_denial`, `credential.rotated`,
`credential.revoked`, and **`meter.observed`** (see [METERING.md](METERING.md)).

## Storage model (`src/storage/file.rs`, `src/crypto/`)

The default backend is an **encrypted file vault**:

- **Cipher:** AES-256-GCM (`crypto/encrypt.rs`), 32-byte key, 12-byte random nonce
  per encryption, nonce stored alongside the ciphertext.
- **Key derivation:** Argon2 (`Argon2::default()`) over the storage password and a
  random 16-byte salt; the salt is stored in the file header (cleartext), the key
  is never stored.
- **On-disk shape:** a JSON file with `version`, `salt`, and an encrypted blob
  holding the cache (credentials, roles, API keys, use tokens, approvals, stored
  policies, and idempotency records; since v7 the signed outbox lives OUTSIDE the
  vault in its own encrypted file).
- **Format version:** `STORAGE_VERSION = 7`. A vault whose recorded version is
  **greater** than the binary understands is **refused** (`check_version`). A
  newer binary reads older vaults (new fields use `#[serde(default)]`), but the
  first write upgrades the on-disk format — after which an older binary sharing the
  same vault is refused. **Upgrade all processes before writing.**
- **Cross-process safety:** every read-modify-write takes an **exclusive
  `fd-lock`** on a lock file, so the `web`, `mcp`, and CLI processes can share one
  vault. Monotonic outbox sequences, token consumption, approval decisions, and
  idempotency reservations are all atomic under this lock.

Other backends (`keychain`, `vault`) are **declared in config but not
implemented** — selecting them returns "not yet implemented". See
[LIMITATIONS.md](LIMITATIONS.md).
