# HTTP API & Wire Reference

The wire reference for the **`vultrino web`** server (default `127.0.0.1:7879`).
Every route, auth requirement, request/response shape, object, enum, and error
code here is verified against `src/web/server.rs` (route registration),
`src/web/api.rs` (JSON handlers), `src/web/routes.rs` (HTML panel), and the type
definitions in `src/lib.rs` / `src/auth/` / `src/policy/` / `src/approval/`.

> This is the consolidated route table for the shipped binary. It supersedes the
> older `docs/src/api/http.md` where they differ (that doc lists a header-based
> proxy and `GET /api/v1/credentials/{alias}` routes that the current server does
> not register). The admin surface also has a task-oriented guide at
> `docs/src/api/admin.md`.

## Base URL & transport

- Base: `http://127.0.0.1:7879` (override with `vultrino web --bind`).
- All JSON API routes are under `/api/v1/`.
- The server speaks plaintext HTTP; **terminate TLS at a reverse proxy** for
  network exposure (see [SECURITY.md](SECURITY.md)).

## Authentication

Three auth modes across the surface:

| Surface | Auth | Header |
|---------|------|--------|
| JSON API: execute, approval poll, list credentials | API key **or** use token | `Authorization: Bearer vk_…` or `Authorization: Bearer vut_…` |
| JSON API: admin (policies, tokens, roles, credentials write, halt, sessions, metrics, events, workload grants) | API key with `admin` permission only — **use tokens rejected** | `Authorization: Bearer vk_admin…` |
| Metered LLM proxy (`POST /llm…`) | API key **or** use token (the same bearer used for `/mcp`) | `Authorization: Bearer vk_…` / `vut_…` |
| Workload token exchange (`POST /api/v1/workload/exchange`) | a signed `vwa_` workload assertion — **not** an API key | `Authorization: Bearer vwa_…` |
| Runtime control lease (`GET /api/v1/runtime/control`) | the MCP **use token** minted by an exchange | `Authorization: Bearer vut_…` |
| HTML admin panel (`/login`, `/dashboard`, `/credentials`, …) | session cookie (login form) + CSRF token on writes | — |
| Health, OOB approval decision link | none (the OOB link is authorized by a capability token in the URL) | — |

A bearer prefixed `vut_` is recognized as a **use token**; anything else is
validated as an **API key**. The admin extractor (`AdminApiAuth`) runs **before**
the request body is parsed, so an unauthenticated admin call gets `401`/`403`, not
a `422` body error.

## Public / authenticated JSON routes

### `GET /api/v1/health` — no auth

```json
{ "status": "ok", "version": "0.1.0" }
```

### `POST /api/v1/execute` — the credential broker (API key or use token)

Run an action with a credential; Vultrino injects the secret. The typed endpoint
shapes `http.request` params; for other actions use the MCP server.

Request body (`ExecuteApiRequest`):

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `credential` | string | yes | Credential alias. |
| `method` | string | yes | HTTP method (upper-cased server-side). |
| `url` | string | yes | Target URL (must be a public host — SSRF guard). |
| `action` | string | no | Canonical `plugin.action` or a govder action label. Omitted/blank → `http.request`. |
| `headers` | object | no | Extra request headers. |
| `body` | any | no | Request body (JSON). |
| `query` | object | no | Query params. |

Inbound workload identity (V10/R6): if the `[identity]` resolver is configured and
the request carries its header, the resolved subject refines the principal.

**Response `200` (`ExecuteApiResponse`):**

```json
{ "status": 200, "headers": { "content-type": "application/json" }, "body": "…upstream body…" }
```

`body` is a string (UTF-8 lossy of the upstream bytes, after egress scrub).

**Response `202` — approval required (the action did NOT run):**

```json
{
  "outcome": "pending_approval",
  "approval_id": "appr_…",
  "message": "This action requires human approval before it runs. … Poll GET /api/v1/approvals/{id} …",
  "summary": "http.request on deploy-hook",
  "expires_at": "2026-06-20T11:30:00Z"
}
```

**Errors:** `401 missing_api_key` / `invalid_api_key` / `invalid_token`;
`403 token_unusable` (revoked/expired/exhausted use token);
`400 execute_error` (policy denied, credential not found, SSRF block, plugin error
— the message carries the reason).

### `GET /api/v1/approvals/{id}` — poll & lazily run an approved action

Authenticate with the **same** bearer that opened the approval (a caller may only
poll its own approvals; ownership is checked before any execution). On the first
poll after a human approves, the action runs **at most once** and the result is
returned.

**Response `200`** carries `approval_id`, `status` (`Pending` | `Escalated` |
`Approved` | `Denied` | `Expired`), `summary`, `executed`, and a per-status
`message`. When approved + executed:

```json
{
  "approval_id": "appr_…",
  "status": "Approved",
  "executed": true,
  "message": "Approved and executed.",
  "result": { "status": 200, "body": "…" }
}
```

Dual-control (M-of-N) progress (`required_approvals`, `approvals_received`,
`approvals_remaining`) is included while the request is still open.

**Errors:** `401` (missing/invalid bearer); `403 not_authorized` (different
principal); `403 token_revoked`; `404 approval_not_found`.

### `GET /api/v1/credentials` — list (API key, `read`)

```json
{ "credentials": [ { "alias": "github-api", "credential_type": "api_key", "description": "…" } ] }
```

Filtered to credentials the caller's role scope allows. **Secrets are never
returned.** Requires the `read` permission.

## Admin JSON routes (API key with `admin` only)

All require `Authorization: Bearer vk_…` whose role holds `Permission::Admin`. Use
tokens are rejected with `403 not_admin`. Create/mint routes honor an optional
`Idempotency-Key` header (see below). Status codes: `401` (missing/invalid key),
`403` (valid key without `admin`, or a use token), `400` (invalid body),
`404` (no such resource), `409` (duplicate / in-flight idempotency / body
mismatch), `201`/`200` on success.

### Policies

| Method | Path | Body / result |
|--------|------|---------------|
| `POST` | `/api/v1/policies` | Body `PolicyUpsertRequest`; `201` canonical policy (id generated). |
| `PUT` | `/api/v1/policies/{id}` | Same body; `200` create-or-replace at this id. |
| `DELETE` | `/api/v1/policies/{id}` | `200 {"deleted": id}` / `404 policy_not_found`. |

`PolicyUpsertRequest`:

```json
{
  "name": "gh-allow",
  "credential_pattern": "github-*",
  "principal_pattern": "refund-bot",      // optional (V4)
  "rules": [ { "condition": { "url_match": "https://api.github.com/*" }, "action": "allow" } ],
  "default_action": "deny",               // "allow" | "deny" | "prompt"
  "kill": false                           // optional (V6): authoritative unconditional Deny
}
```

A write hot-reloads the engine on the web process. An invalid `credential_pattern`
glob → `400 invalid_policy`; a misconfigured SpendCap → `400`. A `kill: true`
policy short-circuits ahead of any allow rule. Each write emits a `policy.changed`
event.

### Use tokens

| Method | Path | Body / result |
|--------|------|---------------|
| `POST` | `/api/v1/tokens` | `201 { token, warning, metadata }` — **plaintext shown once**. |
| `POST` | `/api/v1/tokens/{id}/revoke` | `200 { revoked: true, metadata }` / `404 token_not_found`. |

`TokenCreateRequest`:

```json
{
  "name": "deploy-once",
  "credential_scope": "github-*",       // required (use "*" for any)
  "action_scope": "http.request",       // optional glob; omit for any action
  "max_uses": 1,                        // optional; omit for unlimited
  "require_approval": false,
  "expires_in_secs": 600,               // optional (1 .. ~10y)
  "agent_label": "refund-bot",          // optional (V4) — feeds principal_pattern
  "strictness": "direct",               // optional (V8): "direct" | "checkpoint"
  "owner_identity": "user@corp",        // optional (V10)
  "tenant": "team-a"                    // optional (V11)
}
```

`strictness` overrides `max_uses`/`require_approval`: `direct` = single-use +
require_approval + dual_control; `checkpoint` = require_approval (multi-use).

### Roles

| Method | Path | Body / result |
|--------|------|---------------|
| `POST` | `/api/v1/roles` | `{ name, permissions[], credential_scopes?, description? }` → `201` role / `409 role_exists`. |
| `DELETE` | `/api/v1/roles/{id}` | `200 {deleted}` / `404` / `403 predefined_role` / `409 role_in_use`. |

`permissions` are from: `read`, `write`, `update`, `delete`, `execute`, `admin`
(an unknown permission → `400`). The three predefined roles (`admin`,
`read-only`, `executor`) cannot be deleted.

### Credentials (write; secret material is write-only)

| Method | Path | Body / result |
|--------|------|---------------|
| `POST` | `/api/v1/credentials` | `{ alias, metadata?, data }` → `201` credential metadata / `409 credential_exists`. |
| `DELETE` | `/api/v1/credentials/{id}` | `200 {deleted}` / `404`. Propagates an OAuth2/STS downstream revoke first. |

`data` is the tagged `CredentialData` (see [Objects](#objects)). The create
response carries **metadata only** — the secret is never echoed.

### Agent halt / sessions (V6)

| Method | Path | Result |
|--------|------|--------|
| `POST` | `/api/v1/agents/{label}/halt` | `200 HaltOutcome` (revoked tokens, kill-policy id, in-flight sessions, callbacks fired) / `400 halt_failed`. |
| `DELETE` | `/api/v1/agents/{label}/halt` | `200 { agent_label, halt_lifted }`. |
| `GET` | `/api/v1/sessions` | `200 { sessions: [...], process_scope: true }` — in-flight executions in **this** process. |

`label` must be a literal identifier (`[A-Za-z0-9._-]`, ≤128) — globs are rejected.
The halt also revokes every use token matching the target's `agent_label` (or token
id) — the principal-scoped bulk-revocation leg a decision plane's W2 kill drives.

### Workload grant templates (exchange provisioning)

Author/remove the exchange templates the `vwa_` workload exchange mints tokens from.

| Method | Path | Body / result |
|--------|------|---------------|
| `PUT` | `/api/v1/workload-grants/{agent}` | Body `WorkloadGrantTemplate`; `200 {stored, agent_label}`. |
| `DELETE` | `/api/v1/workload-grants/{agent}?tenant=<t>` | `200 {removed, revoked_tokens}`. Idempotent. |

`WorkloadGrantTemplate` binds the identity an exchange assertion must present
(`tenant`, `agent_label`, `issuer`, `subject`, `audience`) to the scopes each minted
token carries: `mcp_credential_scope` / `mcp_action_scope` (+ optional `mcp_max_uses`,
`mcp_require_approval`) for the MCP token, and a `model_channels` map (each a
`{credential_scope, action_scope}`) for the per-channel model tokens. `ttl_secs`
must be in **30..3600** and the `{agent}` path segment must equal `agent_label`
(else `400 invalid_workload_grant`). **`DELETE` revokes every token previously
minted for `(tenant, agent_label)`** and removes the template; it is idempotent so a
decision plane can safely retry deprovision cleanup.

### `GET /api/v1/approvals` — list approvals (product aggregator, A3)

Admin-gated **and** tenant-scoped: the acting key must carry a `tenant` — a
global (untenanted) admin key gets `403 tenant_required` and must use the HTML
admin console instead. Returns the requests visible to the acting key's tenant
(own + untenanted/shared), pending first then most recent, matching the panel's
ordering. Optional `?status=` filter (`pending` | `escalated` | `approved` |
`denied` | `expired`; an unrecognized value matches nothing).

```json
{ "approvals": [ { "id": "appr_…", "status": "pending", … } ], "truncated": false, "returned": 3 }
```

Each item is an `ApprovalSummary` (see [Objects](#objects)). The list is capped
at `MAX_APPROVALS_LIST` (500) after sorting, so the cap keeps the most relevant
rows; `truncated: true` means more exist than were returned (narrow by
`?status=` or page as the API grows pagination).

### Metrics (V12)

`GET /api/v1/metrics` → point-in-time, per-process read-back:

```json
{
  "unauthorized_attempts": 3,
  "tenant_scope": "team-a",
  "approvals": { "total": 12, "by_status": {"Pending": 2, "Approved": 9, "Denied": 1}, "dual_control_awaiting": 1 },
  "approval_latency_secs": { "count": 10, "avg": 45, "p50": 30, "p95": 120, "max": 300 }
}
```

Approval counts are scoped to the acting admin key's tenant (a tenant admin sees
its own + untenanted; a global admin sees all). The durable history is the event
outbox, not this snapshot.

### Event outbox replay (V9)

| Method | Path | Result |
|--------|------|--------|
| `GET` | `/api/v1/events?after=N&limit=M` | Events with `sequence > after`, in order, gap-free. `limit` default 100, capped 1000. |
| `GET` | `/api/v1/events/dead` | The dead-letter queue (up to 1000). |
| `POST` | `/api/v1/events/{sequence}/replay` | Requeue a dead-lettered event; `200 {requeued}` / `404 not_dead_lettered`. |

`/events` response (each event carries the same `delivery_body` envelope a push
delivery uses, plus its `Govder-Signature` when a signing secret is configured):

```json
{
  "events": [
    { "body": { "sequence": 42, "subject": "…", "event": "meter.observed", "payload": {…}, "created_at": "…" },
      "signature": "sha256=…" }
  ],
  "next_cursor": 42
}
```

`next_cursor` is what a consumer persists for the next poll. See
[METERING.md](METERING.md) for the `meter.observed` payloads.

## Idempotency (create/mint admin routes)

Send an `Idempotency-Key` header. A repeat with the **same key + same body**
replays the original `2xx` response (a retried token mint never creates a second
token). While the first call is in flight, a repeat gets `409
idempotency_in_progress`; the same key with a **different** body gets `409
idempotency_key_reused`. Non-success responses release the reservation so the
client can retry. Records are retained 24h.

> **At-least-once on crash.** Reserve → operate → record-completion are three
> separate atomic writes, not one transaction. A crash after the operation
> persists but before completion is recorded means a retry (after the ~60s stale
> window) re-runs the operation. It is exactly-once only absent a mid-op crash.
> A replayed token mint returns metadata + a note, **not** the plaintext (the
> vault never retains it).

### `POST /api/v1/approvals/{id}/decision` — approve or deny over JSON (admin `vk_`)

The JSON counterpart to the HTML console decision (A4), for the per-tenant product
aggregator. Authenticate with an admin `vk_` key. Body: `{ "approve": true|false, "note": "…" }`.

It is **tenant-partitioned**: the approval must be `visible_to_tenant` for the acting
key's tenant or the route returns `404` (never revealing a cross-tenant approval's
existence), and a **global (untenanted) admin key is rejected `403`** before any lookup —
it has no business deciding a specific tenant's approval. The decision goes through the
same atomic `decide_approval` verb the HTML handlers use (dual-control `M`-of-`N` still
applies). See `src/web/api.rs` `api_decide_approval`.

## Delegate approval decisions (plan 031)

A delegate agent decides an approval it was granted authority over via a `vap_`
approval token, minted from a govder `DelegationGrant` — a separate bearer
scheme from the admin `vk_` decision route above.

### `POST /api/v1/approvals/{id}/delegate-decision` — approve or deny via a `vap_` token

Authenticate with `Authorization: Bearer vap_…`. Body:

```json
{ "approve": true, "note": "optional free-text" }
```

The request is evaluated against govder's D3 human floors
(`evaluate_delegate_decision`) before the decision is recorded — vultrino never
decides delegate authority locally. On success the sign-off records
`approver_kind = delegate-agent` and the token's `delegation_grant_ref`; an
approval within the grant's veto window carries `veto_until` (a human may still
veto it before that deadline elapses).

**Response `200`:**

```json
{
  "id": "appr_…",
  "status": "Approved",
  "executed": false,
  "required_approvals": 1,
  "approvals_received": 1,
  "delegation_grant_ref": "grant_…",
  "veto_until": "2026-07-08T00:05:00Z"
}
```

**Errors:** `401 missing_token` / `invalid_token`; `403 not_approval_token`
(bearer isn't `vap_`); `403 token_unusable` (revoked/expired token);
`404 approval_not_found`; `409 approval_not_decidable` (already decided);
`403 tenant_required` / `403 requester_required` (approval/token missing tenant
or the requester's `agent_label`, both fail-closed); `403
delegate_decision_denied` (govder's D3 floors rejected the verdict — e.g. an
irreversible action, which is human-only); `503 govder_not_configured` (govder
integration not set up — see [CONFIGURATION.md](CONFIGURATION.md)); `503
govder_unavailable` / `govder_invalid_response` (govder call failed or returned
an out-of-bounds veto window — fail-closed).

## Workload token exchange (connector M1)

A framework-native runtime (e.g. a LangChain agent) exchanges a signed workload
assertion for the short-lived use tokens it then presents to `/mcp` and `/llm`.
The endpoint is **gated off** unless `VULTRINO_WORKLOAD_EXCHANGE_ENABLED` is set,
and needs a ≥32-byte `VULTRINO_WORKLOAD_ASSERTION_SECRET` configured.

### `POST /api/v1/workload/exchange` — mint runtime tokens (`vwa_` assertion)

Authenticate with `Authorization: Bearer vwa_<payload>.<sig>` — an HMAC-SHA256
`vwa_` assertion whose payload carries `kind` (`oidc`|`spiffe`), `iss`, `sub`,
`aud`, `tenant`, `agent_label`, `jti`, and `exp`. On success mints an MCP token
plus one model token per `model_channels` entry (all with TTL ≤ 3600s); a partial
mint failure revokes every token already minted.

**Response `200`:**

```json
{
  "mcp_token": "vut_…",
  "model_tokens": { "default": "vut_…" },
  "expires_at_unix": 1750000000,
  "metadata": { "mcp": { … }, "models": [ { … } ] }
}
```

**Deny semantics:**

| Status | Code | When |
|--------|------|------|
| `404` | `feature_disabled` | `VULTRINO_WORKLOAD_EXCHANGE_ENABLED` is not set. |
| `503` | `exchange_unconfigured` | Verifier secret absent or < 32 bytes. |
| `401` | `invalid_workload_identity` | Missing Bearer, forged/tampered signature, expired/overlong `exp`, bad `kind`, or empty `jti`. |
| `403` | `grant_not_found` | No template authored for `(tenant, agent_label)`. |
| `403` | `identity_binding_mismatch` | `iss`/`sub`/`aud`/`tenant`/`agent_label` do not match the stored template. |
| `409` | `assertion_replay` | The `jti` was already exchanged (durable, cross-process, fd-locked). |
| `503` | `grant_store_unavailable` / `replay_store_unavailable` | Grant/replay store I/O failure. |

### `GET /api/v1/runtime/control` — non-consuming liveness lease

Authenticate with the exchange's **MCP use token** (`Authorization: Bearer vut_…`).
A framework runtime polls this to learn whether its authority still holds; the poll
does **not** consume a use. `200 {"active": true, "agent_label", "tenant"}` while
live. A revoked/expired token or a halted principal returns `409 runtime_cancelled`
(so W2 revocation/expiry and W3 principal-kill both terminate the lease); a missing
token → `401 missing_runtime_token`, an unknown token → `401 invalid_runtime_token`.

## Metered LLM proxy (connector M1, decision 5)

A harness points its model `base_url` at Vultrino so the provider key never leaves
the vault and token spend is metered (V13). Authenticate with the same `vut_`/`vk_`
bearer used for `/mcp`.

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/llm` | Provider URL is the bound capability's `provider_base` verbatim (no extra path). |
| `POST` | `/llm/{*path}` | The OpenAI-style route the client appends (e.g. `/v1/chat/completions`) is joined onto `provider_base`. |
| `POST` | `/llm/channels/{channel}` / `/llm/channels/{channel}/{*path}` | Explicit model-channel selection (cross-provider fallback). |

The bearer resolves to the principal's bound LLM-proxy capability; the request is
driven through the **same enforced path** as a named tool (default-deny policy,
single-use consumption, egress scrub, V13a/V13b metering). Enforcement runs **above**
the buffered-vs-streaming branch, so a `{"stream": true}` request cannot evade it:

- **Provider gate:** the capability's protocol must be enabled via its
  `VULTRINO_PROVIDER_*_ENABLED` switch (default-deny) — else `403 provider_feature_disabled`.
- **Model allowlist:** when the capability restricts models, the body's `model` must
  be allowed (an allowlisted channel with no parseable `model` fails closed) — else
  `403 permission_error`.
- **Output-token clamp:** under a configured per-call ceiling, `max_tokens` /
  `max_completion_tokens` / `max_output_tokens` are clamped (and set when absent),
  and `n`/`best_of`/legacy prompt-array multiplicity is pinned so the ceiling can't
  be multiplied around.
- **Streaming:** `{"stream": true}` is forwarded incrementally as
  `text/event-stream` when `[llm_proxy] streaming_enabled` is on (default); when off,
  the stream flags are stripped and the turn is served buffered. Bounded by stream
  idle/total timeouts and byte/line caps.

Errors are shaped like an OpenAI API error (`{"error": {"type", "message"}}`):
`401 invalid_request_error` (bad bearer), `403 permission_error` / `provider_feature_disabled`
(denied), `400 invalid_request_error` (non-JSON body or a credential-like query param),
`502 api_error` (upstream failure — detail is logged, never echoed, since the scrub
has not run on an error path).

## Objects & enums

### `CredentialData` (tagged by `type`, `src/lib.rs`)

The `data` field of a credential. Recognized types and their fields:

| `type` | Fields (secrets in **bold**) |
|--------|------------------------------|
| `api_key` | **`key`**, `header_name` (default `Authorization`), `header_prefix` (default `Bearer `) |
| `basic_auth` | `username`, **`password`** |
| `oauth2` | `client_id`, **`client_secret`**, **`refresh_token`?**, **`access_token`?**, `expires_at?`, `token_url`, `scopes[]` |
| `hmac_api_key` | `api_key`, **`api_secret`**, `header_name` (default `X-MBX-APIKEY`), `recv_window` (default 5000) |
| `ecdsa_key` | **`private_key`**, `api_address?`, `testnet` |
| `ssh_password` | `host`, `port` (22), `user`, **`password`** |
| `postgres` | `host`, `port` (5432), `database`, `user`, **`password`**, `sslmode` (default `prefer`) |
| `private_key` | **`key_pem`**, **`passphrase`?** |
| `certificate` | `cert_pem`, **`key_pem`** |
| `custom` | a map of named **secrets** |

### `Permission` (`src/auth/types.rs`)

`read`, `write`, `update`, `delete`, `execute`, `admin`. Predefined roles:
`admin` (all), `read-only` (`read`), `executor` (`read`+`execute`).

### `PolicyAction` / `PolicyDecision`

Config/wire action: `allow` | `deny` | `prompt`. Engine decision:
`Allow` | `Deny(reason)` | `Prompt`.

### `ApprovalStatus`

`Pending`, `Escalated`, `Approved`, `Denied`, `Expired`.

### `ApprovalSummary` (`GET /api/v1/approvals`, `src/web/api.rs`)

The reduced, machine-friendly projection of an approval for the JSON list API
(ISO-8601 timestamps; no internal params/token bookkeeping).

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | `appr_<uuid>`. |
| `status` | string | lowercase `ApprovalStatus`. |
| `summary` | string | Human one-liner describing the gated action. |
| `action` | string | Business-verb label (V8) when present, else the canonical `plugin.action`. |
| `credential` | string | Credential alias the action would use. |
| `agent_label` | string? | Requesting principal's agent label, if any. |
| `requested_by` | string | e.g. `api key "deploy-agent"`. |
| `created_at` / `expires_at` | string | RFC-3339. |
| `required_approvals` / `approvals_received` | u32 | Dual-control (M-of-N) progress. |
| `is_open` | bool | Still pending/escalated and within TTL — a decision can still be recorded. |
| `tenant` | string? | `null` = untenanted (shared, visible to every admin). |
| `approver_kind` | string? | `human` or `delegate-agent` once a terminal decision is recorded. |
| `delegation_grant_ref` | string? | Govder `DelegationGrant` id when decided by a delegate agent. |
| `decided_by` | string? | Channel/identity that decided the approval. |
| `veto_until` | string? | RFC-3339 end of the delegate-decision veto window, when open. |
| `risk_tier` | string | Govder risk tier (`Low`\|`Medium`\|`High`\|`Extreme`) from the same mapping the delegate-decide D3 floor evaluates against. Always emitted. |
| `irreversible` | bool | Trusted irreversibility stamp (D3 floor input). Always emitted. |

### Event types (`src/outbox.rs`)

`approval.requested`, `approval.approved`, `approval.denied`, `approval.escalated`,
`approval.expired`, `agent.halted`, `policy.changed`, `policy.denied`,
`policy.observed_denial`, `credential.rotated`, `credential.revoked`,
`meter.observed`.

## Error response format

JSON API errors are:

```json
{ "error": "Human-readable message", "code": "machine_code" }
```

(some admin handlers nest the same `{code, error}` shape inside the body). Common
codes by status: `400 invalid_*` / `execute_error`; `401 missing_api_key` /
`invalid_api_key` / `invalid_token`; `403 permission_denied` / `not_admin` /
`not_authorized` / `token_unusable` / `token_revoked`; `404 *_not_found`;
`409 *_exists` / `idempotency_in_progress` / `idempotency_key_reused`;
`500 storage_error` / `reload_error`.

## HTML admin panel routes (session auth)

Served alongside the JSON API for human operators: `/login`, `/dashboard` (`/`),
`/credentials[/new][/{id}/delete]`, `/roles[…]`, `/keys[…]`, `/tokens[…]`,
`/approvals[/{id}/approve|deny|decide]`, `/audit`, `/api/stats`, and `/static/*`.
Login is rate-limited and uses constant-time comparison; write forms require a
CSRF token. The `/approvals/{id}/decide` GET+POST pair backs the signed
out-of-band approval link (the GET renders a confirmation; the POST records the
decision, authorized by the capability token in the link).
