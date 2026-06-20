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
| JSON API: admin (policies, tokens, roles, credentials write, halt, sessions, metrics, events) | API key with `admin` permission only — **use tokens rejected** | `Authorization: Bearer vk_admin…` |
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
