# HTTP API Reference

The JSON API served by **`vultrino web`**. This page is the task-oriented route
map; the exhaustive, code-verified wire reference (every field, object, enum, and
error code) is [`docs/dev/API.md`](../../dev/API.md) — it wins where the two differ.

## Base URL & transport

- Default base: `http://127.0.0.1:7879` (override with `vultrino web --bind`).
- All JSON routes are under `/api/v1/`.
- Plaintext HTTP — terminate TLS at a reverse proxy for network exposure.

There is **no** transparent forwarding proxy and **no** `X-Vultrino-Credential`
header: a client names a credential alias in the request body and Vultrino runs
the action for it (see `POST /api/v1/execute`). `vultrino serve` does not serve
this API.

## Authentication

```
Authorization: Bearer vk_your_api_key      # an API key
Authorization: Bearer vut_your_use_token   # a scoped use token
```

A `vut_` prefix is a use token; anything else is validated as an API key. Admin
routes require an API key with the `admin` permission (use tokens rejected). The
workload-exchange route instead takes a signed `vwa_` assertion.

Error bodies are `{ "error": "message", "code": "machine_code" }`. Codes by
status: `400 invalid_* / execute_error`; `401 missing_api_key / invalid_api_key /
invalid_token`; `403 permission_denied / not_admin / not_authorized /
token_unusable`; `404 *_not_found`; `409 *_exists / idempotency_*`;
`500 storage_error`.

## Public / authenticated routes

### `GET /api/v1/health` — no auth

```json
{ "status": "ok", "version": "0.1.0" }
```

### `POST /api/v1/execute` — run an action with a credential (API key or use token)

Vultrino injects the secret, runs the action, scrubs the response, returns it.
The body is **flat** (not nested under `params`):

```json
{
  "credential": "github-api",
  "method": "GET",
  "url": "https://api.github.com/user",
  "action": "http.request",
  "headers": { "Accept": "application/json" },
  "body": null,
  "query": {}
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `credential` | yes | Credential alias. |
| `method` | yes | HTTP method. |
| `url` | yes | Target URL (public host — SSRF guard). |
| `action` | no | Canonical `plugin.action` or a govder action label. Omitted → `http.request`. |
| `headers` / `body` / `query` | no | Request headers / JSON body / query params. |

**`200`** → `{ "status", "headers", "body" }` (body is a string, post-scrub).
**`202`** → `{ "outcome": "pending_approval", "approval_id": "appr_…", … }` — the
action did **not** run; poll the approval.
**Errors:** `401` (bad bearer); `403 token_unusable` (revoked/expired/exhausted
token); `400 execute_error` (policy denied, credential not found, SSRF block).

### `GET /api/v1/approvals/{id}` — poll & lazily run an approved action

Authenticate with the **same** bearer that opened the approval. On the first poll
after a human approves, the action runs **at most once** and the result is
returned. `status` is one of `Pending` / `Escalated` / `Approved` / `Denied` /
`Expired`. Errors: `401`; `403 not_authorized` / `token_revoked`;
`404 approval_not_found`.

### `GET /api/v1/credentials` — list (API key, `read`)

```json
{ "credentials": [ { "alias": "github-api", "credential_type": "api_key", "description": "…" } ] }
```

Metadata only — secrets are never returned; filtered to the caller's role scope.
There is no `GET /api/v1/credentials/{alias}` route.

## Admin routes (API key with `admin` only)

Use tokens are rejected. Create/mint routes honor an optional `Idempotency-Key`.
See [Admin API](./admin.md) for bodies and semantics.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` / `PUT` / `DELETE` | `/api/v1/policies[/{id}]` | Manage stored policies (hot-reload). |
| `POST` / `DELETE` | `/api/v1/credentials[/{id}]` | Create (write-only secret) / delete by id. |
| `POST` | `/api/v1/tokens`, `/api/v1/tokens/{id}/revoke` | Mint / revoke use tokens. |
| `POST` / `DELETE` | `/api/v1/roles[/{id}]` | Manage roles. |
| `POST` / `DELETE` | `/api/v1/agents/{label}/halt` | Kill / un-kill an agent principal (V6). |
| `GET` | `/api/v1/sessions`, `/api/v1/metrics` | In-flight sessions; per-process metrics (V12). |
| `GET` / `POST` | `/api/v1/events[?after=N]`, `/api/v1/events/{seq}/replay` | Signed outbox replay + DLQ (V9). |
| `PUT` / `DELETE` | `/api/v1/workload-grants/{agent}` | Author / remove exchange grant templates. |

## Connector surfaces (same server)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/mcp` | `vk_` / `vut_` | Networked MCP transport (JSON-RPC). |
| `POST` | `/llm`, `/llm/{*path}`, `/llm/channels/{channel}[/{*path}]` | `vk_` / `vut_` | Metered LLM proxy (provider gate default-deny; SSE streaming). |
| `POST` | `/api/v1/workload/exchange` | `vwa_` | Trade a signed workload assertion for short-lived use tokens (gated by `VULTRINO_WORKLOAD_EXCHANGE_ENABLED`). |
| `GET` | `/api/v1/runtime/control` | `vut_` | Non-consuming liveness lease; `409 runtime_cancelled` once revoked/expired/halted. |

## HTML admin panel (session auth)

Served alongside the API for human operators: `/login`, `/dashboard` (`/`),
`/credentials`, `/roles`, `/keys`, `/tokens`, `/approvals`, `/audit`. Login is
rate-limited; write forms require a CSRF token.
