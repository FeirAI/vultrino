# HTTP API (Credential Broker)

Vultrino runs actions with a credential on the caller's behalf and injects the
secret in-path, so the client makes authenticated calls without ever seeing the
credential. There is **no** transparent forwarding proxy and **no** credential
header — a caller names a credential alias and an action, and Vultrino executes
it through the enforced Policy Enforcement Point.

> **This page is a task-oriented overview.** The complete, code-verified route
> table (every path, header, request/response shape, and error code) lives in
> [`docs/dev/API.md`](../../dev/API.md). Where this page and the dev reference
> differ, the dev reference wins.

## The server

The JSON API is served by **`vultrino web`**, the same process that serves the
HTML admin panel:

```bash
export VULTRINO_PASSWORD="your-password"
vultrino web
# Listening on http://127.0.0.1:7879
```

Custom bind address:

```bash
vultrino web --bind 0.0.0.0:8080
```

The server speaks plaintext HTTP; terminate TLS at a reverse proxy for network
exposure. `vultrino serve` does **not** serve this API — see [the CLI
reference](./cli.md#serve).

## Authentication

Every JSON API route under `/api/v1/` (except `/api/v1/health`) authenticates a
bearer token:

```
Authorization: Bearer vk_your_api_key      # an API key
Authorization: Bearer vut_your_use_token   # a single-/multi-use scoped token
```

A `vut_` prefix is recognized as a **use token** (scoped to one credential/action
with optional use limits); anything else is validated as an **API key**. Admin
routes additionally require an API key whose role holds the `admin` permission
(use tokens are rejected).

## Running an action — `POST /api/v1/execute`

The credential broker. Vultrino resolves the credential by alias, injects the
secret, runs the action, scrubs the response, and returns it — the secret never
leaves the vault.

```bash
curl -sX POST http://127.0.0.1:7879/api/v1/execute \
  -H "Authorization: Bearer vk_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
        "credential": "github-api",
        "method": "GET",
        "url": "https://api.github.com/user"
      }'
```

The request body is flat (not nested under `params`):

| Field | Required | Notes |
|-------|----------|-------|
| `credential` | yes | Credential alias. |
| `method` | yes | HTTP method. |
| `url` | yes | Target URL (must be a public host — SSRF guard). |
| `action` | no | Canonical `plugin.action` or a govder action label. Omitted → `http.request`. |
| `headers` | no | Extra request headers. |
| `body` | no | Request body (JSON). |
| `query` | no | Query params. |

**Success (`200`)** returns the upstream status, headers, and body (a string,
after egress scrub):

```json
{ "status": 200, "headers": { "content-type": "application/json" }, "body": "…" }
```

**Approval required (`202`)** — the action did **not** run; poll the returned
`approval_id`:

```json
{
  "outcome": "pending_approval",
  "approval_id": "appr_…",
  "message": "This action requires human approval before it runs. … Poll GET /api/v1/approvals/{id} …",
  "summary": "http.request on deploy-hook",
  "expires_at": "2026-06-20T11:30:00Z"
}
```

Poll `GET /api/v1/approvals/{id}` with the **same** bearer; the action runs at
most once, on the first poll after a human approves.

## Injection by credential type

Vultrino formats the injected auth from the stored credential type — for example
`api_key` becomes `Authorization: Bearer <key>` (or a custom header per the
credential's `header_name`/`header_prefix`), `basic_auth` becomes
`Authorization: Basic <base64(user:pass)>`, and `oauth2` injects (and refreshes)
the access token. The client sends none of these; it only names the alias.

## Listing credentials — `GET /api/v1/credentials`

Metadata only — secrets are never returned. Requires the `read` permission and
is filtered to the caller's role scope.

```json
{ "credentials": [ { "alias": "github-api", "credential_type": "api_key", "description": "…" } ] }
```

There is no `GET /api/v1/credentials/{alias}` route. Credential **writes**
(`POST /api/v1/credentials`, `DELETE /api/v1/credentials/{id}`) are admin-only —
see [Admin API](../api/admin.md).

## Other surfaces on the same server

The `web` process also serves, on the same port:

- **`POST /mcp`** — the networked MCP transport (JSON-RPC), for remote agent
  harnesses. See [MCP Server](./mcp.md).
- **`POST /llm` and `/llm/channels/{channel}/…`** — the metered LLM proxy: point
  a harness's model `base_url` here so the provider key stays in the vault and
  token spend is metered. Providers are default-deny (`VULTRINO_PROVIDER_*_ENABLED`).
  See [the LLM proxy reference](../../dev/API.md#metered-llm-proxy-connector-m1-decision-5).
- **`POST /api/v1/workload/exchange`** and **`GET /api/v1/runtime/control`** — the
  workload-identity token exchange (a signed `vwa_` assertion is traded for
  short-lived use tokens) and its non-consuming liveness lease.

## Error responses

JSON API errors are `{ "error": "message", "code": "machine_code" }`. Common:
`400 execute_error` (policy denied, credential not found, SSRF block, plugin
error), `401 missing_api_key` / `invalid_api_key` / `invalid_token`,
`403 permission_denied` / `not_admin` / `token_unusable`, `404 *_not_found`.

## Security

- **Bind to localhost** and put a TLS-terminating reverse proxy (nginx, Caddy) in
  front for any network exposure.
- **Default-deny policy.** A credential matching no policy is denied unless
  `[enforcement] default_action = "allow"`. See [Policy Configuration](../guides/policies.md).
- **Egress scrub.** Responses are scanned and the credential's own reflected
  secret is redacted before return; `[[egress]]` rules can block or redact
  further. See [Configuration](../getting-started/configuration.md#egress-controls).
