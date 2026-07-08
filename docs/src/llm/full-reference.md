# Vultrino Complete LLM Reference

This document contains everything an LLM needs to know to use Vultrino effectively.

---

## What is Vultrino?

Vultrino is a credential proxy for the AI era. It allows AI agents and applications to make authenticated API requests without ever seeing the actual credentials.

**Core Concept:** You reference credentials by *alias* (e.g., "github-api"), and Vultrino automatically injects the real credential into your request.

---

## MCP Tools

### list_credentials

Lists all credentials you have access to.

**Input:** None required

**Output:**
```json
{
  "credentials": [
    {
      "alias": "github-api",
      "type": "api_key",
      "description": "GitHub personal access token"
    }
  ]
}
```

**Permission Required:** read

---

### http_request

Makes an authenticated HTTP request.

**Input:**
```json
{
  "credential": "string (required) - credential alias",
  "method": "string (required) - GET|POST|PUT|PATCH|DELETE",
  "url": "string (required) - target URL",
  "headers": "object (optional) - additional headers",
  "body": "string (optional) - request body"
}
```

**Output:**
```json
{
  "status": 200,
  "headers": {"content-type": "application/json"},
  "body": "string - response body"
}
```

**Permission Required:** execute

**Example:**
```json
{
  "credential": "github-api",
  "method": "GET",
  "url": "https://api.github.com/user"
}
```

---

### get_credential_info

Returns metadata (type, description) for one credential — never the secret.

**Input:**
```json
{
  "credential": "string (required) - alias or id"
}
```

**Permission Required:** read

---

### check_approval

Polls an action that was gated for human approval. Once approved, this tool runs
the original action and returns its result; while pending it says to keep polling.
You may only poll approvals created by the same `api_key`/use token.

**Input:**
```json
{
  "approval_id": "string (required) - the appr_… id from a gated call"
}
```

**Permission Required:** execute

> **Credential writes are not MCP tools.** The stdio MCP server exposes only
> `list_credentials`, `http_request`, `get_credential_info`, and `check_approval`
> (plus any plugin/capability tools). Adding or deleting credentials is done with
> the CLI (`vultrino add` / `vultrino remove`) or the admin JSON API — there is no
> `add_credential` / `delete_credential` MCP tool.

Every tool call also takes an `api_key` argument — a `vk_` API key or a `vut_`
use token — which Vultrino consumes and never forwards to the target.

---

## HTTP API Endpoints

Served by `vultrino web` at `http://127.0.0.1:7879`. All routes are under
`/api/v1/` and take `Authorization: Bearer vk_…` or `vut_…`. There is no
credential header and no transparent proxy. Full wire reference:
[`docs/dev/API.md`](../../dev/API.md).

### Execute an action

```
POST /api/v1/execute
Authorization: Bearer {vk_ or vut_ token}
Content-Type: application/json

{
  "credential": "alias",
  "method": "GET",
  "url": "https://...",
  "action": "http.request",   // optional; defaults to http.request
  "headers": {},              // optional
  "body": null,               // optional
  "query": {}                 // optional
}
```

Returns `{ "status", "headers", "body" }` on `200`, or a `202` pending-approval
envelope with an `approval_id` to poll.

### List Credentials (metadata only)

```
GET /api/v1/credentials
Authorization: Bearer {api_key}    # requires the `read` permission
```

### Create / Delete Credential (admin API key only)

```
POST   /api/v1/credentials         # body: { alias, metadata?, data }
DELETE /api/v1/credentials/{id}    # by id, not alias
```

There is no `GET /api/v1/credentials/{alias}` route. See
[Admin API](../api/admin.md).

---

## CLI Commands

```bash
# Initialize
vultrino init

# Add credential
vultrino add --alias NAME --key SECRET

# List credentials
vultrino list

# Make request (credential alias is the first positional argument)
vultrino request ALIAS URL

# Start the HTTP API + web UI (default 127.0.0.1:7879)
vultrino web

# Start MCP server (stdio) for AI agents
vultrino mcp   # or: vultrino serve --mcp

# Manage roles
vultrino role create NAME --permissions read,execute
vultrino role list
vultrino role delete NAME

# Manage API keys
vultrino key create NAME --role ROLE
vultrino key list
vultrino key revoke KEY_PREFIX
```

---

## Credential Types

### api_key
- For API tokens, bearer tokens
- Injected as: `Authorization: Bearer {key}`

### basic_auth
- For username/password
- Injected as: `Authorization: Basic {base64(user:pass)}`

### oauth2
- For OAuth2 with refresh tokens
- Handles token refresh automatically

---

## Permissions

| Permission | Description |
|------------|-------------|
| read | List credentials (metadata only) |
| write | Create new credentials |
| update | Modify existing credentials |
| delete | Remove credentials |
| execute | Use credentials for requests |

---

## Error Codes

| Code | Meaning |
|------|---------|
| invalid_api_key / invalid_token | Missing or invalid bearer token |
| permission_denied | Role lacks the required permission |
| token_unusable | Use token revoked, expired, or exhausted |
| execute_error | Policy denied, credential not found, SSRF block, or plugin error |

---

## Common Patterns

### List then use

```
1. list_credentials → see what's available
2. http_request → use the appropriate credential
```

### Handle missing credentials

When a credential isn't available:
1. List available credentials
2. Tell user what's available
3. Suggest adding the needed credential

### Parse response body

The `body` field in http_request response is always a string.
Parse it according to the content-type:
- `application/json` → JSON.parse()
- `text/plain` → use directly
- `text/html` → use directly

---

## Security Notes

1. **Never ask for actual secrets** - only use aliases
2. **Credentials are never returned** - only metadata
3. **All requests are logged** - audit trail exists
4. **Policies may restrict access** - some URLs/methods may be blocked
5. **Scopes limit visibility** - you may not see all credentials

---

## Environment

| Variable | Purpose |
|----------|---------|
| VULTRINO_PASSWORD | Decryption password (required) |
| VULTRINO_CONFIG | Config file path |
| RUST_LOG | Log level |

| Port | Service |
|------|---------|
| 7879 | `vultrino web` — HTTP JSON API (`/api/v1/…`, `/mcp`, `/llm`) + admin UI |
| stdio | `vultrino mcp` — MCP server for local AI agents (no port) |

---

## Quick Examples

**Get GitHub user:**
```json
{"tool": "http_request", "arguments": {"credential": "github-api", "method": "GET", "url": "https://api.github.com/user"}}
```

**Create Stripe customer:**
```json
{"tool": "http_request", "arguments": {"credential": "stripe-api", "method": "POST", "url": "https://api.stripe.com/v1/customers", "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "email=test@example.com"}}
```

**List repos:**
```json
{"tool": "http_request", "arguments": {"credential": "github-api", "method": "GET", "url": "https://api.github.com/user/repos"}}
```

**Post to Slack:**
```json
{"tool": "http_request", "arguments": {"credential": "slack-webhook", "method": "POST", "url": "https://hooks.slack.com/services/xxx", "headers": {"Content-Type": "application/json"}, "body": "{\"text\":\"Hello!\"}"}}
```
