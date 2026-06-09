# LLM Reference

This section provides documentation optimized for Large Language Models (LLMs) to understand and use Vultrino effectively.

## Quick Reference

### What is Vultrino?

Vultrino is a credential proxy that allows applications (including AI agents) to make authenticated API requests without seeing the actual credentials.

**Key Concept:** You use credential *aliases* (like "github-api"), not actual secrets.

### Available Paths

For programmatic access to documentation, these raw markdown paths are available:

| Content | Path |
|---------|------|
| Full reference | `/llm/full-reference.md` |
| Quick start | `/getting-started/quickstart.md` |
| CLI commands | `/components/cli.md` |
| HTTP API | `/api/http.md` |
| MCP tools | `/api/mcp-tools.md` |

## Condensed Reference

### Making Authenticated Requests

**Via HTTP Proxy:**
```bash
curl -H "X-Vultrino-Credential: <alias>" \
     http://localhost:7878/https://target-api.com/endpoint
```

**Via MCP (AI Agents):**
```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_your_api_key_here",
    "credential": "<alias>",
    "method": "GET",
    "url": "https://target-api.com/endpoint"
  }
}
```

**Via CLI (requires running Vultrino web server):**
```bash
vultrino --key vk_your_api_key request <alias> https://target-api.com/endpoint
```

### MCP Tools Summary

| Tool | Purpose | Required Permission |
|------|---------|---------------------|
| `list_credentials` | List available credentials | read |
| `http_request` | Make authenticated request | execute |
| `check_approval` | Retrieve the result of an action that required human approval | execute |
| `get_credential_info` | Get credential metadata | read |

**Important:** Every tool call requires an `api_key` parameter for authentication. This value may be a regular API key (`vk_…`) or a **use token** (`vut_…`) — a single-use or time-scoped grant restricted to one credential/action.

**Approval gating:** If a request requires human approval, `http_request` returns an "APPROVAL REQUIRED" message with an `approval_id` and the action does **not** run. Poll `check_approval` with that id (re-sending your `api_key`) every ~10–30 seconds; once a human approves, it returns the real result. A denied/expired approval tells you to stop — do not retry.

### Common Credential Aliases

Typical naming patterns:
- `github-api` — GitHub API token
- `stripe-live` / `stripe-test` — Stripe API keys
- `openai` — OpenAI API key
- `anthropic` — Anthropic API key
- `aws-prod` / `aws-staging` — AWS credentials

## For AI Agents

**Authentication Model:** Every tool call requires your API key. This enables multiple agents to use the same MCP server with different scoped keys.

### Step 1: Check Available Credentials

```json
{
  "tool": "list_credentials",
  "arguments": {
    "api_key": "vk_your_api_key_here"
  }
}
```

Response:
```json
{
  "credentials": [
    {"alias": "github-api", "type": "api_key", "description": "..."},
    {"alias": "stripe-test", "type": "api_key", "description": "..."}
  ]
}
```

### Step 2: Make Request

```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_your_api_key_here",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```

Response:
```json
{
  "status": 200,
  "headers": {"content-type": "application/json"},
  "body": "{\"login\":\"username\",...}"
}
```

### Step 3: Parse Response

The `body` field is a JSON string. Parse it to access the data.

### Error Handling

If a credential isn't available:
1. List what IS available
2. Explain to user
3. Offer alternatives

Example response to user:
> "I don't have access to AWS credentials. I can access: github-api, stripe-test. Would you like to add AWS credentials?"

## HTTP API Quick Reference

### Proxy Request
```
GET /https://api.example.com/endpoint
X-Vultrino-Credential: <alias>
Authorization: Bearer <vultrino-api-key>  (if RBAC enabled)
```

### List Credentials
```
GET /v1/credentials
Authorization: Bearer <vultrino-api-key>
```

### Execute Action
```
POST /v1/execute
Authorization: Bearer <vultrino-api-key>
Content-Type: application/json

{"credential": "<alias>", "action": "http.request", "params": {...}}
```

## Configuration Summary

### Environment Variables
- `VULTRINO_PASSWORD` — Storage encryption password (required)
- `VULTRINO_CONFIG` — Config file path
- `RUST_LOG` — Log level

### Default Ports
- `7878` — HTTP proxy
- `7879` — Web UI

### File Locations
- `~/.vultrino/credentials.enc` — Encrypted credentials
- `~/.vultrino/admin.json` — Admin auth
- `/etc/vultrino/config.toml` — System config

## Security Model

1. **Credentials encrypted at rest** — AES-256-GCM
2. **Aliases only** — Never expose actual secrets
3. **RBAC** — Role-based access control via API keys
4. **Policies** — URL/method restrictions
5. **Audit logging** — Track all usage

## API Key Authentication

Vultrino uses **per-request API key authentication**. Include your API key in every tool call:

```json
{
  "tool": "list_credentials",
  "arguments": {
    "api_key": "vk_your_api_key_here"
  }
}
```

This design enables:
- **Multiple agents** using the same MCP server with different keys
- **Scoped access** - each key has its own permissions and credential access
- **No session state** - stateless, secure by default

The API key determines what credentials you can access based on your assigned role:

| Role | Permissions | Use Case |
|------|-------------|----------|
| `executor` | read, execute | AI agents (recommended) |
| `read-only` | read | Listing credentials only |
| `admin` | all | Full administrative access |

**Every tool call requires the `api_key` parameter.**

## Common Tasks

### "List my credentials"
```json
{"tool": "list_credentials", "arguments": {"api_key": "vk_..."}}
```

### "Get my GitHub user info"
```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_...",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```

### "Create a Stripe customer"
```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_...",
    "credential": "stripe-api",
    "method": "POST",
    "url": "https://api.stripe.com/v1/customers",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "body": "email=user@example.com"
  }
}
```

### "List GitHub repos"
```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_...",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user/repos"
  }
}
```
