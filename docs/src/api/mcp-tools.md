# MCP Tools Reference

Complete reference for Vultrino's Model Context Protocol (MCP) tools.

## Overview

Vultrino exposes tools through MCP that allow AI agents to:
- List available credentials (`list_credentials`) and inspect one (`get_credential_info`)
- Make authenticated HTTP requests (`http_request`)
- Poll for human approval of gated actions (`check_approval`)

Installed plugins and granted capabilities can contribute additional named tools.
Credential writes are **not** MCP tools (see the note below `get_credential_info`).

> **Authentication.** Every tool takes an `api_key` argument. It accepts a regular API key (`vk_…`) **or** a [use token](../guides/use-tokens.md) (`vut_…`). A use token additionally constrains which credential and action the call may use, and how many times. The `api_key` argument is consumed by Vultrino and is **never** forwarded to the target API or plugin.

## Tool Definitions

### list_credentials

List all credentials available to the current session.

**Schema:**
```json
{
  "name": "list_credentials",
  "description": "List all available credential aliases. Returns metadata only, never actual secrets.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "api_key": { "type": "string", "description": "API key (vk_) or use token (vut_)" },
      "pattern": { "type": "string", "description": "Optional glob to filter aliases (e.g. 'github-*')" }
    },
    "required": ["api_key"]
  }
}
```

**Input:** None

**Output:**
```json
{
  "credentials": [
    {
      "alias": "github-api",
      "type": "api_key",
      "description": "GitHub personal access token"
    },
    {
      "alias": "stripe-test",
      "type": "api_key",
      "description": "Stripe test mode API key"
    }
  ]
}
```

**Required Permission:** `read`

**Example Usage:**
```
User: "What APIs can you access?"
Agent: [calls list_credentials]
Agent: "I have access to 2 credentials: github-api and stripe-test"
```

---

### http_request

Make an authenticated HTTP request using a stored credential.

**Schema:**
```json
{
  "name": "http_request",
  "description": "Make an authenticated HTTP request. The credential's actual value is never exposed - only the alias is needed. Vultrino automatically injects the appropriate authentication header.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "api_key": {
        "type": "string",
        "description": "API key (vk_) or use token (vut_)"
      },
      "credential": {
        "type": "string",
        "description": "Alias of the credential to use for authentication"
      },
      "method": {
        "type": "string",
        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        "description": "HTTP method"
      },
      "url": {
        "type": "string",
        "description": "Target URL"
      },
      "headers": {
        "type": "object",
        "description": "Additional headers to include in the request",
        "additionalProperties": { "type": "string" }
      },
      "body": {
        "description": "Request body (for POST, PUT, PATCH requests)"
      },
      "query": {
        "type": "object",
        "description": "Query parameters to append to the URL",
        "additionalProperties": { "type": "string" }
      }
    },
    "required": ["api_key", "credential", "method", "url"]
  }
}
```

**Input:**
```json
{
  "credential": "github-api",
  "method": "GET",
  "url": "https://api.github.com/user",
  "headers": {
    "Accept": "application/vnd.github.v3+json"
  }
}
```

**Output:**
```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json; charset=utf-8",
    "x-ratelimit-limit": "5000",
    "x-ratelimit-remaining": "4999"
  },
  "body": "{\"login\":\"username\",\"id\":12345,...}"
}
```

**Required Permission:** `execute`

**Error Responses:**

| Error | Description |
|-------|-------------|
| `credential_not_found` | The specified credential alias doesn't exist |
| `permission_denied` | No permission to use this credential |
| `policy_denied` | Request blocked by policy rules |
| `upstream_error` | Failed to connect to target server |

**Example Usage:**
```
User: "Get my GitHub profile"
Agent: [calls http_request with credential=github-api, url=https://api.github.com/user]
Agent: "Your GitHub profile shows you're logged in as 'username' with 42 public repos"
```

**Approval-gated response:**

If the credential, use token, or a policy requires human approval, `http_request` returns an **"APPROVAL REQUIRED"** message with an `approval_id` instead of a result — the action has **not** run. The agent should then poll `check_approval` (below) with that id.

---

### check_approval

Poll a previously-gated action. Once a human approves it, this tool **runs the action and returns the real result**. Until then it reports the current status and tells the agent to keep polling. An agent may only check approvals it originally requested (same `api_key`/use token).

**Schema:**
```json
{
  "name": "check_approval",
  "description": "Check the status of an action that required human approval, and retrieve its result once approved.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "api_key": { "type": "string", "description": "API key or use token (same one that made the original request)" },
      "approval_id": { "type": "string", "description": "The approval id returned by the gated tool call" }
    },
    "required": ["api_key", "approval_id"]
  }
}
```

**Output (still pending):**
```json
{
  "approval_id": "appr_xxxxxxxx",
  "status": "Pending",
  "executed": false,
  "message": "Awaiting human approval. The action has NOT run. Poll again every ~10-30 seconds."
}
```

**Output (approved and executed):**
```json
{
  "approval_id": "appr_xxxxxxxx",
  "status": "Approved",
  "executed": true,
  "message": "Approved and executed.",
  "result": { "status": 200, "body": "..." }
}
```

A `Denied` or `Expired` status returns a `message` instructing the agent to stop and not retry. The action runs **at most once** no matter how many times it is polled.

**Required Permission:** `execute` (same as the original request)

---

### get_credential_info

Return metadata about one credential — its type and description. Never exposes the
secret value.

**Schema:**
```json
{
  "name": "get_credential_info",
  "description": "Get metadata (type, description) for a specific credential. Does not expose the actual secret value.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "api_key": { "type": "string", "description": "API key or use token" },
      "credential": { "type": "string", "description": "The credential alias or id" }
    },
    "required": ["api_key", "credential"]
  }
}
```

**Required Permission:** `read`

---

> **Credential writes are not MCP tools.** The stdio/networked MCP server exposes
> exactly four built-in tools — `list_credentials`, `http_request`,
> `get_credential_info`, `check_approval` — plus any tools contributed by
> installed plugins or granted capabilities. To add or delete credentials, use the
> CLI (`vultrino add` / `vultrino remove`) or the admin JSON API
> (`POST /api/v1/credentials`, `DELETE /api/v1/credentials/{id}`). There is no
> `add_credential` or `delete_credential` tool.

## Permission Requirements

| Tool | Required Permission |
|------|---------------------|
| `list_credentials` | `read` |
| `get_credential_info` | `read` |
| `http_request` | `execute` |
| `check_approval` | `execute` |

## Scope Restrictions

If the API key's role has credential scopes, tools are further restricted:

- `list_credentials` — Only shows credentials matching scope patterns
- `get_credential_info` — Only resolves credentials matching scope patterns
- `http_request` — Only works with credentials matching scope patterns

## Error Format

All MCP tool errors follow this format:

```json
{
  "error": {
    "code": "error_code",
    "message": "Human-readable error message"
  }
}
```

## Usage Patterns

### Basic API Call

```json
{
  "tool": "http_request",
  "arguments": {
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```

### POST with JSON Body

```json
{
  "tool": "http_request",
  "arguments": {
    "credential": "stripe-api",
    "method": "POST",
    "url": "https://api.stripe.com/v1/customers",
    "headers": {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    "body": "email=test@example.com&name=Test+User"
  }
}
```

### Check Available Credentials First

```json
// Step 1: List what's available
{
  "tool": "list_credentials",
  "arguments": {}
}

// Step 2: Use a credential
{
  "tool": "http_request",
  "arguments": {
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/repos/owner/repo"
  }
}
```

## Best Practices for AI Agents

### 1. List First, Then Use

Always check available credentials before attempting to use one:

```
1. Call list_credentials
2. Verify the needed credential exists
3. Call http_request with the credential
```

### 2. Handle Errors Gracefully

When a credential isn't available:
```
Agent: "I don't have access to AWS credentials. The credentials I can use are:
- github-api (GitHub API)
- stripe-test (Stripe test mode)

Would you like to add AWS credentials?"
```

### 3. Use Appropriate Methods

- **GET** — Fetch data
- **POST** — Create resources
- **PUT** — Replace resources
- **PATCH** — Update resources
- **DELETE** — Remove resources

### 4. Include Necessary Headers

Many APIs require specific headers:
```json
{
  "headers": {
    "Accept": "application/json",
    "Content-Type": "application/json"
  }
}
```

### 5. Parse Response Bodies

The `body` field is a string. Parse it as appropriate:
- JSON APIs: `JSON.parse(response.body)`
- XML APIs: Parse as XML
- Plain text: Use directly

## Security Notes

1. **Credentials are never exposed** — The AI only sees aliases
2. **All requests are logged** — Audit trail of all tool usage
3. **Policies are enforced** — URL and method restrictions apply
4. **Rate limits apply** — Prevent abuse
5. **Scopes restrict access** — Roles limit which credentials are visible
