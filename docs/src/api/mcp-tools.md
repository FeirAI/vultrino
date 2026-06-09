# MCP Tools Reference

Complete reference for Vultrino's Model Context Protocol (MCP) tools.

## Overview

Vultrino exposes tools through MCP that allow AI agents to:
- List available credentials
- Make authenticated HTTP requests
- Manage credentials (with appropriate permissions)
- Poll for human approval of gated actions (`check_approval`)

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
    "properties": {},
    "required": []
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
        "description": "Target URL (must be HTTPS for security)"
      },
      "headers": {
        "type": "object",
        "description": "Additional headers to include in the request",
        "additionalProperties": {
          "type": "string"
        }
      },
      "body": {
        "type": "string",
        "description": "Request body (for POST, PUT, PATCH requests)"
      }
    },
    "required": ["credential", "method", "url"]
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

**Boundary behavior:**

- **Redirects are not followed.** A 3xx response is returned as-is (status +
  `Location` header); issue a new request to the new URL — it gets the same
  SSRF and policy validation as any other request.
- **Egress redaction.** If the upstream response contains the injected
  credential material (e.g. an echo endpoint reflecting request headers), it
  is replaced with `[REDACTED:vultrino]` before the response reaches the
  agent.
- **Host binding.** If the credential has `allowed_hosts` metadata
  (comma-separated hosts / `*.domain` wildcards), requests to any other host
  are rejected before the credential is attached.
- **Limits.** Response bodies are capped at 10 MB and requests time out after
  60 seconds.

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

### add_credential

Add a new credential to storage.

**Schema:**
```json
{
  "name": "add_credential",
  "description": "Store a new credential. The credential will be encrypted at rest and only accessible by alias.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "alias": {
        "type": "string",
        "description": "Unique human-readable name for this credential"
      },
      "type": {
        "type": "string",
        "enum": ["api_key", "basic_auth"],
        "description": "Type of credential"
      },
      "key": {
        "type": "string",
        "description": "API key or token value (for api_key type)"
      },
      "username": {
        "type": "string",
        "description": "Username (for basic_auth type)"
      },
      "password": {
        "type": "string",
        "description": "Password (for basic_auth type)"
      },
      "description": {
        "type": "string",
        "description": "Optional description of what this credential is for"
      }
    },
    "required": ["alias", "type"]
  }
}
```

**Input (API Key):**
```json
{
  "alias": "new-service-api",
  "type": "api_key",
  "key": "sk_live_xxxxxxxxxxxx",
  "description": "API key for new service"
}
```

**Input (Basic Auth):**
```json
{
  "alias": "jenkins-ci",
  "type": "basic_auth",
  "username": "admin",
  "password": "token123",
  "description": "Jenkins CI access"
}
```

**Output:**
```json
{
  "success": true,
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "alias": "new-service-api"
}
```

**Required Permission:** `write`

**Error Responses:**

| Error | Description |
|-------|-------------|
| `permission_denied` | No write permission |
| `alias_exists` | A credential with this alias already exists |
| `invalid_type` | Unknown credential type |

---

### delete_credential

Remove a credential from storage.

**Schema:**
```json
{
  "name": "delete_credential",
  "description": "Delete a credential by its alias. This action cannot be undone.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "alias": {
        "type": "string",
        "description": "Alias of the credential to delete"
      }
    },
    "required": ["alias"]
  }
}
```

**Input:**
```json
{
  "alias": "old-api-key"
}
```

**Output:**
```json
{
  "success": true
}
```

**Required Permission:** `delete`

**Error Responses:**

| Error | Description |
|-------|-------------|
| `permission_denied` | No delete permission |
| `not_found` | Credential with this alias not found |

---

## Permission Requirements

| Tool | Required Permission |
|------|---------------------|
| `list_credentials` | `read` |
| `http_request` | `execute` |
| `check_approval` | `execute` |
| `add_credential` | `write` |
| `delete_credential` | `delete` |

## Scope Restrictions

If the API key's role has credential scopes, tools are further restricted:

- `list_credentials` — Only shows credentials matching scope patterns
- `http_request` — Only works with credentials matching scope patterns
- `add_credential` — New credentials must match scope patterns
- `delete_credential` — Can only delete credentials matching scope patterns

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
