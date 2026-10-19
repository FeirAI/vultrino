# Roles & API Keys

Vultrino's Role-Based Access Control (RBAC) system lets you create scoped API keys for different applications, each with specific permissions.

## Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│   API Key   │────▶│    Role     │────▶│  Permissions        │
│   vk_xxx    │     │  executor   │     │  + Credential Scopes│
└─────────────┘     └─────────────┘     └─────────────────────┘
```

- **API Keys** — Authenticate applications
- **Roles** — Define permissions and scopes
- **Permissions** — What actions are allowed
- **Scopes** — Which credentials are accessible

## Permissions

| Permission | Description |
|------------|-------------|
| `read` | List credentials (metadata only, never secrets) |
| `write` | Create new credentials |
| `update` | Modify existing credentials |
| `delete` | Remove credentials |
| `execute` | Use credentials for authenticated requests |
| `admin` | Administer the enforcement plane through the admin API (policies, use tokens, roles, credential metadata). Held by the predefined `admin` role; grant it sparingly |

## Predefined Roles

Vultrino includes three predefined roles that are always available:

| Role | Permissions | Use Case |
|------|-------------|----------|
| `admin` | read, write, update, delete, execute, admin | Full administrative access |
| `executor` | read, execute | AI agents and applications (recommended) |
| `read-only` | read | Monitoring and listing credentials only |

These roles cannot be deleted and are available immediately after init.

## Creating Custom Roles

### Basic Role

```bash
# Read-only role (can only list credentials)
vultrino role create readonly --permissions read

# Execute-only role (can use credentials but not manage them)
vultrino role create executor --permissions execute

# Full management role
vultrino role create admin --permissions read,write,update,delete,execute
```

### Scoped Roles

Limit which credentials a role can access using glob patterns:

```bash
# Only GitHub credentials
vultrino role create github-user \
  --permissions read,execute \
  --scopes "github-*"

# Only test credentials (no production)
vultrino role create test-executor \
  --permissions execute \
  --scopes "*-test,*-staging"

# Multiple specific patterns
vultrino role create payment-processor \
  --permissions execute \
  --scopes "stripe-*,paypal-*,braintree-*"
```

### With Description

```bash
vultrino role create ci-pipeline \
  --permissions read,execute \
  --scopes "github-ci-*" \
  --description "Used by CI/CD pipeline for deployments"
```

## Managing Roles

### List Roles

```bash
vultrino role list

# Output:
# Name            Permissions                    Scopes
# readonly        read                           (all)
# executor        execute                        (all)
# github-user     read,execute                   github-*
```

### View Role Details

```bash
vultrino role info github-user

# Output:
# Name:        github-user
# ID:          <role id>
# Permissions: read, execute
# Scopes:      github-*
# Created:     2024-01-15 10:30:00 UTC
```

### Delete Role

```bash
vultrino role delete old-role
```

Note: Deleting a role doesn't delete associated API keys, but those keys will no longer work.

## Creating API Keys

### Basic Key

```bash
vultrino key create my-app --role executor
# Output:
# Created API key: vk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
#
# IMPORTANT: Save this key now. It won't be shown again.
```

### With Expiration

```bash
# Expires in 30 days
vultrino key create temp-access --role readonly --expires 30d

# Expires in about 1 year
vultrino key create annual-key --role executor --expires 365d

# An absolute date is not supported. Accepted forms: a number with h, d, w or m
# (m = 30 days), or never (the default).
```

## Managing API Keys

### List Keys

```bash
vultrino key list

# Output:
# Prefix      Name         Role          Expires        Last Used
# vk_a1b2... my-app       executor      never          2024-01-15
# vk_x9y8... temp-access  readonly      2024-02-14     2024-01-16
```

### Revoke Key

```bash
vultrino key revoke vk_a1b2c3d4
# Revoked API key: vk_a1b2c3d4
```

Revocation is immediate. Any requests using the key will fail.

## Using API Keys

### CLI with API Key (No Password Required)

Once `vultrino web` is running, use CLI commands with just an API key:

```bash
# Make request using API key (no VULTRINO_PASSWORD needed)
vultrino --key vk_a1b2c3d4... request github-api https://api.github.com/user
```

This connects to the running web server's API at `VULTRINO_API_URL` (default `http://127.0.0.1:7879`). Plain `http://` is accepted only to a loopback or private address; use `https://` otherwise. Only `request` uses the API key this way; other commands still open the vault directly and need `VULTRINO_PASSWORD`.

### MCP Server (Per-Request Auth)

Every MCP tool call requires the API key:

```json
{
  "tool": "list_credentials",
  "arguments": {
    "api_key": "vk_a1b2c3d4..."
  }
}
```

```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_a1b2c3d4...",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```

This allows multiple AI agents to use the same MCP server with different scoped keys.

### HTTP API

Include the API key in the Authorization header:

```bash
# List credentials
curl -H "Authorization: Bearer vk_a1b2c3d4..." \
     http://localhost:7879/api/v1/credentials

# Execute request
curl -X POST http://localhost:7879/api/v1/execute \
     -H "Authorization: Bearer vk_a1b2c3d4..." \
     -H "Content-Type: application/json" \
     -d '{"credential": "github-api", "method": "GET", "url": "https://api.github.com/user"}'
```

### Application Configuration

Store the API key in your application's environment:

```bash
# .env
VULTRINO_API_KEY=vk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

```python
import os
import requests

api_key = os.environ["VULTRINO_API_KEY"]
response = requests.post(
    "http://vultrino:7879/api/v1/execute",
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    },
    json={
        "credential": "github-api",
        "method": "GET",
        "url": "https://api.github.com/user"
    }
)
```

## Web UI

### Creating Roles

1. Navigate to **Roles** in the sidebar
2. Click **New Role**
3. Fill in:
   - Name
   - Description (optional)
   - Select permissions
   - Enter credential scopes (comma-separated)
4. Click **Create Role**

### Creating API Keys

1. Navigate to **API Keys** in the sidebar
2. Click **New API Key**
3. Fill in:
   - Name (for identification)
   - Select a role
   - Expiration date (optional)
4. Click **Create Key**
5. **Copy the key immediately** — it's only shown once

## Common Patterns

### Multi-Environment Setup

```bash
# Production role (limited credentials)
vultrino role create prod-app \
  --permissions execute \
  --scopes "*-prod"

# Staging role (more credentials)
vultrino role create staging-app \
  --permissions read,execute \
  --scopes "*-staging,*-test"

# Development role (everything except prod)
vultrino role create dev-app \
  --permissions read,write,execute \
  --scopes "*-dev,*-staging,*-test"
```

### Per-Service Keys

```bash
# Role for payment processing
vultrino role create payment-service \
  --permissions execute \
  --scopes "stripe-*,paypal-*"

# Create key for the payment service
vultrino key create payment-service-prod --role payment-service

# Role for email service
vultrino role create email-service \
  --permissions execute \
  --scopes "sendgrid-*,mailgun-*"

# Create key for the email service
vultrino key create email-service-prod --role email-service
```

### CI/CD Pipeline

```bash
# Read-only for listing credentials in CI
vultrino role create ci-readonly \
  --permissions read \
  --scopes "*"

# Execute for deployments
vultrino role create ci-deploy \
  --permissions execute \
  --scopes "aws-deploy-*,github-ci-*"

# Short-lived keys for CI
vultrino key create ci-read-key --role ci-readonly --expires 7d
vultrino key create ci-deploy-key --role ci-deploy --expires 7d
```

### AI Agent Access

```bash
# Limited role for AI agents
vultrino role create ai-agent \
  --permissions read,execute \
  --scopes "github-api,stripe-test"  # Only specific credentials

# Create key for the AI
vultrino key create claude-agent --role ai-agent
```

## Security Best Practices

### 1. Principle of Least Privilege

Only grant the minimum permissions needed:

```bash
# Bad: Full admin access
vultrino role create my-app --permissions read,write,update,delete,execute

# Good: Only what's needed
vultrino role create my-app --permissions execute --scopes "api-needed-*"
```

### 2. Use Scopes

Always scope credentials when possible:

```bash
# Bad: Access to all credentials
vultrino role create service-role --permissions execute

# Good: Scoped to specific credentials
vultrino role create service-role --permissions execute --scopes "service-*"
```

### 3. Set Expiration

Use expiring keys for temporary access:

```bash
# Contractor access
vultrino key create contractor-key --role readonly --expires 90d

# CI pipeline (rotate weekly)
vultrino key create ci-key --role ci-deploy --expires 7d
```

### 4. Audit Key Usage

There is no audit log file. Review key activity through the event outbox
(`GET /api/v1/events?after=<cursor>`, global admin key) and the server logs.

### 5. Rotate Keys Regularly

Even for long-lived applications, rotate keys periodically:

1. Create new key
2. Update application configuration
3. Verify new key works
4. Revoke old key

## Troubleshooting

### "Permission denied"

- Check the role has the required permission
- Verify the credential matches the role's scopes
- Ensure the API key hasn't expired

### "API key not found"

- The key may have been revoked
- Check for typos in the key
- Verify the key was created successfully

### "Role not found"

- The role may have been deleted
- Keys without valid roles won't work
- Recreate the role or assign a new role to a new key
