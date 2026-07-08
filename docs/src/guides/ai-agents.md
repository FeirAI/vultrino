# Using with AI Agents

Vultrino enables AI agents to make authenticated API calls without exposing credentials. This guide covers integration patterns and best practices.

## Why Vultrino for AI Agents?

AI agents (Claude, GPT, etc.) need to interact with APIs, but:
- Credentials shouldn't be in prompts or context
- Agents shouldn't see actual secrets
- Usage should be auditable
- Access should be restricted and revocable

Vultrino solves this by:
1. Storing credentials securely (encrypted at rest)
2. Exposing only aliases to agents
3. Injecting auth automatically
4. Logging all usage

## Integration Options

### 1. MCP Server (Recommended)

The Model Context Protocol provides native AI integration:

```bash
vultrino mcp
```

**Pros:**
- Native protocol for AI tools
- Rich tool descriptions
- Scoped access via API key authentication
- Best security isolation

**Setup:**
See [MCP Server documentation](../components/mcp.md) for configuration.

### 2. HTTP API

For agents that can make HTTP requests:

```bash
vultrino web  # Start the JSON API + admin UI on 127.0.0.1:7879
```

The agent POSTs the credential alias and target to the execute endpoint (there is
no credential header and no transparent proxy):

```
POST http://vultrino:7879/api/v1/execute
Authorization: Bearer vk_your_api_key
Content-Type: application/json

{"credential": "github-api", "method": "GET", "url": "https://api.github.com/user"}
```

**Pros:**
- Works with any HTTP-capable agent
- Simple integration
- Language agnostic

### 3. CLI Tool Calls

For agents that can execute shell commands:

```bash
vultrino request github-api https://api.github.com/user
```

**Pros:**
- Simplest integration
- Works with function calling
- Easy to audit

## Setting Up for AI Agents

### Step 1: Store Credentials

```bash
# Add credentials the AI will need
vultrino add --alias github-api --key ghp_xxx \
  --description "GitHub API for repo access"

vultrino add --alias stripe-test --key sk_test_xxx \
  --description "Stripe test mode API"
```

### Step 2: Create Restricted Role

```bash
# Create a role with limited access
vultrino role create ai-agent \
  --permissions read,execute \
  --scopes "github-api,stripe-test" \
  --description "Limited access for AI agent"
```

### Step 3: Create API Key

```bash
vultrino key create claude-key --role ai-agent --expires 30d
# Save the generated key
```

### Step 4: Configure AI Client

For Claude Desktop MCP:
```json
{
  "mcpServers": {
    "vultrino": {
      "command": "/path/to/vultrino",
      "args": ["mcp"],
      "env": {
        "VULTRINO_PASSWORD": "your-password"
      }
    }
  }
}
```

### Step 5: Configure Agent with API Key

Add to your AI agent's system prompt:
```
When using Vultrino tools, always include your API key in every tool call:

For listing credentials:
{"tool": "list_credentials", "arguments": {"api_key": "vk_your_generated_key_here"}}

For making requests:
{"tool": "http_request", "arguments": {"api_key": "vk_your_generated_key_here", "credential": "...", ...}}
```

**Important:** Every tool call requires the `api_key` parameter. This enables multiple agents to share the same MCP server with different scoped access.

## Example Interactions

### Listing Available Credentials

**User:** "What APIs can you access?"

**AI:** *calls list_credentials with api_key*
```json
{
  "tool": "list_credentials",
  "arguments": {"api_key": "vk_..."}
}
```

**AI:** "I have access to:
- `github-api` — GitHub API for repo access
- `stripe-test` — Stripe test mode API"

### Making Requests

**User:** "Check my GitHub notifications"

**AI:** *calls http_request with api_key and credential*
```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_...",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/notifications"
  }
}
```

**AI:** "You have 3 unread notifications..."

### Handling Errors

**User:** "Access my AWS account"

**AI:** *calls http_request with credential=aws-prod*

**AI:** "I don't have access to AWS credentials. I can only access:
- github-api
- stripe-test

Would you like to add AWS credentials?"

## Security Best Practices

### 1. Scope Credentials Narrowly

Don't give AI access to admin credentials:

```bash
# Bad: Full admin access
vultrino add --alias github-admin --key ghp_admin_everything

# Good: Read-only access
vultrino add --alias github-readonly --key ghp_read_only_token
```

### 2. Use Test/Sandbox Credentials

For AI experimentation, use test mode:

```bash
vultrino add --alias stripe-test --key sk_test_xxx
# Not: stripe-live with sk_live_xxx
```

### 3. Set Key Expiration

Short-lived keys limit damage if compromised:

```bash
vultrino key create ai-key --role ai-agent --expires 7d
```

### 4. Monitor Usage

Check what the AI is doing:

```bash
# Watch audit log
tail -f /var/log/vultrino/audit.log

# Filter by credential
grep "github-api" /var/log/vultrino/audit.log
```

### 5. Restrict Scopes

Only allow access to specific credentials:

```bash
vultrino role create ai-readonly \
  --permissions read,execute \
  --scopes "github-readonly,stripe-test"
```

## Common Patterns

### Read-Only Research Agent

```bash
# Create read-only credential
vultrino add --alias github-public --key ghp_public_readonly

# Create restricted role
vultrino role create research-agent \
  --permissions read,execute \
  --scopes "github-public"

# Create key
vultrino key create research-key --role research-agent
```

### Multi-Service Agent

```bash
# Add multiple credentials
vultrino add --alias github-api --key ghp_xxx
vultrino add --alias linear-api --key lin_xxx
vultrino add --alias notion-api --key secret_xxx

# Role with access to all
vultrino role create project-agent \
  --permissions read,execute \
  --scopes "github-api,linear-api,notion-api"
```

### Development vs Production

```bash
# Dev credentials
vultrino add --alias stripe-dev --key sk_test_xxx
vultrino add --alias github-dev --key ghp_dev_xxx

# Dev-only role
vultrino role create ai-dev \
  --permissions read,execute \
  --scopes "*-dev,*-test"

# This role CANNOT access production credentials
```

## Prompt Engineering Tips

### Be Explicit About Available Credentials

System prompt:
```
You have access to these credentials through Vultrino:
- github-api: Read/write access to company repositories
- jira-api: Read access to project issues
- slack-api: Can post to #engineering channel

Always use these aliases when making API requests.
Never ask for or accept raw API keys.
```

### Guide Credential Usage

```
When the user asks about GitHub:
1. Use github-api credential
2. Check available endpoints first
3. Prefer read operations over write

When uncertain, list available credentials first.
```

### Handle Errors Gracefully

```
If a credential is not available or access is denied:
1. Inform the user what credentials you DO have access to
2. Suggest alternatives if possible
3. Never attempt to bypass Vultrino
```

## Troubleshooting

### Agent Can't Find Credentials

- Verify credentials exist: `vultrino list`
- Check role scopes include the credential
- Ensure API key has read permission

### Request Fails with 403

- Check role has execute permission
- Verify credential scope matches
- The underlying API may also be denying access

### MCP Server Not Responding

- Ensure `VULTRINO_PASSWORD` is set
- Check Vultrino binary path is correct
- Review stderr for error messages

### Audit Log Not Showing Requests

- Audit logging may be disabled
- Check config: `logging.audit_file`
- Verify file permissions

## Monitoring AI Usage

### Real-time Monitoring

```bash
# Watch all AI requests
tail -f /var/log/vultrino/audit.log | grep ai-agent-key

# Count requests per credential
awk '{print $4}' /var/log/vultrino/audit.log | sort | uniq -c
```

### Usage Reports

Generate daily summaries:
```bash
# Requests per credential today
grep $(date +%Y-%m-%d) /var/log/vultrino/audit.log | \
  awk '{print $4}' | sort | uniq -c | sort -rn
```

### Alerting

Set up alerts for unusual activity:
- Sudden spike in requests
- Access to unexpected credentials
- Failed authentication attempts
