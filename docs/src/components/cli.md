# CLI Reference

The Vultrino CLI provides complete control over credential management, server operations, and administration.

## Global Options

```bash
vultrino [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>    Path to config file
  -v, --verbose          Enable verbose output
  -h, --help             Print help
  -V, --version          Print version
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VULTRINO_PASSWORD` | Storage encryption password (required) |
| `VULTRINO_CONFIG` | Path to config file |
| `RUST_LOG` | Log level (trace, debug, info, warn, error) |

## Commands

### `init`

Initialize a new Vultrino instance.

```bash
vultrino init [OPTIONS]

Options:
  --force    Overwrite existing configuration
```

This command:
1. Creates the credentials storage file
2. Prompts for admin username and password
3. Sets up initial configuration

**Example:**
```bash
export VULTRINO_PASSWORD="your-secure-password"
vultrino init
# Enter admin username: admin
# Enter admin password: ********
```

---

### `add`

Add a new credential to storage.

```bash
vultrino add [OPTIONS]

Options:
  -a, --alias <ALIAS>         Human-readable name (required)
  -t, --type <TYPE>           Credential type [default: api_key]
  -k, --key <KEY>             API key or secret value
  -u, --username <USERNAME>   Username (for basic auth)
  -p, --password <PASSWORD>   Password (for basic auth)
  --description <DESC>        Optional description
```

**Credential Types:**
- `api_key` — API key or token
- `basic_auth` — Username and password
- `oauth2` — OAuth2 credentials (client ID, secret, tokens)
- `private_key` — SSH or signing key

**Examples:**
```bash
# Add an API key
vultrino add --alias github-api --key ghp_xxx...

# Add basic auth credentials
vultrino add --alias jira-api --type basic_auth \
  --username user@example.com --password secret123

# Add with description
vultrino add --alias stripe-api --key sk_live_xxx \
  --description "Production Stripe key"
```

---

### `list`

List all stored credentials.

```bash
vultrino list [OPTIONS]

Options:
  --json    Output as JSON
```

**Example:**
```bash
vultrino list
# ID                                    Alias         Type      Created
# 550e8400-e29b-41d4-a716-446655440000  github-api    api_key   2024-01-15
# 6ba7b810-9dad-11d1-80b4-00c04fd430c8  stripe-api    api_key   2024-01-16
```

---

### `info`

Show details about a specific credential — metadata only, never the secret.

```bash
vultrino info <ALIAS>
```

Accepts a credential alias or id.

**Example:**
```bash
vultrino info github-api
# Alias: github-api
# Type: api_key
# Created: 2024-01-15T10:30:00Z
# Description: GitHub personal access token
```

---

### `remove`

Remove a credential from storage.

```bash
vultrino remove <ALIAS>
```

Accepts a credential alias or id.

**Example:**
```bash
vultrino remove old-api-key
# Deleted credential: old-api-key
```

---

### `serve`

Run the MCP server (with `--mcp`). **`serve` on its own no longer starts an API
server** — it prints a message directing you to `vultrino web` and exits without
binding. Use `vultrino web` for the HTTP JSON API and admin UI, and `vultrino mcp`
(or `vultrino serve --mcp`) for the MCP stdio server.

```bash
vultrino serve [OPTIONS]

Options:
  -b, --bind <ADDR>    Bind address for the legacy stub [default: 127.0.0.1:7878]
  --mcp                Start as MCP server (stdio transport) — same as `vultrino mcp`
```

**Examples:**
```bash
# Start MCP server for AI agents
vultrino serve --mcp   # equivalently: vultrino mcp

# `vultrino serve` alone does NOT serve the API — use `vultrino web` instead
```

---

### `web`

Start the HTTP JSON API and web administration UI (the same process serves both,
plus the `/mcp` and `/llm` connector routes).

```bash
vultrino web [OPTIONS]

Options:
  -b, --bind <ADDR>    Bind address [default: 127.0.0.1:7879]
```

**Example:**
```bash
vultrino web
# API + Web UI available at http://127.0.0.1:7879
```

---

### `request`

Make an authenticated HTTP request.

```bash
vultrino request [OPTIONS] <CREDENTIAL> <URL>

Arguments:
  <CREDENTIAL>                Credential alias to use for authentication
  <URL>                       Target URL

Options:
  -X, --method <METHOD>       HTTP method [default: GET]
  -H, --header <HEADER>       Additional headers (can be repeated)
  -d, --data <DATA>           Request body (JSON string, or @filename to read from a file)
  -q, --quiet                 Output only the response body (no status info)
```

**Examples:**
```bash
# Simple GET request (credential alias is the first positional argument)
vultrino request github-api https://api.github.com/user

# POST with JSON body
vultrino request stripe-api \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "currency": "usd"}' \
  https://api.stripe.com/v1/charges

# Body only
vultrino request api-key https://api.example.com/data --quiet
```

---

### `role`

Manage RBAC roles.

```bash
vultrino role <SUBCOMMAND>

Subcommands:
  create    Create a new role
  list      List all roles
  get       Get role details
  delete    Delete a role
```

**Create a role:**
```bash
vultrino role create <NAME> [OPTIONS]

Options:
  -p, --permissions <PERMS>    Comma-separated: read,write,update,delete,execute
  -s, --scopes <SCOPES>        Credential patterns (glob): "github-*,stripe-*"
  -d, --description <DESC>     Role description
```

**Examples:**
```bash
# Create read-only role
vultrino role create readonly --permissions read

# Create role for GitHub credentials only
vultrino role create github-executor \
  --permissions read,execute \
  --scopes "github-*" \
  --description "Execute requests with GitHub credentials"

# List roles
vultrino role list

# Delete role
vultrino role delete old-role
```

---

### `key`

Manage API keys for programmatic access.

```bash
vultrino key <SUBCOMMAND>

Subcommands:
  create    Create a new API key
  list      List all API keys
  revoke    Revoke an API key
```

**Create an API key:**
```bash
vultrino key create <NAME> [OPTIONS]

Options:
  -r, --role <ROLE>           Role to assign (required)
  -e, --expires <DURATION>    Expiration (e.g., "30d", "1y")
```

**Examples:**
```bash
# Create key with role
vultrino key create my-app --role github-executor
# Created API key: vk_a1b2c3d4e5f6...
# (Save this key - it won't be shown again)

# Create key with expiration
vultrino key create temp-key --role readonly --expires 7d

# List keys
vultrino key list

# Revoke key
vultrino key revoke vk_a1b2c3d4
```

---

### `completions`

Generate shell completions.

```bash
vultrino completions <SHELL>

Shells:
  bash, zsh, fish, powershell
```

**Examples:**
```bash
# Bash
vultrino completions bash > /etc/bash_completion.d/vultrino

# Zsh
vultrino completions zsh > ~/.zfunc/_vultrino

# Fish
vultrino completions fish > ~/.config/fish/completions/vultrino.fish
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Credential not found |
| 4 | Permission denied |
| 5 | Storage error |

## Tips

### Use Aliases

Add to your shell profile:
```bash
alias vreq='vultrino request'
alias vcred='vultrino list'
```

### Store Password Securely

On macOS, use Keychain:
```bash
security add-generic-password -a vultrino -s vultrino -w "your-password"
export VULTRINO_PASSWORD=$(security find-generic-password -a vultrino -s vultrino -w)
```

On Linux, use a secrets manager or environment file:
```bash
# ~/.vultrino-env (chmod 600)
export VULTRINO_PASSWORD="your-password"

# In shell profile
source ~/.vultrino-env
```
