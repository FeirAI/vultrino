# Vultrino

**A credential proxy for the AI era** — enabling AI agents to use credentials without seeing them.

## What is Vultrino?

Vultrino is a secure credential proxy that allows AI agents, LLMs, and automated systems to make authenticated API requests without ever exposing the actual credentials. Instead of giving your AI agent direct access to API keys, you give it access to Vultrino, which injects the authentication on behalf of the agent.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│    Vultrino     │────▶│   External API  │
│   (Claude, etc) │     │   (injects auth)│     │   (GitHub, etc) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │ "Use github-api       │ Authorization: Bearer ghp_xxx...
        │  credential"          │
        ▼                       ▼
   Never sees the key     Handles authentication
```

## Features

- **Credential Isolation** — AI agents never see actual API keys or secrets
- **Role-Based Access Control** — Fine-grained permissions with credential scoping
- **Multiple Credential Types** — API keys, Basic Auth, OAuth2 (with automatic token refresh), and extensible via plugins
- **OAuth2 Support** — Client credentials and refresh token flows with automatic token refresh
- **Scoped API Keys** — Restrict which credentials each API key can access using glob patterns
- **Plugin System** — Extend with custom credential types and actions via WASM plugins
- **MCP Integration** — Native Model Context Protocol support for LLM tools
- **Web UI** — Clean admin interface for managing credentials, roles, and API keys
- **Encrypted Storage** — AES-256-GCM encryption with Argon2 key derivation
- **Policy Engine** — URL patterns, method restrictions, rate limiting
- **Audit Logging** — Track all credential usage

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/zachyking/vultrino.git
cd vultrino

# Build release binary
cargo build --release

# Install to path (optional)
cp target/release/vultrino ~/.local/bin/
```

### Requirements

- Rust 1.75+
- OpenSSL development libraries

## Quick Start

### 1. Initialize Storage

```bash
# Set your encryption password
export VULTRINO_PASSWORD="your-secure-password"

# Add your first credential
vultrino add --alias github-api --key ghp_your_token_here
```

### 2. Make Authenticated Requests

```bash
# Make a request using the credential
vultrino request github-api https://api.github.com/user
```

### 3. Start the Web UI

```bash
# Start the admin interface
vultrino web

# Open http://127.0.0.1:7879 in your browser
```

### 4. Use with AI Agents (MCP)

```bash
# Start MCP server for LLM integration
vultrino serve --mcp
```

## Usage

### CLI Commands

```bash
# Credential Management
vultrino add --alias <name> --key <api-key>    # Add API key credential
vultrino add --alias <name> -t basic_auth      # Add basic auth (interactive)
vultrino add --alias <name> -t oauth2 \        # Add OAuth2 credential
  --client-id <id> --client-secret <secret> \
  --token-url https://oauth.example.com/token \
  --scopes "read,write"
vultrino add --alias <name> -t ssh_password \  # Add SSH (password) credential
  --ssh-host <host> --ssh-user <user>          # for ssh plugin deploy/run
vultrino add --alias <name> -t postgres \      # Add Postgres credential
  --pg-host <host> --pg-database <db> \        # for postgres plugin run_sql/backup
  --pg-user <user> --pg-sslmode require
vultrino list                                   # List all credentials
vultrino remove <alias>                         # Remove a credential

# Per-credential defaults (non-secret configuration)
vultrino meta set <alias> <key> <value>         # e.g. deploy.source_dir, run.commands
vultrino meta list <alias>                      # Show all metadata for a credential
vultrino meta unset <alias> <key>               # Remove a metadata key

# Making Requests
vultrino request <alias> <url>                  # GET request
vultrino request <alias> <url> -X POST -d '{}'  # POST with body

# Plugin Actions
vultrino action <credential> <plugin.action>    # Execute plugin action
vultrino action my-pgp pgp-signing.sign_cleartext -p '{"data":"Hello"}'
vultrino action my-server ssh.deploy            # Rsync via stored SSH credential
vultrino action my-server ssh.run               # Run a configured command sequence
vultrino action my-db postgres.run_sql          # Apply the configured migration script
vultrino action my-db postgres.backup           # pg_dump to the configured output dir

# Plugin Management
vultrino plugin install <path-or-url>           # Install a plugin
vultrino plugin list                            # List installed plugins
vultrino plugin info <name>                     # Show plugin details
vultrino plugin remove <name>                   # Remove a plugin

# Role & API Key Management
vultrino role create <name> --permissions read,execute --scopes "github-*"
vultrino role list
vultrino key create <name> --role <role-name>
vultrino key list

# Server Modes
vultrino web                                    # Start web UI
vultrino serve --mcp                            # Start MCP server
```

### Web UI

The web interface provides:

- **Dashboard** — Overview of credentials and recent activity
- **Credentials** — Add, edit, and remove credentials
- **API Keys** — Manage access keys for external applications
- **Roles** — Configure role-based access control
- **Audit Log** — View credential usage history

### OAuth2 Credentials

Vultrino supports OAuth2 with automatic token refresh for machine-to-machine authentication:

```bash
# Add OAuth2 credential via CLI
vultrino add --alias my-oauth2 -t oauth2 \
  --client-id your-client-id \
  --client-secret your-client-secret \
  --token-url https://oauth.example.com/token \
  --scopes "api,read,write"

# With optional refresh token (for providers that issue them upfront)
vultrino add --alias my-oauth2 -t oauth2 \
  --client-id your-client-id \
  --client-secret your-client-secret \
  --token-url https://auth.provider.com/token \
  --refresh-token your-refresh-token
```

**Supported Grant Types:**
- `client_credentials` — Machine-to-machine API access (default)
- `refresh_token` — Use refresh token to obtain new access token

**Automatic Token Refresh:**
- Vultrino automatically fetches tokens before the first request
- Tokens are refreshed 5 minutes before expiration
- Updated tokens are persisted to storage automatically
- If refresh token flow fails, falls back to client credentials

**Security:**
- Token URLs must use HTTPS
- SSRF protection prevents token endpoints pointing to internal IPs
- Client secrets are encrypted at rest

### Scoped API Keys

API keys can be scoped to only access specific credentials using glob patterns:

```bash
# Create a role with credential scoping
vultrino role create github-only \
  --permissions read,execute \
  --scopes "github-*" \
  --description "Can only access GitHub credentials"

# Create an API key with this role
vultrino key create github-agent --role github-only
# Output: vk_abc123...

# This key can only access credentials matching "github-*"
```

**Scope Patterns:**
- `github-*` — Matches `github-api`, `github-org`, etc.
- `*-prod` — Matches `aws-prod`, `stripe-prod`, etc.
- `oauth2-*` — Matches all OAuth2 credentials
- Empty scopes (default) — Access all credentials

**Using Scoped Keys:**

```bash
# CLI: Pass the API key with -k flag
vultrino -k vk_abc123... request github-api https://api.github.com/user

# MCP: Include api_key in tool arguments
{"name": "http_request", "arguments": {
  "api_key": "vk_abc123...",
  "credential": "github-api",
  "method": "GET",
  "url": "https://api.github.com/user"
}}
```

### MCP Integration

Vultrino provides native MCP (Model Context Protocol) support for AI agent integration:

```bash
# Start MCP server
vultrino serve --mcp

# Or use the dedicated mcp command
vultrino mcp
```

Available MCP tools:
- `http_request` — Make authenticated HTTP requests
- `list_credentials` — List available credentials
- `get_credential_info` — Get credential metadata
- Plugin tools (e.g., `pgp_sign`, `pgp_verify`)

**Example MCP Request:**
```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "http_request",
  "arguments": {
    "api_key": "vk_your_api_key",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}}
```

## Plugin System

Vultrino ships with built-in plugins and also supports WASM plugins for extending functionality with custom credential types and actions.

### Built-in Plugins

| Plugin    | Credential Types                  | Actions                                  |
|-----------|-----------------------------------|------------------------------------------|
| `http`    | `api_key`, `basic_auth`, `oauth2` | `request`                                |
| `hmac`    | `hmac_api_key`                    | `request`, `sign`                        |
| `ecdsa`   | `ecdsa_key`                       | `sign`, `sign_l1_action`                 |
| `ssh`     | `ssh_password`                    | `deploy` (rsync), `run` (remote exec)    |
| `postgres`| `postgres`                        | `run_sql` (migrations/maintenance), `backup` (pg_dump) |

The `ssh` plugin requires `sshpass`, `ssh`, and `rsync` on the host's `PATH`. See [the SSH plugin docs](docs/src/plugins/ssh.md) for the full credential schema, metadata keys, override-lock model, and a worked deploy + restart example.

The `postgres` plugin requires `psql` and `pg_dump` (from `postgresql-client` or Homebrew's `libpq`). See [the Postgres plugin docs](docs/src/plugins/postgres.md) for the credential schema, metadata keys, SQL-override lock model, and a worked migration + nightly-backup example.

### Installing Plugins

```bash
# From local path
vultrino plugin install ./plugins/pgp-signing

# From git URL
vultrino plugin install https://github.com/user/vultrino-plugin-example
```

### Example: PGP Signing Plugin

The included PGP signing plugin adds:

**Credential Type:** `pgp_key`
- Private key (PEM/ASCII-armored)
- Optional passphrase

**Actions:**
- `sign` — Create detached signature
- `sign_cleartext` — Create cleartext signed message
- `verify` — Verify a signature
- `get_public_key` — Extract public key

```bash
# Install the plugin
vultrino plugin install ./plugins/pgp-signing

# Add a PGP credential via web UI or create via plugin

# Sign a message
vultrino action my-pgp pgp-signing.sign_cleartext -p '{"data":"Hello, World!"}'
```

### Developing Plugins

Plugins are WASM modules with a `plugin.toml` manifest:

```toml
[plugin]
name = "my-plugin"
version = "1.0.0"
description = "My custom plugin"
format = "wasm"
wasm_module = "plugin.wasm"

[[credential_types]]
name = "my_credential"
display_name = "My Credential Type"

[[credential_types.fields]]
name = "secret_field"
label = "Secret Field"
type = "password"
required = true
secret = true

[[actions]]
name = "my_action"
description = "Does something useful"

[[mcp_tools]]
name = "my_tool"
description = "MCP tool for AI agents"
action = "my_action"
```

Build with:
```bash
cargo build --release --target wasm32-wasip1
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VULTRINO_PASSWORD` | Storage encryption password | Required (or prompts / `VULTRINO_PASSWORD_FILE`) |
| `VULTRINO_PASSWORD_FILE` | Path to a file containing the storage password. Useful for unattended agents — `chmod 600` it; trailing newline is stripped. Ignored if `VULTRINO_PASSWORD` is also set. | — |
| `VULTRINO_DATA_DIR` | Data directory path | `~/.vultrino` or platform default |

### Storage Location

- **macOS**: `~/Library/Application Support/vultrino/`
- **Linux**: `~/.local/share/vultrino/`
- **Windows**: `%APPDATA%\vultrino\`

## Security

### Encryption

- Credentials encrypted with AES-256-GCM
- Key derived using Argon2id
- Each credential has unique nonce

### Credential Types

| Type | Description | Authentication Method |
|------|-------------|----------------------|
| `api_key` | API key/token | Header injection (default: `Authorization: Bearer <key>`) |
| `basic_auth` | Username/password | Base64 encoded `Authorization: Basic` header |
| `oauth2` | OAuth2 client credentials | Automatic token fetch/refresh, `Authorization: Bearer <token>` |
| `hmac_api_key` | HMAC-signed API key (e.g. Binance-style exchanges) | SHA-256 signature over query string / body |
| `ecdsa_key` | ECDSA private key (Ethereum / Hyperliquid) | On-the-fly signing of requests or arbitrary payloads |
| `ssh_password` | SSH host + password (for `ssh` plugin) | `sshpass`-fed password to `ssh` / `rsync`; password never leaves Vultrino |
| `postgres` | PostgreSQL connection (for `postgres` plugin) | Password passed to `psql`/`pg_dump` via `PGPASSWORD` env; never leaves Vultrino |

### Best Practices

1. Use a strong `VULTRINO_PASSWORD`
2. Restrict file permissions on data directory
3. Use role-based access control for multi-user setups
4. Enable audit logging in production
5. Review plugin code before installation
6. Use scoped API keys to limit AI agent access to specific credentials
7. For OAuth2, prefer HTTPS token endpoints and rotate secrets regularly

## Architecture

```
src/
├── auth/       # Authentication & authorization
├── config/     # Configuration management
├── crypto/     # Encryption & key derivation
├── mcp/        # Model Context Protocol server
├── plugins/    # Plugin system & WASM runtime
├── policy/     # Policy engine & rate limiting
├── router/     # Credential routing
├── server/     # HTTP proxy server
├── storage/    # Encrypted storage backend
└── web/        # Web UI (Axum + Askama)
```

## Documentation

Full documentation available in the `docs/` directory:

- [Getting Started](docs/src/getting-started/)
- [API Reference](docs/src/api/)
- [Plugin Development](docs/src/plugins/)
- [Deployment Guide](docs/src/deployment/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read the contributing guidelines before submitting PRs.
