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
- **Use Tokens** — Single-use or time-scoped grants that let an agent perform one specific action
- **Action Approvals** — Human-in-the-loop sign-off (admin panel, Telegram, or webhook/email) before an action runs
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
vultrino meta set <alias> allowed_hosts "api.github.com, *.example.com"  # restrict destinations
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

# Use Tokens (single-use / time-scoped agent grants)
vultrino token create deploy-once \              # one-shot, expires in 10 minutes
  --credential "deploy-*" --action ssh.deploy --uses 1 --expires 10m
vultrino token create reporter \                 # time-scoped, unlimited uses for 24h
  --credential github-api --action http.request --expires 24h
vultrino token create risky --credential prod-db --require-approval  # gate every use
vultrino token list
vultrino token revoke <id|prefix|name>

# Action Approvals (human-in-the-loop)
vultrino approval list                           # see pending/decided requests
vultrino approval status <id>                    # show status; runs it if approved
vultrino approval status <id> --wait             # block until decided, then return result
vultrino approval approve <id>
vultrino approval deny <id>

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
- `check_approval` — Poll a pending action approval and retrieve its result once approved
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

## Use Tokens

A **use token** is a narrow, ephemeral grant — the opposite of a durable API key.
It authorizes *one kind of action* against *one credential (or glob)*, optionally
capped to a number of uses and/or a time window. Hand it to an agent in the same
place as an API key (the `api_key` field, or `Authorization: Bearer`); it is
recognized by its `vut_` prefix.

```bash
# "POST to the deploy webhook once, in the next 10 minutes"
vultrino token create deploy-once \
  --credential deploy-hook --action http.request --uses 1 --expires 10m
# Output: vut_xxxxxxxx... (shown once)
```

- **Single-use** (`--uses 1`) or **limited-use** (`--uses N`); omit for unlimited.
- **Time-scoped** with `--expires` (`30m`, `24h`, `7d`; omit for never).
- **Scoped** to a credential glob (`--credential`) and optionally a single action
  or `plugin.*` glob (`--action`).
- Uses are counted **fail-closed**: the use is spent the moment the action runs,
  even if the downstream call errors, so a single-use token can never run twice.
- Add `--require-approval` to gate every use behind a human decision (below).

Manage tokens in the **Use Tokens** page of the web UI or with
`vultrino token list` / `vultrino token revoke`.

## Action Approvals

Some actions are too consequential to let an agent run unsupervised. Mark them and
Vultrino will pause for a human before the action executes — the agent never sees
the result until someone signs off.

**What triggers approval** (any of):
- A credential flagged with `vultrino meta set <alias> require_approval true`
- A use token created with `--require-approval`
- A matching policy rule with `action = "prompt"`

**How it works (and what the agent sees):**

1. The agent calls a tool. Instead of a result it gets a clear **"APPROVAL
   REQUIRED"** message with an `approval_id` — the action has *not* run.
2. The agent polls the `check_approval` MCP tool (or `GET /api/v1/approvals/{id}`,
   or `vultrino approval status <id> --wait`) with that id.
3. A human approves or denies it — in the **Approvals** page of the admin panel,
   via a **Telegram** button, or via a link delivered by **webhook/email**.
4. Once approved, the next poll runs the action and returns the real result. If
   denied or expired, the agent is told to stop.

Configure out-of-band notifications under `[approvals]` in `config.toml`:

```toml
[approvals]
enabled = true
ttl_secs = 3600                                   # auto-expire undecided requests
public_base_url = "https://vultrino.example.com"  # used in approve/deny links

[approvals.telegram]                              # inline Approve/Deny buttons
bot_token = "123456:ABC-DEF..."
chat_id = "987654321"

[approvals.webhook]                               # POST to any URL (email/Slack/...)
url = "https://hooks.example.com/vultrino-approvals"
auth_header = "Bearer your-webhook-secret"
```

Out-of-band links carry a single-use capability token and open a confirmation
page (a link prefetch can't auto-decide), so the admin panel session is never
required to approve from Telegram/email.

**Notes & guarantees:**
- Single-use/limited-use tokens are enforced **fail-closed** with a cross-process
  file lock, so a token can never drive more than `max_uses` executions even
  when the web and MCP servers run as separate processes sharing one vault.
- Approved actions execute **at most once**: execution is claimed atomically, a
  crashed mid-execution claim is auto-recovered after a timeout, and a transient
  pre-execution failure (e.g. a plugin not yet loaded) is retried rather than
  marked done.
- An agent may only poll approvals created by the **same principal** (API key or
  use token) that made the original request.
- Set `public_base_url` to an **HTTPS** address so Telegram/email approve-deny
  links are confidential, and avoid running the web server at `DEBUG` log level
  in production (request URIs, which carry the link's capability token, are
  logged at `DEBUG`).
- A use token's *pending* approvals are **bounded**: `uses + outstanding pending
  approvals` can never exceed `max_uses`, checked-and-inserted atomically under
  the vault lock. So a single-use token can't flood the approval queue (or the
  Telegram/webhook notifier) with requests it could never run.
- Policy is **re-evaluated when the action finally runs**, so an explicit deny
  rule (URL / method / time-window) still blocks even a human-approved action.
  Rate limits are charged **once, at request time** — a human approval is never
  re-charged against, nor re-denied by, the rate limiter at execution time. When
  a deny does fire on resume, the use token is left unconsumed.

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

> The web / JSON-API server scans and loads plugins **once at startup** (for
> per-request performance). After installing a plugin, **restart the web server**
> so the API picks it up. The CLI and MCP entry points load plugins on launch, so
> they see newly installed plugins on their next invocation.

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

### Agent-boundary protections

- **Egress redaction** — any injected credential material found in an upstream
  response (e.g. an echo/reflector endpoint returning the request headers) is
  replaced with `[REDACTED:vultrino]` before the response reaches the agent.
- **No automatic redirects** — proxied requests do not follow 3xx responses;
  the status and `Location` header are returned to the caller, and a new
  request to the new target is re-validated (SSRF + policy) from scratch.
- **Per-credential host binding** — set `vultrino meta set <alias>
  allowed_hosts "api.github.com, *.example.com"` to restrict which hosts a
  credential may ever be sent to, independent of policy configuration.
- **Immediate revocation** — API keys are validated against storage on every
  call, so `vultrino auth revoke` takes effect immediately in running web/MCP
  servers (matching use-token semantics).
- **Sandboxed plugins** — WASM plugins run with no filesystem, network, env,
  or stdio access, a CPU (fuel) budget, a memory cap, and a wall-clock
  timeout, and execute off the async runtime.
- **Response/size limits** — upstream responses are capped at 10 MB and all
  outbound requests carry timeouts, so a hostile upstream cannot hang or
  OOM the proxy.

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
