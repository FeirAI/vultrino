# Configuration

Vultrino uses a TOML configuration file located at:

- **macOS:** `~/Library/Application Support/vultrino/config.toml`
- **Linux:** `~/.config/vultrino/config.toml`
- **Windows:** `%APPDATA%\vultrino\config.toml`

## Default Configuration

```toml
# Vultrino Configuration

[server]
bind = "127.0.0.1:7878"
mode = "local"

[storage]
backend = "file"

[storage.file]
path = "~/.local/share/vultrino/credentials.enc"

[logging]
level = "info"
# audit_file = "~/.local/share/vultrino/audit.log"

[mcp]
enabled = true
transport = "stdio"
```

## Configuration Options

### Server Section

```toml
[server]
bind = "127.0.0.1:7878"  # Address for HTTP proxy
mode = "local"            # "local" or "server"
# trusted_proxies = ["127.0.0.1", "10.0.0.0/8"]
```

| Option | Description | Default |
|--------|-------------|---------|
| `bind` | Address and port for the HTTP proxy | `127.0.0.1:7878` |
| `trusted_proxies` | Reverse proxies (IPs or CIDR blocks) whose `X-Forwarded-For`/`X-Real-IP` headers are trusted for client-IP attribution (login rate limiting). When empty (default), forwarding headers are ignored and the direct socket address is used. | `[]` |
| `mode` | Deployment mode (`local` or `server`) | `local` |

### Storage Section

```toml
[storage]
backend = "file"  # Storage backend: "file", "keychain", or "vault"

[storage.file]
path = "~/.local/share/vultrino/credentials.enc"
```

| Option | Description | Default |
|--------|-------------|---------|
| `backend` | Storage backend type | `file` |
| `path` | Path to encrypted credentials file | OS-specific |

### Logging Section

```toml
[logging]
level = "info"  # Log level: error, warn, info, debug, trace
# audit_file = "~/.local/share/vultrino/audit.log"  # Optional audit log
```

| Option | Description | Default |
|--------|-------------|---------|
| `level` | Logging verbosity | `info` |
| `audit_file` | Path to audit log (optional) | disabled |

### MCP Section

```toml
[mcp]
enabled = true
transport = "stdio"  # "stdio" or "http"
```

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable MCP server | `true` |
| `transport` | Transport method | `stdio` |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VULTRINO_PASSWORD` | Storage encryption password (avoids prompts) |
| `VULTRINO_CONFIG` | Path to config file |
| `RUST_LOG` | Override log level (e.g., `vultrino=debug`) |

## Policy Configuration

Policies control which requests are allowed for each credential:

```toml
[[policies]]
name = "github-readonly"
credential_pattern = "github-*"  # Glob pattern for credential aliases
default_action = "deny"

[[policies.rules]]
condition = { url_match = "https://api.github.com/*" }
action = "allow"

[[policies.rules]]
condition = { method_match = ["POST", "PUT", "DELETE"] }
action = "deny"
```

See [Policy Configuration](../guides/policies.md) for detailed policy options.

## Using a Custom Config File

```bash
vultrino --config /path/to/config.toml list
```

## Regenerating Configuration

To reset to defaults:

```bash
vultrino init --force
```

> **Warning:** This will overwrite your existing configuration and require re-entering admin credentials.
