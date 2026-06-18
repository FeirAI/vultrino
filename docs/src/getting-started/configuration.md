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
```

| Option | Description | Default |
|--------|-------------|---------|
| `bind` | Address and port for the HTTP proxy | `127.0.0.1:7878` |
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

### Enforcement Section

Controls what the policy engine decides for a credential that matches **no**
policy at all.

```toml
[enforcement]
default_action = "deny"  # "deny" (fail-closed, default) or "allow" (fail-open)
```

| Option | Description | Default |
|--------|-------------|---------|
| `default_action` | Decision for a credential matched by no policy: `deny` or `allow` | `deny` |

With `deny` (the default, and the recommended posture for shared/server
deployments), an un-policied credential is denied with a distinct `no_policy`
reason — closing the historical fail-open gap. Use `allow` for the legacy
behavior where an un-policied credential is permitted. If the section is omitted
the built-in default is `deny`. The config produced by `vultrino init` also
ships with `deny` and prints a reminder that you must add an allow policy (or
switch to `allow`) before credentials will work.

> When `default_action = "deny"` and no policies are configured, **every**
> credential is denied. Vultrino logs a loud warning at startup in this case
> (and the symmetric `allow` + no-policies fail-open case is warned about too).

#### Upgrading (breaking change)

Before this change the engine was fail-**open**: a credential matching no policy
was allowed. It is now fail-**closed** by default. A config that has **no**
`[enforcement]` section will start denying un-policied credentials after upgrade.
To preserve the pre-upgrade behavior, add:

```toml
[enforcement]
default_action = "allow"
```

Otherwise, add allow policies for the credentials your agents legitimately use.

### Spend Extractors

For `SpendCap` policies (V3), Vultrino needs to know where the amount lives in
the request body. Each extractor matches an action + credential and reads the
amount (an integer in minor units, e.g. cents) from a JSON pointer, plus an
asset (literal or a second pointer).

```toml
[[spend_extractors]]
action_pattern = "http.request"     # glob over plugin.action
credential_pattern = "stripe-*"     # glob over credential alias
amount_pointer = "/body/amount"     # JSON pointer to the integer amount
asset = "usd"                        # literal asset...
# asset_pointer = "/body/currency"  # ...or read it from the body
```

If a `SpendCap` policy applies to a credential but no extractor yields an amount
(missing extractor or unparseable body), the request is **denied** (fail-closed)
and a `spend_unparseable` warning is logged.

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
