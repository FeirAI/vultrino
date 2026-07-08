# Local Development

The simplest way to run Vultrino — perfect for personal use and development.

## Quick Setup

```bash
# 1. Initialize
vultrino init

# 2. Add credentials
vultrino add --alias github-api --key ghp_xxx

# 3. Start services
vultrino web &          # HTTP API + web UI on :7879
vultrino mcp            # MCP server (stdio) for AI agents
```

## Running Components

### HTTP API + Web UI

The `web` process serves the JSON API (`/api/v1/…`), the connector routes
(`/mcp`, `/llm`), and the HTML admin UI on one port:

```bash
export VULTRINO_PASSWORD="your-password"
vultrino web
# Access at http://127.0.0.1:7879
```

### MCP Server Only

For local AI agent integration over stdio:

```bash
export VULTRINO_PASSWORD="your-password"
vultrino mcp   # equivalently: vultrino serve --mcp
```

> `vultrino serve` on its own does **not** start an API server (it's a stub that
> redirects you to `vultrino web`). Use `vultrino web` for HTTP.

## Configuration for Local Use

The default configuration is optimized for local development:

```toml
[server]
mode = "local"

[storage]
backend = "file"
```

## Using with Claude Desktop

Add to your Claude Desktop MCP configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

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

## Running as Background Process

### macOS (launchd)

Create `~/Library/LaunchAgents/dev.vultrino.web.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.vultrino.web</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vultrino</string>
        <string>web</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>VULTRINO_PASSWORD</key>
        <string>your-password</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load it:
```bash
launchctl load ~/Library/LaunchAgents/dev.vultrino.web.plist
```

### Linux (systemd user service)

Create `~/.config/systemd/user/vultrino-web.service`:

```ini
[Unit]
Description=Vultrino Web UI
After=network.target

[Service]
Type=simple
Environment="VULTRINO_PASSWORD=your-password"
ExecStart=/usr/local/bin/vultrino web
Restart=always

[Install]
WantedBy=default.target
```

Enable and start:
```bash
systemctl --user enable vultrino-web
systemctl --user start vultrino-web
```

## Tips

1. **Store password in keychain** — Use OS keychain to avoid plaintext passwords
2. **Use aliases** — Add `alias vreq='vultrino request'` to your shell
3. **Tab completion** — Generate with `vultrino completions bash > /etc/bash_completion.d/vultrino`

## Troubleshooting

### "Device not configured" error
The password prompt requires a terminal. Set `VULTRINO_PASSWORD` environment variable instead.

### "Address already in use"
Another process is using the port. Check with:
```bash
lsof -i :7879
```

### Credentials not loading
Ensure you're using the same `VULTRINO_PASSWORD` that was used when creating credentials.
