# Deployment Overview

Vultrino can be deployed in several ways depending on your needs:

## Deployment Options

| Method | Best For | Complexity |
|--------|----------|------------|
| [Local Development](./local.md) | Personal use, testing | Simple |
| [VPS / Server](./vps.md) | Team deployment, production | Moderate |
| [Cloudflare Workers](./cloudflare.md) | Edge deployment, serverless | Moderate |
| [Docker](./docker.md) | Containerized environments | Simple |

## Architecture Considerations

### Single Binary
Vultrino is distributed as a single binary with no external dependencies. This includes:
- CLI commands
- HTTP proxy server
- Web UI (embedded)
- MCP server

### Storage
Credentials are stored encrypted using AES-256-GCM. Storage options:
- **File** (default): an encrypted vault snapshot plus its write-ahead log on disk
- **Keychain** — OS keychain integration (coming soon)
- **Vault** — HashiCorp Vault integration (coming soon)

### Network Security

**Local Mode (default):**
- `vultrino web` listens on `127.0.0.1:7879` unless you pass `--bind`; the mode itself does not restrict the listen address
- The session cookie has no Secure flag, so plain-HTTP login on localhost works
- Suitable for single-machine use

**Server Mode (`[server] mode = "server"`):**
- Turns on the Secure session cookie and HSTS, assuming a TLS-terminating reverse proxy (nginx, Caddy) in front
- Does not change the listen address; Vultrino has no built-in TLS and serves plain HTTP
- Requires additional security measures

## Security Recommendations

1. **Always use HTTPS in production** — Use a reverse proxy with TLS
2. **Restrict network access** — Firewall rules, VPN, or private network
3. **Use strong passwords** — Both storage and admin passwords
4. **Retain the event outbox** outside Vultrino (push it to `[outbox] url` or poll `GET /api/v1/events`); there is no audit log file to enable
5. **Rotate API keys** — Set expiration on Vultrino API keys
6. **Principle of least privilege** — Create scoped roles for each application

## Quick Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOCAL                                     │
│  vultrino web  (+ vultrino mcp for AI agents)                    │
│  ├── Best for: Personal use, development                        │
│  ├── Security: Localhost only                                   │
│  └── Setup: Minimal                                              │
├─────────────────────────────────────────────────────────────────┤
│                        VPS/SERVER                                │
│  vultrino web + nginx/caddy                                     │
│  ├── Best for: Team use, production                             │
│  ├── Security: TLS, firewall, auth                              │
│  └── Setup: Moderate (systemd, reverse proxy)                   │
├─────────────────────────────────────────────────────────────────┤
│                        CLOUDFLARE                                │
│  Cloudflare Workers + KV/Durable Objects                        │
│  ├── Best for: Edge deployment, global access                   │
│  ├── Security: Cloudflare's infrastructure                      │
│  └── Setup: Moderate (requires adaptation)                      │
├─────────────────────────────────────────────────────────────────┤
│                        DOCKER                                    │
│  docker run vultrino                                            │
│  ├── Best for: Containerized environments                       │
│  ├── Security: Container isolation                              │
│  └── Setup: Simple (docker-compose)                             │
└─────────────────────────────────────────────────────────────────┘
```

## Next Steps

Choose your deployment method:
- [Local Development](./local.md) — Start here for testing
- [VPS / Server](./vps.md) — Production deployment
- [Cloudflare Workers](./cloudflare.md) — Edge/serverless deployment
- [Docker](./docker.md) — Container deployment
