# Vultrino

> **A credential proxy for the AI era** — enabling AI agents to use credentials without seeing them.

## What is Vultrino?

Vultrino is a secure credential proxy that allows AI agents, LLMs, and automated systems to use credentials without ever exposing them. Instead of giving your AI agent direct access to secrets, you give it access to Vultrino, which performs authenticated actions on behalf of the agent — whether that's making API calls, signing data with PGP keys, or any other credential-based operation.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│    Vultrino     │────▶│  External API   │
│   (Claude, etc) │     │ (uses secrets)  │     │  or Operation   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │ "Use my-credential"   │ Injects auth, signs data, etc.
        │                       │
        ▼                       ▼
   Never sees secrets    Performs secure actions
```

## Key Features

- **Credential Isolation** — AI agents never see actual secrets or private keys
- **Role-Based Access Control** — Fine-grained permissions for different applications
- **Multiple Credential Types** — API keys, Basic Auth, PGP keys, and more
- **Plugin System** — Extend with custom credential types and actions via WASM plugins
- **MCP Integration** — Native Model Context Protocol support for LLM tools
- **Web UI** — Clean admin interface for managing credentials and keys
- **Encrypted Storage** — AES-256-GCM encryption with Argon2 key derivation
- **Policy Engine** — URL patterns, method restrictions, rate limiting
- **Audit Logging** — Track all credential usage

## Use Cases

### AI Agent Security
Give Claude, GPT, or other AI agents the ability to call APIs without exposing credentials. The agent requests actions through Vultrino, which handles authentication transparently.

### Team Credential Management
Centralize API credentials for your team. Create scoped API keys for different applications with specific permissions.

### Development Environments
Safely share credentials across development, staging, and production without exposing secrets in code or environment variables.

## Quick Example

```bash
# Add a credential
vultrino add --alias github-api --key ghp_your_token_here

# Make an authenticated request
vultrino request github-api https://api.github.com/user

# Or use with AI agents via MCP
vultrino serve --mcp
```

## Components

| Component | Description |
|-----------|-------------|
| **CLI** | Command-line interface for all operations |
| **Web UI** | Browser-based admin dashboard |
| **HTTP API** | `POST /api/v1/execute` runs authenticated requests on behalf of agents (served by `vultrino web`) |
| **MCP Server** | Model Context Protocol server for LLM integration |

## Next Steps

- [Installation](./getting-started/installation.md) — Get Vultrino running
- [Quick Start](./getting-started/quickstart.md) — Add your first credential
- [Using with AI Agents](./guides/ai-agents.md) — Configure LLM integration
- [Plugin System](./plugins/overview.md) — Extend with custom credential types
