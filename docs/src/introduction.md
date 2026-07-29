# Vultrino

> **A credential proxy for the AI era** — enabling AI agents to use credentials without seeing them.

## What is Vultrino?

Vultrino keeps raw credential fields out of agent-facing requests and performs authenticated operations inside trusted connectors. An agent receives aliases and action results rather than direct access to the stored secret.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│    Vultrino     │────▶│  External API   │
│   (Claude, etc) │     │ (uses secrets)  │     │  or Operation   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │ "Use my-credential"   │ Injects auth, signs data, etc.
        │                       │
        ▼                       ▼
   Alias-only request    Injects inside a trusted connector
```

## Key Features

- **Credential Isolation** — raw fields are absent from agent/MCP response schemas
- **Role-Based Access Control** — Fine-grained permissions for different applications
- **Multiple Credential Types** — API keys, Basic Auth, OAuth2, signing keys, and more
- **Plugin System** — Extend public-data actions through the credential-confining WASM ABI v2
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
