# Cloudflare Workers Deployment

> **Note:** Cloudflare Workers deployment requires adapting Vultrino to the Workers runtime. This guide covers the architecture and approach.

## Overview

Deploying Vultrino to Cloudflare Workers provides:
- Global edge deployment
- Serverless scaling
- Cloudflare's security infrastructure
- Low-latency access worldwide

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Cloudflare Edge                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────┐     ┌─────────────────────────────────┐   │
│   │  Workers        │     │  Durable Objects                │   │
│   │  (HTTP API)     │────▶│  (Session State, Credentials)   │   │
│   └─────────────────┘     └─────────────────────────────────┘   │
│           │                           │                          │
│           │                           ▼                          │
│           │               ┌─────────────────────────────────┐   │
│           │               │  KV                             │   │
│           │               │  (Encrypted Credential Storage) │   │
│           │               └─────────────────────────────────┘   │
│           │                                                      │
│           ▼                                                      │
│   ┌─────────────────┐                                           │
│   │  External APIs  │                                           │
│   │  (via fetch)    │                                           │
│   └─────────────────┘                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Components Mapping

| Vultrino Component | Cloudflare Equivalent |
|--------------------|-----------------------|
| Encrypted file storage | KV with encryption |
| Session management | Durable Objects |
| HTTP handlers | Workers |
| Static assets | Workers Sites or R2 |

## Implementation Approach

### 1. Create Worker Project

```bash
npm create cloudflare@latest vultrino-edge -- --template hello-world
cd vultrino-edge
```

### 2. Configure wrangler.toml

```toml
name = "vultrino"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[vars]
ENVIRONMENT = "production"

[[kv_namespaces]]
binding = "CREDENTIALS"
id = "your-kv-namespace-id"

[[durable_objects.bindings]]
name = "SESSIONS"
class_name = "SessionDO"

[[migrations]]
tag = "v1"
new_classes = ["SessionDO"]
```

### 3. Implement Core Logic

```typescript
// src/index.ts
import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Bindings = {
  CREDENTIALS: KVNamespace;
  SESSIONS: DurableObjectNamespace;
  ENCRYPTION_KEY: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Middleware
app.use('*', cors());

// Login
app.post('/login', async (c) => {
  const { username, password } = await c.req.json();
  // Verify credentials, create session
  // ...
});

// Execute request with credential (mirrors the shipped POST /api/v1/execute:
// a flat body with credential/method/url, not a nested `params` object)
app.post('/api/v1/execute', async (c) => {
  const { credential, method, url, headers, body } = await c.req.json();

  // Get encrypted credential from KV
  const encryptedCred = await c.env.CREDENTIALS.get(credential);
  if (!encryptedCred) {
    return c.json({ error: 'Credential not found' }, 404);
  }

  // Decrypt credential
  const cred = await decrypt(encryptedCred, c.env.ENCRYPTION_KEY);

  // Execute request with injected auth
  const response = await executeWithCredential(cred, { method, url, headers, body });

  return c.json(response);
});

export default app;
```

### 4. Credential Encryption

Use Web Crypto API for encryption:

```typescript
async function encrypt(data: string, key: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('vultrino-salt'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    derivedKey,
    encoder.encode(data)
  );

  // Return iv + ciphertext as base64
  return btoa(String.fromCharCode(...iv, ...new Uint8Array(encrypted)));
}
```

### 5. Deploy

```bash
# Set secrets
wrangler secret put ENCRYPTION_KEY
wrangler secret put ADMIN_PASSWORD_HASH

# Deploy
wrangler deploy
```

## Limitations

| Feature | Status | Notes |
|---------|--------|-------|
| HTTP Proxy | ✅ | Via fetch() |
| Web UI | ✅ | Workers Sites |
| MCP Server | ❌ | Requires stdio (not available) |
| File Storage | ⚠️ | Use KV instead |
| OS Keychain | ❌ | Not available |

## Security Considerations

1. **Secrets Management** — Use Wrangler secrets for encryption keys
2. **KV Encryption** — Always encrypt credentials before storing in KV
3. **Access Control** — Use Cloudflare Access for additional auth layer
4. **Audit Logging** — Log to Workers Analytics or external service

## Alternative: Hybrid Deployment

For MCP support, consider a hybrid approach:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  AI Agent       │────▶│  Local Vultrino │────▶│  Cloudflare     │
│  (MCP)          │     │  (MCP Server)   │     │  Vultrino Edge  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        Syncs credentials
                        from edge storage
```

This allows:
- MCP support via local instance
- Centralized credential management on edge
- Web UI accessible globally
