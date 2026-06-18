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

### Egress Controls

Vultrino keeps proxied responses from carrying secrets back to the agent (V7),
applied at the execution seam for **every** plugin:

1. **Always-on secret-material redaction.** If an endpoint reflects the
   credential's own injected secret in its response (a header-echoing reflector,
   an open redirect, etc.), the secret — and its common re-encoded forms
   (percent-encoded, JSON-escaped) — is scrubbed from the body and headers and
   replaced with `[REDACTED:<alias>]` before the response is returned. This is
   not configurable. It is defense-in-depth, not absolute: an endpoint that
   *transforms* the secret (base64, hashing, splitting it) — or returns a
   **compressed** body (the http plugin requests `Accept-Encoding: identity`,
   but a server may compress anyway) — can still leak it. Use a `block` rule for
   endpoints you don't trust. Secrets shorter than 5 bytes are not scrubbed (too
   little entropy to match safely); a warning is logged when such a credential
   is created.
2. **Egress classification.** For endpoints whose response is itself a secondary
   secret (an STS/login/secret-read endpoint), configure `[[egress]]` rules:

```toml
[[egress]]
credential_pattern = "sts-*"        # glob over credential alias
action_pattern = "http.request"     # glob over plugin.action (default "*")
block = true                         # withhold the body + headers entirely

[[egress]]
credential_pattern = "secrets-api-*"
redact_patterns = ['"token":\s*"[^"]+"', "AKIA[0-9A-Z]{16}"]  # extra regexes to redact
```

The first matching rule applies. `block = true` replaces the body with a marker
and drops the headers; otherwise any `redact_patterns` (regexes) are scrubbed
from the body (on top of the always-on redaction).

> **Downstream credentials.** Blocking/redacting prevents an agent from reading
> a downstream secret out of a response, but a `vut_` revoke does **not** revoke
> a secret the downstream already issued. Prefer credential types that mint
> short-lived, revocable downstream credentials (OAuth2 client-credentials, STS,
> SVIDs) so a revoke maps to a real resource-side revoke. OAuth2 in-path token
> rotation emits a `credential.rotated` event (delivered via the signed outbox).

### Action Labels

Map a govder **business verb** to a canonical `plugin.action` (V8), so use-token
scopes and the approval/audit trail can speak in business terms while vultrino
executes the underlying plugin action. (Policy *rules* match on
URL/method/credential/principal/spend — not on the action label — so the verb is
a scoping and audit concept, not a policy-condition one.)

```toml
[[action_labels]]
label = "payments.refund"   # what govder / a token scopes against
action = "http.request"     # the canonical plugin.action vultrino runs
```

A request (or use-token `action_scope`) may then use the label `payments.refund`;
it resolves to `http.request` for execution, the use-token scope is satisfied by
either the label or the canonical action, and the approver sees the business
verb in the approval. The typed `/api/v1/execute` endpoint also accepts an
optional `action` field (default `http.request`) so it is no longer hardwired.

### Event Outbox (V9)

Vultrino records security-relevant events to a durable, ordered, replayable,
**signed** outbox: approval requested/approved/denied/escalated/expired,
`agent.halted`, `policy.changed`, and `credential.rotated`. Configure push
delivery with `[outbox]`:

```toml
[outbox]
url = "https://govder.example.com/vultrino/events"  # delivery endpoint
hmac_secret = "shared-signing-secret"                # required to push (deliveries are signed)
max_attempts = 8                                      # retries before dead-lettering (default 8)
retention_secs = 604800                               # replay window, default 7 days
```

- **Ordered + monotonic.** Every event gets a process-global, gap-free
  `sequence`. Events for the same `subject` (e.g. an approval id) are delivered
  in order.
- **Signed.** Each delivery carries `Govder-Signature: sha256=<hex>` =
  `HMAC-SHA256(hmac_secret, body)`. A consumer recomputes it over the raw body
  to verify authenticity. Enabling the outbox **requires** both `url` and
  `hmac_secret` (an unsigned/undeliverable outbox is rejected at load).
- **Exactly-once-ish delivery across processes.** Each event is atomically
  *claimed* (leased) under the vault lock before it is POSTed, so the web and MCP
  processes can't both deliver it; a failed delivery backs off (the lease holds it
  off the retry queue) before re-attempting, and a crashed deliverer's lease is
  reclaimed once stale.
- **Replayable.** A consumer that drops offline replays from its last-seen
  sequence: `GET /api/v1/events?after=<cursor>` returns the next events — each as
  `{ "body": …, "signature": "sha256=…" }`, the same body a push carries plus its
  signature — with no gaps and no dupes, within the retention window.
- **Dead-letter queue.** An event that fails `max_attempts` deliveries is parked
  (`GET /api/v1/events/dead`) and re-queued with
  `POST /api/v1/events/{sequence}/replay` — it stops blocking its subject.
- Events are appended even when push is unconfigured (still replayable via the
  API). GC prunes the oldest contiguous prefix past `retention_secs` (keeping the
  retained window gap-free); the window is the replay + dead-letter-resolution SLA.

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
