# Configuration Reference

Every environment variable and `config.toml` key the `vultrino` binary reads,
with defaults, required-ness, and fail-closed behavior. Verified against
`src/main.rs` (env), `src/config/types.rs` (raw TOML parse), and
`src/config/mod.rs` (validation + defaults).

Config is loaded from `--config <path>` if given, else from the OS config dir
(`Config::default_path`); if that file is absent, built-in defaults are used.
**Invalid config fails the load** (the process errors out) for the keys noted
below — Vultrino prefers a loud config error to a silent misconfiguration.

## Environment variables

| Variable | Read by | Default | Required | Behavior |
|----------|---------|---------|----------|----------|
| `VULTRINO_PASSWORD` | every vault-touching command | — | Yes (one of these or the prompt) | The vault encryption password. First in precedence. |
| `VULTRINO_PASSWORD_FILE` | every vault-touching command | — | — | Path to a file whose contents are the password (trailing `\n`/`\r` trimmed; empty file is an error). Warns on Unix if the file is group/world-readable (`chmod 600`). Used only if `VULTRINO_PASSWORD` is unset. |
| `VULTRINO_API_URL` | `vultrino request --key …` | `http://127.0.0.1:7879` | — | Base URL the CLI's `--key` mode posts `/api/v1/execute` to (connect to a running `web` server instead of opening the vault directly). |
| `RUST_LOG` | tracing (`EnvFilter::from_default_env`) | derived from `-v` flags | — | Standard `tracing` filter. The `-v`/`-vv`/`-vvv` global CLI flags raise the base level (INFO → DEBUG → TRACE). |
| `USER` / `LOGNAME` | `vultrino approval approve/deny` | `cli` | — | The local OS user recorded as the approver identity (`cli:<user>`) for a CLI approval decision. |
| `VULTRINO_WORKLOAD_EXCHANGE_ENABLED` | `web` (workload exchange) | unset | — | Master switch for `POST /api/v1/workload/exchange`. Off unless set to `1`/`true`; otherwise the route returns `404 feature_disabled`. Fail-closed. |
| `VULTRINO_WORKLOAD_ASSERTION_SECRET` | `web` (workload exchange) | — | Yes, when exchange is enabled | HMAC-SHA256 verifier key for inbound `vwa_` assertions. **Must be ≥32 bytes**; a shorter/absent value fails the exchange closed with `503 exchange_unconfigured`. |
| `VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE` | `web` (workload exchange) | — | — | Path to a file whose (trimmed) contents are the verifier key. Takes precedence over `VULTRINO_WORKLOAD_ASSERTION_SECRET` when set to a non-blank path; same ≥32-byte requirement. |
| `VULTRINO_PROVIDER_OPENAI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `openai-chat` / `openai-responses` provider protocols on `POST /llm`. |
| `VULTRINO_PROVIDER_AZURE_OPENAI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `azure-openai` protocol. |
| `VULTRINO_PROVIDER_ANTHROPIC_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `anthropic-messages` protocol. |
| `VULTRINO_PROVIDER_BEDROCK_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `bedrock-converse` / `bedrock-invoke` protocols. |
| `VULTRINO_PROVIDER_GEMINI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `gemini` protocol. |
| `VULTRINO_PROVIDER_VERTEX_AI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `vertex-ai` protocol. |
| `VULTRINO_MCP_ALLOWED_ORIGINS` | `web` (MCP transport) | unset | — | Comma-separated `Origin` allowlist for browser MCP requests. A request's `Origin` must equal the request `Host` **or** an entry here, else `403`. |
| `GOVDER_BASE_URL` | `web` (govder delegate-decision client) | — | Yes, to enable delegate approvals | Base URL of the govder decide-plane. Read at startup (`GovderConfig::from_env`), **not** a `config.toml` key. Unset (or blank) → `state.govder` is `None` and `POST /api/v1/approvals/{id}/delegate-decision` fails closed with `503 govder_not_configured`. |
| `GOVDER_TENANT_ASSERTION_SECRET` | `web` (govder delegate-decision client) | — | Yes, to enable delegate approvals | HMAC key vultrino signs the outbound `X-Govder-Tenant-Assertion` with on every govder call. Unset (or blank) → same fail-closed `503 govder_not_configured` as a missing `GOVDER_BASE_URL`. |
| `GOVDER_ASSERTION_TTL_SECS` | `web` (govder delegate-decision client) | `90` | — | TTL of the outbound tenant assertion. A non-positive or unparseable value falls back to the default. |

> **Provider protocol gate is default-deny (fail-closed).** Each `VULTRINO_PROVIDER_*_ENABLED`
> switch accepts `1`/`true` to turn its family on; anything else (including any
> unset switch) leaves that protocol disabled. A protocol with **no** mapped switch
> — including the validated `observed-only` protocol — can never carry
> credential-injected proxy traffic. A request routed to a disabled protocol is
> denied with `403 provider_feature_disabled` before any upstream call.

There is **no** environment variable for the bind address, storage path, or
policies — those are CLI flags (`--bind`) or config keys.

## Config file (`config.toml`)

### `[server]`

```toml
[server]
bind = "127.0.0.1:7878"   # default; the CLI --bind flag overrides per process
mode = "local"            # "local" | "server"
```

| Key | Default | Notes |
|-----|---------|-------|
| `bind` | `127.0.0.1:7878` | Used by `serve`. **`vultrino web` defaults to `127.0.0.1:7879`** and `mcp` is stdio; the `--bind` flag overrides. |
| `mode` | `local` | `server` sets `require_auth = true` on the PEP (JSON API auth is always enforced regardless; `mode` controls the in-process default). Any value other than `"server"` parses as `local`. |
| `[server.tls]` | none | `cert_path` + `key_path`. Parsed into config; TLS termination is expected at the edge (see [SECURITY.md](SECURITY.md)). |

### `[storage]`

```toml
[storage]
backend = "file"          # "file" | "keychain" | "vault"
[storage.file]
path = "~/.local/share/vultrino/credentials.enc"   # ~ expands to home
```

| Key | Default | Notes |
|-----|---------|-------|
| `backend` | `file` | `file` is the only implemented backend. **`keychain` and `vault` parse but error at runtime** ("not yet implemented"). An unknown backend errors at load. |
| `storage.file.path` | `<data_local>/vultrino/credentials.enc` | The encrypted vault path. `~/` is expanded. |
| `[storage.vault]` | none | `address`, `auth_method` (`token` or AppRole `role_id`/`secret_id`) — parsed, not implemented. |

### `[enforcement]` — the engine default (fail-closed)

```toml
[enforcement]
default_action = "deny"   # "deny" (default, fail-closed) | "allow" (legacy fail-open)
```

| Key | Default | Behavior |
|-----|---------|----------|
| `default_action` | `deny` | Decision for a credential matching **no** policy. `deny` (the built-in default, even if the whole section is omitted) is fail-closed. `allow` is legacy fail-open. **An unknown value (or wrong case, e.g. `"Deny"`) is a hard load error.** |

> Two zero-policy postures are warned about loudly at startup: `deny` + no policies
> ("ALL credential use will be denied") and `allow` + no policies ("FAIL-OPEN").

### `[logging]`

```toml
[logging]
level = "info"            # informational; tracing level is driven by -v / RUST_LOG
format = "pretty"         # "pretty" | "json"
# audit_file = "~/.local/share/vultrino/audit.log"
```

`audit_file` is parsed (`~/` expanded) but audit-to-file is **not yet
implemented** (the dashboard/audit page is a TODO). Admin mutations are logged via
structured `tracing`; the durable audit history is the signed outbox.

### `[mcp]`

```toml
[mcp]
enabled = true            # default true
transport = "stdio"       # "stdio" | "socket"
# socket_path = "/run/vultrino.sock"
```

The shipped MCP transport is **stdio** (`run_stdio`); `socket` is parsed but the
socket transport is not the run path. `enabled` is informational for the `mcp`
subcommand.

### `[llm_proxy]` — metered LLM proxy streaming (connector M1)

```toml
[llm_proxy]
streaming_enabled        = true        # default true — SSE kill-switch
inject_stream_usage      = true        # default true — force OpenAI-chat usage trailer
stream_idle_timeout_secs = 120         # default 120 (0 disables)
stream_total_timeout_secs = 1800       # default 1800 (0 disables)
stream_max_bytes         = 268435456   # default 256 MiB (0 disables)
stream_max_line_bytes    = 4194304     # default 4 MiB (must be > 0)
```

Every key is optional; an absent key falls back to the streaming-on default.

| Key | Default | Behavior |
|-----|---------|----------|
| `streaming_enabled` | `true` | Master switch for incremental SSE. When `false`, a `{"stream": true}` request still works — Vultrino strips the stream flags and serves it on the buffered path (disabling streaming de-streams a client, never breaks it). |
| `inject_stream_usage` | `true` | When a streamed **OpenAI-chat** request omits `stream_options.include_usage`, force it to `true` so the provider emits a terminal usage chunk and V13b token metering fires. An explicit client value (true **or** false) is honored, never overwritten. Anthropic `/v1/messages` and OpenAI `/v1/responses` report usage natively and are excluded. |
| `stream_idle_timeout_secs` | `120` | Abort a stream idle this many seconds (slow-loris upstream). `0` disables. |
| `stream_total_timeout_secs` | `1800` | Abort a stream running longer than this in total. `0` disables. |
| `stream_max_bytes` | `268435456` (256 MiB) | Abort a stream once it has forwarded more than this many bytes. `0` disables. |
| `stream_max_line_bytes` | `4194304` (4 MiB) | Fail closed if a single un-delimited SSE line / scrub carry-buffer would exceed this. A `0`/absent value falls back to the default (a 0 cap would fail every chunk). |

The provider-protocol gate (`VULTRINO_PROVIDER_*_ENABLED`, above) is separate from
these streaming tunables and governs which protocols may carry traffic at all.

### `[[policies]]` — static declarative policies

```toml
[[policies]]
name = "github-readonly"
credential_pattern = "github-*"      # glob
principal_pattern  = "refund-bot"    # optional glob (V4): scope to one agent/id/SVID
default_action     = "deny"          # "allow" | "deny" | "prompt" (default deny)

[[policies.rules]]
condition = { url_match = "https://api.github.com/*" }
action    = "allow"

[[policies.rules]]
condition = { method_match = ["POST", "PUT", "DELETE"] }
action    = "deny"
```

Conditions (untagged): `{ url_match = "…" }`, `{ method_match = ["GET", …] }`,
`{ rate_limit = { max = N, window_secs = S } }`, `{ spend_cap = { asset = "usd",
per_action_max = N } }`, `{ and = [ … ] }`, `{ or = [ … ] }`. Actions: `allow` /
`deny` / `prompt`. Config policies are merged with admin-API-managed stored
policies into the live engine (config-first, never deduped by id).

**SpendCap validation (hard error at load):** a `SpendCap` must be a rule's
top-level condition (not nested), `asset` non-empty, `per_action_max > 0`, and the
policy must be `default_action = "deny"`.

### `[[spend_extractors]]` — read the amount for a SpendCap (V3)

```toml
[[spend_extractors]]
action_pattern     = "http.request"
credential_pattern = "stripe-*"
amount_pointer     = "/body/amount"   # JSON pointer (RFC 6901) → integer minor units
asset              = "usd"            # literal asset…
# asset_pointer    = "/body/currency" # …or a pointer (takes precedence)
```

A `SpendCap` is **fail-closed**: if a credential governed by a spend cap has no
matching extractor, or the amount/asset can't be read, the action is denied.

### `[[egress]]` — response egress controls (V7)

```toml
[[egress]]
credential_pattern = "sts-*"
action_pattern     = "*"              # default "*"
block              = true             # withhold body + headers entirely
# redact_patterns  = ["[A-F0-9]{16,}"] # extra regexes to redact from body + headers
```

**Validated at load:** a rule that neither blocks nor redacts is rejected (it does
nothing); a malformed glob or redact regex is a hard error (no silent degrade to
exact-match, which would be fail-open for a block rule).

### `[[action_labels]]` — govder business-verb mappings (V8)

```toml
[[action_labels]]
label  = "payments.refund"   # the verb an agent/govder presents
action = "http.request"      # the canonical plugin.action it resolves to
```

**Validated at load:** `label`/`action` non-empty; `action` must be a well-formed
`plugin.action`; a label may not equal its own target, duplicate another label, or
shadow another mapping's target.

### `[outbox]` — signed event outbox + meter feed (V9)

```toml
[outbox]
enabled        = true        # default: true when a `url` is present, else false
url            = "https://consumer.example/webhook"
hmac_secret    = "shared-signing-secret"
max_attempts   = 8           # default 8 (deliveries before dead-letter)
retention_secs = 604800      # default 7 days (replay window for DELIVERED events)
```

| Key | Default | Notes |
|-----|---------|-------|
| `enabled` | `true` if `url` set, else `false` | When `false`, events are still appended to the log and replayable via the API — just not push-delivered. |
| `url` | — | **Required when delivery is enabled** (hard error otherwise). |
| `hmac_secret` | — | **Required when delivery is enabled** — deliveries are signed (`Govder-Signature`). Hard error if missing. Redacted from any debug/config dump. |
| `max_attempts` | `8` | A `0`/absent value falls back to the default. |
| `retention_secs` | `604800` | GC window for delivered events. |

This is the feed the leria metering plane polls (`meter.observed`); see
[METERING.md](METERING.md).

### `[approvals]` — human-in-the-loop (V5/V10/V12)

```toml
[approvals]
enabled                     = true   # default: true if a notifier is configured, else false
ttl_secs                    = 3600   # default 3600
public_base_url             = "https://vultrino.example.com"  # for approve/deny links
oob_approver_identity       = "oncall@example.com"  # REQUIRED if a notifier is set
reauth_interval_secs        = 0      # continuous re-auth window (optional)
enforce_separation_of_duty  = false  # hard-reject self-approvals (default false: record only)
dual_control_approvers      = 2      # distinct approvers for a dual-control request (min/default 2)

[approvals.telegram]
bot_token = "123456:ABC-DEF..."
chat_id   = "987654321"

[approvals.webhook]
url         = "https://hooks.example.com/vultrino-approvals"
auth_header = "Bearer your-webhook-secret"

# Optional per-criticality SLA + assignment rules
[[approvals.sla]]
class = "high"
escalate_after_secs  = 60
escalate_window_secs = 120
[[approvals.criticality_rules]]
credential_pattern = "pay-*"
action_pattern     = "*"
class              = "high"
```

**Validated at load (hard errors):** a Telegram/webhook notifier without a named
`oob_approver_identity` is rejected (an out-of-band verdict would be
unattributable — separation of duty requires an attributable approver); an SLA
with a zero window, a duplicate SLA class, an unknown criticality class, or a
malformed criticality-rule glob are all rejected.

### `[identity]` — inbound workload-identity resolution (V10/R6)

```toml
[identity]
kind    = "spiffe"            # "spiffe" | "oidc"
header  = "x-spiffe-verified" # header carrying the ALREADY-VERIFIED document (lower-cased)
allowed = ["example.org"]     # SPIFFE trust domains / OIDC issuers (empty = accept any)
```

The deployment must terminate mTLS / verify the token **at the edge** and pass the
verified document in `header`; Vultrino trusts that header. A resolved identity
**refines** the principal (adds a `workload_id` match dimension and binds the
owner for SoD) but never replaces the `vk_`/`vut_` id — so a halt keyed on the id
always holds. A malformed/untrusted document falls back to the static principal
(fail-safe: it can't elevate). **Validated:** only `spiffe`/`oidc` are wireable
(other kinds error); a blank header errors; an allowlist of only blanks errors.

### `[[tenants]]` — per-team enforcement mode (V11)

```toml
[[tenants]]
id   = "team-a"
mode = "observe"             # "enforce" (default) | "observe"
[[tenants]]
id   = "team-b"              # mode omitted → enforce
```

`enforce` (the default for any tenant not listed, and for untenanted principals)
blocks a policy `Deny`. `observe` logs + emits a `policy.observed_denial` and lets
the action run — **except** halts/kills, cross-tenant isolation, and
SpendCap/RateLimit guards, which always enforce. **Validated:** unknown mode, empty
id, or duplicate id are hard errors.

## CLI flags that affect a run

| Flag | On | Default | Notes |
|------|----|---------|-------|
| `--bind <addr>` | `web`, `serve` | `7879` (web) / `7878` (serve) | Listen address. |
| `--config <path>` | global | OS config dir | Config file path. |
| `-v` / `-vv` / `-vvv` | global | INFO | Raise log verbosity. |
| `--key <vk_…>` | global (used by `request`) | — | Route the CLI `request` through a running server's JSON API instead of the local vault. |
| `--mcp` | `serve` | off | Run the MCP stdio server (same as `vultrino mcp`). |
