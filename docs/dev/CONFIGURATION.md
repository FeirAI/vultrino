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
| `VULTRINO_NEW_PASSWORD` | `vultrino rekey` | — | — | The **new** vault master password for an offline re-key (run with the service stopped). First in precedence over `VULTRINO_NEW_PASSWORD_FILE` and the interactive double-entry prompt. Empty is refused (would leave the vault trivially unlockable). |
| `VULTRINO_NEW_PASSWORD_FILE` | `vultrino rekey` | — | — | Path to a file whose (trimmed) contents are the new master password. Used only if `VULTRINO_NEW_PASSWORD` is unset. Warns on Unix if the file is group/world-readable. Empty file is refused. |
| `VULTRINO_API_URL` | `vultrino request --key …` | `http://127.0.0.1:7879` | — | Base URL the CLI's `--key` mode posts `/api/v1/execute` to (connect to a running `web` server instead of opening the vault directly). |
| `RUST_LOG` | tracing (`EnvFilter::from_default_env`) | derived from `-v` flags | — | Standard `tracing` filter. The `-v`/`-vv`/`-vvv` global CLI flags raise the base level (INFO → DEBUG → TRACE). |
| `USER` / `LOGNAME` | `vultrino approval approve/deny` | `cli` | — | The local OS user recorded as the approver identity (`cli:<user>`) for a CLI approval decision. |
| `VULTRINO_WORKLOAD_EXCHANGE_ENABLED` | `web` (workload exchange) | unset | — | Master switch for `POST /api/v1/workload/exchange`. Off unless set to `1`/`true`; otherwise the route returns `404 feature_disabled`. When on, `vultrino web` validates and snapshots the verifier before vault access or listener bind. Fail-closed. |
| `VULTRINO_WORKLOAD_ASSERTION_SECRET` | `web` (workload exchange) | — | Yes, when exchange is enabled | HMAC-SHA256 verifier key (or comma-separated overlap list) for inbound `vwa_` assertions. Every entry **must be ≥32 bytes**. If the exchange is enabled and the value is absent, blank, or short, `vultrino web` refuses to start. The validated list is frozen in `AppState`; requests do not reread the environment. |
| `VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE` | `web` (workload exchange) | — | — | Path to a file whose trimmed contents are the verifier key or overlap list. Takes precedence over `VULTRINO_WORKLOAD_ASSERTION_SECRET` when set to a non-blank path. An enabled exchange refuses startup if the file is unreadable or any entry is shorter than 32 bytes; the file is not reread per request. |
| `VULTRINO_PROVIDER_OPENAI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `openai-chat` / `openai-responses` provider protocols on `POST /llm`. |
| `VULTRINO_PROVIDER_NVIDIA_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `nvidia` protocol. NVIDIA's `integrate.api.nvidia.com` is OpenAI-wire-compatible and rides the same transparent-proxy path as `openai-chat`, but on its own switch — an operator can run NVIDIA (e.g. Nemotron) without enabling the generic OpenAI provider. Capability validation pins an `nvidia` channel's `provider_base` to an `*.nvidia.com` host. |
| `VULTRINO_PROVIDER_AZURE_OPENAI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `azure-openai` protocol. |
| `VULTRINO_PROVIDER_ANTHROPIC_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `anthropic-messages` protocol. |
| `VULTRINO_PROVIDER_BEDROCK_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `bedrock-converse` / `bedrock-invoke` protocols. |
| `VULTRINO_PROVIDER_GEMINI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `gemini` protocol. |
| `VULTRINO_PROVIDER_VERTEX_AI_ENABLED` | `web` (LLM proxy) | unset | — | Enables the `vertex-ai` protocol. |
| `VULTRINO_UPSTREAM_PROXY` | every secret-bearing outbound call | unset | no | Explicit opt-in egress proxy (`http://` or `https://` URL whose host is an IP literal; a host name is refused at client construction). Unset means a direct connection through the connect-time SSRF guard; `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are never read by any secret-bearing client (plugins, plane clients, notifier, outbox, CLI). Only `https://` targets use it; a target host this machine cannot resolve is refused while it is set. The HTTP plugin refuses a plain `http://` target in every mode. An invalid value stops the process at client construction. |
| `VULTRINO_UPSTREAM_PROXY_CA_FILE` | every secret-bearing outbound call | unset | no | PEM file with the private CA that signs a TLS-inspecting `VULTRINO_UPSTREAM_PROXY`'s certificates; trusted in addition to the built-in roots. Set without the proxy, or unreadable, or not PEM, it stops the process at client construction. |
| `VULTRINO_IDENTITY_SECRET` (or `_FILE`) | `web` (`[identity]`) | unset | Yes, when `[identity]` is configured | Key the edge signs the inbound workload-identity header with (see `[identity]`). `vultrino web` refuses to start without it when `[identity]` is set. |
| `VULTRINO_POLICY_REFRESH_SECS` | `web` (policy refresh) | `5` | no | Whole seconds, 1 to 86400, between background policy refreshes from the vault; invalid values fall back to 5 with a warning, and any non-default value logs a warning. Ordinary (non-kill) policy changes made through another process reach this one only every interval; kill policies are fenced from the vault before every dispatch and do not wait for it. |
| `VULTRINO_MCP_ALLOWED_ORIGINS` | `web` (MCP transport) | unset | — | Comma-separated `Origin` allowlist for browser MCP requests. A request's `Origin` must equal the request `Host` **or** an entry here, else `403`. |
| `VULTRINO_TRUST_FORWARDED_FOR` | `web` (admin-login throttle) | `false` | — | When `1`/`true`, the admin-login brute-force throttle keys on the **rightmost** `X-Forwarded-For` (else `X-Real-IP`) hop instead of the socket peer. Set this **only** behind a trusted reverse proxy that sets the header — those headers are client-controlled, so trusting them on an untrusted network lets an attacker spoof a fresh lockout bucket per request (defeating the throttle). Fail-safe default is untrusted. In `mode = "server"` without this flag, every client behind the proxy shares **one** lockout bucket (a startup warning is emitted). |
| `GOVDER_BASE_URL` | `web` (govder delegate-decision client) | — | Yes, to enable delegate approvals | Base URL of the govder decide-plane. Read at startup (`GovderConfig::from_env`), **not** a `config.toml` key. Unset (or blank) → `state.govder` is `None` and `POST /api/v1/approvals/{id}/delegate-decision` fails closed with `503 govder_not_configured`. |
| `GOVDER_TENANT_ASSERTION_SECRET` | `web` (govder delegate-decision client; inbound approval identity verifier only under the shared-key escape) | unset | Yes, to enable delegate approvals or broker-verified approval identities | HMAC key vultrino signs outbound Govder `X-Govder-Tenant-Assertion` calls with. It verifies inbound feir-os JSON decisions only when `VULTRINO_ALLOW_SHARED_APPROVAL_KEY=1`; otherwise that is the job of `VULTRINO_APPROVAL_ASSERTION_SECRET`. Unset (or blank) leaves `state.govder` absent: delegate decisions fail closed with `503`, and any JSON decision that presents an assertion fails closed with `401` rather than falling back to a claimed identity. |
| `VULTRINO_APPROVAL_ASSERTION_SECRET` (or `_FILE`) | `web` (inbound feir-os approval identity verifier) | unset | Yes, for broker-verified approval identities | The approver-identity key: vultrino verifies the `X-Govder-Tenant-Assertion` on `POST /api/v1/approvals/{id}/decision` with it. Must be byte-equal to the feir-os broker's copy and different from `GOVDER_TENANT_ASSERTION_SECRET` (compared after trimming whitespace). Unset, blank, unreadable or equal to that key: a decision that presents an assertion is refused with `403 verified_approvals_disabled` and records nothing, and startup logs an ERROR. Requires `GOVDER_BASE_URL` and `GOVDER_TENANT_ASSERTION_SECRET` too (without them every signed decision is `401`). Unsigned decisions are unaffected. |
| `VULTRINO_ALLOW_SHARED_APPROVAL_KEY` | `web` (inbound feir-os approval identity verifier) | unset | no | Dev/test escape. Exactly `1` lets `GOVDER_TENANT_ASSERTION_SECRET` verify approver identities when no distinct `VULTRINO_APPROVAL_ASSERTION_SECRET` is configured, and logs a WARNING at every startup. Every holder of that shared key can then assert an approver, so never set it where an approval is evidence. |
| `GOVDER_ASSERTION_TTL_SECS` | `web` (outbound Govder signer + inbound broker assertion verifier) | `90` | — | Configured assertion TTL. A non-positive or unparseable value falls back to the default; inbound approval assertions are independently capped at five minutes even if this value is larger. |
| `VULTRINO_POLICY_HASH_SECRET` | `web` (policy inventory / create / replace) | unset | Yes for `vultrino web` | Server-held key for the policy `content_hash` (D2): the hash emitted is **HMAC-SHA256(secret, canonical-policy-bytes)**, not a bare digest, so a compromised read-only key cannot brute-force the reduced DTO back into the full enforcement topology offline. Sourced from the environment at startup, never parsed from `config.toml` (so a config dump never carries it). `vultrino web` refuses an unset/blank value before vault access or listener bind. It **must also remain stable across restarts** — startup proves presence, not cross-process key ownership; changing it makes every authored hash mismatch and creates a false drift signal. The reusable in-process `WebServer::new` constructor remains permissive for embedded/tests and emits an empty hash when given no key; it never falls back to a bare digest. |

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
| `bind` | `127.0.0.1:7878` | **Parsed but not wired to any run mode.** `vultrino web` binds its own `--bind` CLI flag (default `127.0.0.1:7879`), not this key; `mcp` is stdio; bare `vultrino serve` (no `--mcp`) refuses to start rather than binding anything (see [ARCHITECTURE.md](ARCHITECTURE.md)). Set `--bind` on `vultrino web` directly to change its listen address. |
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
require_declared_capabilities = true
```

| Key | Default | Behavior |
|-----|---------|----------|
| `default_action` | `deny` | Decision for a credential matching **no** policy. `deny` (the built-in default, even if the whole section is omitted) is fail-closed. `allow` is legacy fail-open. **An unknown value (or wrong case, e.g. `"Deny"`) is a hard load error.** |
| `require_declared_capabilities` | `false` in the library/parser; `true` in newly generated configs | Refuse unless the presented business label, or an unambiguous canonical action, has an exact stored capability declaration. The production `vultrino web` entrypoint forces this to `true` before validated startup, even when an older config omits it or sets it false. Stdio/embedded callers retain the parsed value for compatibility. |

Strict declaration enforcement is separate from `default_action`: policy `Allow`
cannot authorize an undeclared action. An unavailable capability catalog always
refuses. With configured business labels, callers must present the label; the
shared canonical target cannot borrow one sibling's `reversible` classification.
The exact spelling `reversible` is operator authority, so operators remain
responsible for classifying the real side effect truthfully.

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
require_priced_model     = true        # default true: refuse a model the rate card does not price
rate_card_path           = "/etc/vultrino/rate-card.json"   # the SAME file leria reads

[llm_proxy.azure_deployments]            # Azure deployment name -> the priced model it serves
prod-4o = "gpt-4o"
```

Every key is optional; an absent key falls back to the default (streaming on, priced models only, no Azure deployment mapped).

| Key | Default | Behavior |
|-----|---------|----------|
| `streaming_enabled` | `true` | Master switch for incremental SSE. When `false`, a `{"stream": true}` request still works — Vultrino strips the stream flags and serves it on the buffered path (disabling streaming de-streams a client, never breaks it). |
| `inject_stream_usage` | `true` | When `true`, a streamed **OpenAI-chat** request is forced to `stream_options.include_usage = true` (a missing value is added and a client `false` is **overwritten**: the flag is gateway-owned, so a client cannot opt out of token metering) so the provider emits a terminal usage chunk and V13b token metering fires. When `false`, nothing is injected and a stream without a trailer is charged an estimate (`dims.estimated = "true"`). Anthropic `/v1/messages` and OpenAI `/v1/responses` report usage natively and are excluded. |
| `stream_idle_timeout_secs` | `120` | Abort a stream idle this many seconds (slow-loris upstream). `0` disables. |
| `stream_total_timeout_secs` | `1800` | Abort a stream running longer than this in total. `0` disables. |
| `stream_max_bytes` | `268435456` (256 MiB) | Abort a stream once it has forwarded more than this many bytes. `0` disables. |
| `stream_max_line_bytes` | `4194304` (4 MiB) | Fail closed if a single un-delimited SSE line / scrub carry-buffer would exceed this. A `0`/absent value falls back to the default (a 0 cap would fail every chunk). |
| `require_priced_model` | `true` | Refuse an LLM-proxy request whose model the rate card at `rate_card_path` does not price: `403 model_unpriced`, before any upstream call (so the mock or real upstream sees no request). A model no entry covers books $0 in leria (its token event is rejected as unpriced), so a budget cap would never trip for it. A request that carries a body but names no model is refused too (it cannot be shown to be priced); a bodiless request (a model list) is not a billed call and is not gated. The model is the one the upstream URL selects where the URL picks it (Gemini and Vertex `models/<id>`, Bedrock `model/<id>`, Azure `deployments/<name>` through `[llm_proxy.azure_deployments]`; a deployment that is not mapped is refused), else the JSON body's `model`. A body `model` that differs from the URL's is refused, as is a request with a feature the proxy cannot show to bill tokens alone (`403 modifier_unpriced`): a top-level field, an `anthropic-beta` value or a tool shape that is not on the per-protocol allowlist in the code (compaction, `context_management`, `fallbacks`, `speed`, `inference_geo`, a service tier in any casing and server tools are refused). An operator widens the allowlist only by a code change, not by a card entry. With **no card configured nothing is priced, so every model-bearing call is refused**: set `rate_card_path`, or set this to `false` to opt out explicitly (posture reports it). |
| `rate_card_path` | unset | The rate-card JSON file leria prices with (`LERIA_RATE_CARD_FILE`): mount one file for both planes. Read at start (an unreadable, empty or malformed file, an unknown field, a missing `rate_card_version`, a one-sided input or output price, or a zero token price, is a startup error, as in leria) and re-read when its size or modified time changes. leria reads the file only at start, so a change can only narrow coverage: vultrino serves the intersection of the card it read at start and the latest good file until it restarts. A changed file that cannot be used keeps the previous card and is reported as `rate_card.last_error` in `/api/v1/posture`. Only coverage is read: an entry with `model_ref` covers exactly that id; an entry with `model_ref_prefix` covers a dated id, the prefix followed by `-` or `@` and more text (`claude-haiku-4-5-20251001`), and a dated id matches no other way. Entries of another asset than `tokens` price nothing. Prices are not used by vultrino. |

When a card is configured the token meter event is booked under the model the provider served if the card prices it, else the model the request named only when the served id is a dated form of it (so a dated snapshot of a priced alias is still priced); any other served model is booked under its own id. `/api/v1/posture` reports `rate_card.sha256` (the sha256 of the card read at start, the same digest leria reports for the same file) and `rate_card.file_sha256` (the file as last read), so a deploy check can compare the two planes and see a drift.

The provider-protocol gate (`VULTRINO_PROVIDER_*_ENABLED`, above) is separate from
these streaming tunables and governs which protocols may carry traffic at all.

Per-channel request shaping is **not** configured here: it lives on the capability
itself (admin API `POST`/`PUT /api/v1/capabilities`, see `API.md`). Two fields on the
capability's `llm` block are gateway-owned, meaning the agent's own value is clamped
or overwritten rather than honored: `llm.max_output_tokens` (per-call output-token
ceiling) and `llm.reasoning_effort` (one of `none`, `minimal`, `low`, `medium`,
`high`, accepted only on `llm.protocol` `openai-chat` or `openai-responses`). Both
are spend controls: reasoning tokens are billed as output tokens. An absent
`reasoning_effort` leaves the request body untouched.

**Org-level Anthropic keys.** Anthropic rejects a request made with an API key that
is not scoped to a workspace unless it carries an `anthropic-workspace-id` header.
To use such a key, set the credential's `anthropic_workspace_id` metadata, for
example `vultrino meta set <alias> anthropic_workspace_id
wrkspc_...` (or the `metadata` map on `POST /api/v1/credentials`). The value is
`wrkspc_` followed by 8 to 64 ASCII letters or digits; anything else is refused when
it is set, and a stored value that fails the same check at use time makes the request
fail before any upstream call. Vultrino then sends that value on every upstream
request that uses the credential: `/llm`, `POST /api/v1/execute`, the MCP
`http_request` tool and approval replay. The workspace is fixed by the operator, not
by the agent: an `anthropic-workspace-id` header sent by a caller is dropped on every
one of those paths, never forwarded. A credential with no setting sends no header,
so a workspace-scoped key keeps working unchanged, and a key that spans several
workspaces and has no setting is left for Anthropic to refuse rather than letting the
caller choose.

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

**`url_match` compares canonical URLs.** The request URL and the pattern are
both put in canonical form before matching: scheme and host lowercased (IDNA to
ASCII), one trailing dot on the host dropped, default port dropped, dot segments
resolved, fragment dropped, percent-encoded unreserved characters decoded, other
escapes upper-cased, and a stray `%` encoded as `%25`. The caller's `query` map
is merged into the URL (sorted by key, percent-encoded) before matching, so a
rule on `https://host/v1/search?q=secret*` sees the query the plugin will send.
A URL with userinfo (`https://user@host/...`) is treated as unparseable. A
pattern ending in `*` is a literal prefix of the canonical URL; any other
pattern is a glob. A prefix that ends in `*` directly after a host
(`https://api.example.com*`) is a host match: the prefix must be followed by a
port, a path, a query or the end, so it matches the same host on any port but no
longer matches `api.example.com.evil.net`. A prefix that stops inside a host
(`https://api.*`, `https://10.0.0*`) is a host match of the host the parser
reads from it (`api`, `10.0.0.0`), so it matches less than before. A glob is
matched part by part against a URL with a host: its scheme against the scheme,
its host against the host, its port against the port (no port matches only the
default port) and the rest against the path and query. A `*`, `?` or `[...]` in
the scheme or host therefore stays in that part, on every rule polarity: it
never matches `/`, `?`, `#`, `@` or the port, so `https://*.example.com/x` no
longer matches `https://evil.net/a.example.com/x`. A glob without a scheme that
starts with `*` (`*.example.com/x`) is read with any scheme; any other glob
without a scheme matches no URL with a host. In the path and query a glob `*`
still matches `/` and `?`. A pattern
without a trailing `*` must match the merged query as well. A URL that cannot be
parsed never matches an Allow rule and is denied when a matching policy has a
`url_match` under a deny or prompt rule or under a `not`. Path-only values
(`/v1/refunds`) are canonicalised the same way. At load, vultrino logs a WARNING
(once per policy and pattern) for patterns with `*` right after the host, `*`
inside the host (also without a scheme, except a prefix of `http://` or
`https://` such as `http*`), or where canonicalisation changes the meaning (dot
segments, encoded dots, a fragment, a backslash, a `*` that cuts a percent escape
short), or that are not a parseable URL or path, or that are an exact URL or path with
no `*`, `?` or query (a request with a query string appended does not match it: write
the prefix form `<url>*`), or that hold a `{` or `}` other than the literal
`{credential}` (a glob has no `{a,b}` alternation; the braces are literal and the
pattern matches nothing). A deny or prompt rule with such a pattern anywhere in its
condition (inside `and`, `or` or `not` too) is refused (an exact URL on a `prompt` rule
is accepted in a policy whose `default_action` is `deny`, which is govder's compiled
shape: the query form then falls to the deny default instead of skipping a gate): the admin API
(`POST` and `PUT /api/v1/policies`) answers 400 (`invalid_policy`, naming the rule and
the pattern), config load fails with the same message, and a policy already stored in
the vault that holds one makes `vultrino web` refuse to start (the live set stays
unchanged) and names the policy and the fix: `vultrino policy check` lists every such
stored policy and `vultrino policy fix-url-patterns <id>` rewrites an exact URL to
`<url>*` and expands `{a,b}` into an `or` (it only broadens a deny or prompt; a `*`
in a host needs a human edit). An allow rule is refused only when the warned pattern
sits under an odd number of `not` (a dead pattern there allows every URL); any other
warned pattern on an allow rule stays a warning, and an exact URL on an allow rule is
not warned at all. A policy loaded from the
vault that fails validation in another way is logged as a WARNING and still enforced as
written, except a `RateLimit` policy with a non-deny default, which is refused
on load (below). The `http` plugin sends the
evaluated string and refuses a URL that cannot be canonicalised; for a
`UrlToken` credential it sends the evaluated string with the secret in place of
the literal `{credential}` and refuses a URL in which other text canonicalises to a spelling of it (such as `%7Bcredential%7D` or `%7Bcr%65dential%7D`). The `hmac` plugin sends the canonical URL and adds only
`timestamp`, `recvWindow` and `signature` to the evaluated query pairs. See the
limits in `docs/dev/LIMITATIONS.md`.

**SpendCap validation (hard error at load):** a `SpendCap` must be a rule's
top-level condition (not nested), `asset` non-empty, `per_action_max > 0`, and the
policy must be `default_action = "deny"`.

**RateLimit validation (hard error at load and on the admin API):** a policy that
contains a `RateLimit` at any depth must be `default_action = "deny"`, because an
exhausted Allow-`RateLimit` rule falls through to the policy default when no other
rule matches. Another matching allow rule still allows an over-limit request, so
put the `RateLimit` inside an `and` with the conditions it limits. A policy
stored in the vault with a `RateLimit` and an allow or prompt default (possible
only in a vault written before this was refused) is **refused on load**:
`vultrino web` and `vultrino serve --mcp` do not start, and the error names the
policy and the fix; the CLI commands that load policies fail the same way; a
reload after an admin write returns an error and leaves the live set unchanged;
the periodic refresh logs an ERROR and keeps the live set (so a later halt kill
policy is not applied by that process, and `halt` reports `policy_active=false`,
until the refused policy is fixed). Fix it offline with
`vultrino policy deny-default <id>` (sets `default_action = "deny"` and keeps the
rules), then start again.

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

### `[[sheets_pins]]`: spreadsheet and range pins for the `sheets` plugin (plan 106 G1b)

```toml
[[sheets_pins]]
spreadsheet_id = "solo-marketing-fixture"
read_ranges  = ["Brand!A1:Z100", "Sources!A1:Z100", "Campaigns!A1:Z100", "Pipeline!A1:Z100"]
write_ranges = ["Pipeline!A:Z"]
```

The typed `sheets` adapter enforces these pins itself, independent of any
capability schema `const`. Every check runs before credential refresh and before
any upstream request, on the preflight (`validate_params`) and again in `execute`.

| Key | Notes |
|-----|-------|
| `spreadsheet_id` | Exact id, `[A-Za-z0-9_-]`, 1-128 chars, compared byte-for-byte. Duplicate ids are a load error. |
| `read_ranges` | Ranges `sheets.read` may name, exact match only. `append_draft` also reads `Sources!A1:F100` internally, so that span must lie inside one of these or append is refused. |
| `write_ranges` | Ranges `append_draft` / `revise_draft` may name, exact match only. A read range is not a write range. A revision's derived row write (`Sheet!A{n}:W{n}`, starting at the range's first row and column) must lie inside the named write range. |

**Fail closed:**
- **No `[[sheets_pins]]` (the default):** the plugin is still registered, but it
  refuses every Sheets call. It never falls back to "any spreadsheet".
- **A pin with no ranges at all:** load error.
- **Range spelling is strict**, at load time and at request time. Allowed forms
  are `Sheet!A1:Z100` or `Sheet!A:Z`, with an unquoted `[A-Za-z0-9_-]` sheet
  name, uppercase column letters and rows without a leading zero. These are
  refused, not normalized:
  - lowercase or case-variant sheet names or columns (Sheets matches sheet
    names case-insensitively)
  - whitespace, `$` absolute refs, quoted sheet names, a second `!`
  - R1C1 notation, a bare sheet name, single cells, row-only spans
  - percent-encoding
  - a range wider or narrower than the pin

  Sheet names containing spaces cannot be pinned.

### `[solo_pins]`: learner spreadsheet and Calendar pins for the `solo` plugin

```toml
[solo_pins]
learner_spreadsheet_ids = ["solo-learner-fixture"]
calendar_ids            = ["solo-calendar-fixture"]
```

The typed `solo` adapter pins its Sheets ranges to compiled constants
(`Cohorts!A1:K100`, `Learners!A1:L1000`, `Attendance!A1:K1000`,
`Knowledge!A1:H200`); these pins bound the spreadsheet id and Calendar id a
request may name. Every check runs before credential refresh and before any
upstream request, on the preflight (`validate_params`) and again at the start of
each `execute` path.

| Key | Notes |
|-----|-------|
| `learner_spreadsheet_ids` | Spreadsheet ids `solo.learner_read` and `solo.attendance_update` may name. `[A-Za-z0-9_-]`, 1-128 chars, compared byte-for-byte. |
| `calendar_ids` | Calendar ids `solo.session_list`, `solo.availability_check`, `solo.session_create`, `solo.session_update` and `solo.session_cancel` may name. `[A-Za-z0-9_.@+-]`, 1-512 chars, compared byte-for-byte. |

This section is separate from `[[sheets_pins]]` on purpose. A `[[sheets_pins]]`
entry never authorizes a solo call and a `[solo_pins]` entry never authorizes a
`sheets` call, even for the same spreadsheet. Within `[solo_pins]`, a
spreadsheet pin never authorizes a Calendar id and a Calendar pin never
authorizes a spreadsheet id.

**Fail closed:**
- **No `[solo_pins]` (the default), or an empty list:** the plugin is still
  registered, but it refuses every call of that family (Sheets or Calendar).
  It never falls back to "any spreadsheet" or "any calendar".
- **Malformed, duplicate or unknown keys:** load error. Values are not trimmed
  or case-folded, so a case or whitespace variant of a pinned id is refused.
- `solo.learner_message_send` names no spreadsheet or Calendar; its recipients
  stay bound by the credential's own recipient map and are unaffected.

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
ttl_secs                    = 3600   # default 3600 — a CEILING, not a promise (see below)
public_base_url             = "https://vultrino.example.com"  # for approve/deny links
oob_approver_identity       = "oncall@example.com"  # REQUIRED if a notifier is set
reauth_interval_secs        = 900    # continuous re-auth window, seconds (optional; 0/absent = off)
# enforce_separation_of_duty: hard-reject self-approvals. UNSET (recommended): ON when approver
# identities are verified (a distinct VULTRINO_APPROVAL_ASSERTION_SECRET is set, so the broker
# signs the decider), OFF otherwise (dev mode: record only). An explicit true/false always wins;
# an explicit false with verified identities logs that a requester can approve its own request.
# The startup log says which posture is running.
enforce_separation_of_duty  = true
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

Webhook approval payloads include the requesting `agent_label`. This lets a trusted
Slack, Telegram, or email bridge route approvals from several specialist agents into
one owner-facing lead conversation without holding their use tokens. Treat the webhook
as sensitive: first-request payloads also carry one-time decision links.

**Validated at load (hard errors):** a Telegram/webhook notifier without a named
`oob_approver_identity` is rejected (an out-of-band verdict would be
unattributable — separation of duty requires an attributable approver); an SLA
with a zero window, a duplicate SLA class, an unknown criticality class, or a
malformed criticality-rule glob are all rejected.

**`ttl_secs` and per-class SLA windows govern human review, independently of bearer
TTL.** The presenting use token authenticates and scopes approval-open, then may
expire or rotate. A completed human recipe authorizes the frozen request through a
durable one-shot permit. Immediately before dispatch Vultrino revalidates the live
credential revision and tenant, capability declaration, Govder approval recipe,
and current policy/kill state. This lets operators configure multi-day review
windows without issuing multi-day bearer credentials.

**`reauth_interval_secs` (continuous re-auth / execute-by window):** when set to a
positive value, an approved action must run within that many seconds of the
decision or it lapses (`approval.expired`) and must be re-approved. `0` (or absent)
disables *explicit* continuous re-auth — it is treated as "off", **not** a
0-second window. Note that an approved-but-unrun grant is still bounded even with
re-auth off: it lapses after a generous default execute-by window (24h) so a
forgotten grant can't stay executable indefinitely. Set a positive
`reauth_interval_secs` when you need a tighter bound.

### `[averin]` evidence floor: `d8_evidence_floor` (VUL-38)

```toml
[averin]
enabled = true
d8_complete_evidence = true
# "money_and_irreversible" (default) | "human_floor"
d8_evidence_floor = "money_and_irreversible"
```

`d8_evidence_floor` decides which actions are refused while Averin cannot begin the two-phase
use evidence (unreachable, timed out, a 5xx or a 429). It has an effect only with
`d8_complete_evidence = true`; with that off, every action the catalog declares non-reversible
keeps its committed-evidence requirement, as before. An unknown value is refused at config load.

| Action | `money_and_irreversible` (default) | `human_floor` |
|---|---|---|
| declared irreversible | refused | refused |
| money (see below), any declaration | refused | refused |
| partially-reversible, not money | keeps running: one-phase seal, `AVERIN-D8-DEGRADED`, `d8_degraded` | refused |
| reversible, not money | keeps running, same alarm | keeps running, same alarm |
| no catalog declaration | refused | refused |

Money, for Vultrino, is an action whose name is in the `money.*` namespace, or one its
capability catalog declares irreversible. A partially-reversible action in the `money.*`
namespace (for example `money.notify`) is therefore refused in both modes. A `money.*` name
is read from the request's action, label and, for a non-reversible declaration, the catalog
entry's own action; a reversible catalog entry named `money.*` that is requested under another
label is not recognised as money. FeirOS's own money check (`isMoneyClass`) also counts a high
risk hint that Vultrino's catalog does not carry, so the two planes can classify an action
differently. The running mode is reported in `GET /api/v1/posture` under `averin`
(`d8_evidence_floor`, and `d8_evidence_floor_effective`, which reads `human_floor` while
`d8_complete_evidence` is off). An approval opened before this setting existed for a
partially-reversible action is refused on resume (its recorded authority class no longer
matches) and must be requested again.

### `[identity]` — inbound workload-identity resolution (V10/R6)

```toml
[identity]
kind    = "spiffe"            # "spiffe" | "oidc"
header  = "x-spiffe-verified" # header carrying the ALREADY-VERIFIED document (lower-cased)
allowed = ["example.org"]     # SPIFFE trust domains / OIDC issuers (empty = accept any)
```

The edge verifies the token **and signs** the document. Set `VULTRINO_IDENTITY_SECRET` (or
`_FILE`) on vultrino and the edge; `vultrino web` refuses to start with `[identity]` and no key.
The request carries `header` (the document) and `<header>-signature`
(`v1.<exp>.<base64url HMAC-SHA-256>`): the MAC is under the key over
`"vultrino-identity-v1\n" + document + "\n" + exp + "\n" + hex(SHA-256(bearer secret))`,
where `exp` is unix seconds at most 300 s ahead and the bearer secret is the `vk_`/`vut_`
the request authenticates with. A missing, wrong, expired or foreign-bearer signature makes
the document ignored (the static principal stays). See `identity::sign_identity`. A resolved identity
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
