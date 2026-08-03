# Build & Run Quickstart

Vultrino is a standalone Rust binary. This walks you from source to a running
JSON API with a real end-to-end credential-broker request. Commands here are
verified against `src/main.rs`, `src/web/server.rs`, and the four-plane e2e
harness (`<workspace>/govder/e2e`, i.e. `e2e/` in the govder repo), which is the
authoritative record of how the binary is actually built, configured, and run.

## Prerequisites

- **Rust** (edition 2021; pinned in `rust-toolchain.toml`). Stable Rust with
  `cargo` is sufficient.
- **TLS:** reqwest is built with `rustls-tls` — no system OpenSSL development
  packages are required for a normal build.
- For the **web UI login record** (`admin.json`), the `init` flow prompts
  interactively; the e2e harness seeds it non-interactively with `htpasswd`
  (bcrypt). Either works — the JSON API itself uses `vk_` keys, not this record.

> If you install dependencies, route them through Socket Firewall per your
> environment policy (e.g. `sfw cargo build`).

## 1. Build from source

```bash
git clone https://github.com/FeirAI/vultrino.git
cd vultrino

# Debug build (what the e2e harness uses — faster to build):
cargo build
# binary at: target/debug/vultrino

# Release build:
cargo build --release
# binary at: target/release/vultrino
```

## 2. Configure (the storage password is mandatory)

Every command that touches the vault needs a **storage password** — it is the
encryption key for the credential vault. Source precedence
(`get_storage_password` in `src/main.rs`):

1. `VULTRINO_PASSWORD` — the password inline in the env.
2. `VULTRINO_PASSWORD_FILE` — a path to a file whose contents are the password
   (trailing newlines trimmed; warns on Unix if the file is group/world-readable —
   `chmod 600` it).
3. Interactive prompt.

```bash
export VULTRINO_PASSWORD="a-strong-passphrase"
```

Initialize config + the web admin account interactively:

```bash
vultrino init
```

This writes `config.toml` to the OS config dir and prompts for a web-UI admin
username/password (stored as a bcrypt hash in `admin.json` beside the config).
Config/vault locations (`Config::default_path` / `default_storage_path`):

| OS | config | vault |
|----|--------|-------|
| macOS | `~/Library/Application Support/vultrino/config.toml` | `…/vultrino/credentials.enc` |
| Linux | `~/.config/vultrino/config.toml` | `~/.local/share/vultrino/credentials.enc` |

> **Non-interactive setup** (CI / harness): write `config.toml` and `admin.json`
> yourself. A minimal, fail-closed config — taken from the e2e harness — is:
>
> ```toml
> [server]
> bind = "127.0.0.1:7879"
> mode = "local"
>
> [storage]
> backend = "file"
> [storage.file]
> path = "/abs/path/to/credentials.enc"
>
> [logging]
> level = "info"
>
> [enforcement]
> default_action = "deny"   # fail-closed (also the built-in default)
> require_declared_capabilities = true
>
> [mcp]
> enabled = false
>
> # Optional: enable the signed event outbox (required to emit meter events / webhooks)
> [outbox]
> enabled = true
> url = "https://your-consumer.example/webhook"
> hmac_secret = "shared-signing-secret"
> ```
>
> `admin.json` (the web server requires it to start) is just
> `{"username":"admin","password_hash":"<bcrypt>"}`. The harness seeds the hash
> with `htpasswd -bnBC 10 admin "$VULTRINO_PASSWORD"`.

## 3. Mint an admin API key

The JSON API authenticates with `vk_…` API keys, not the web-login record. Create
a role with `admin` (plus `execute`/`read` for the proxy) and mint a key:

```bash
vultrino role create admin --permissions admin,execute,read   # idempotent
vultrino key create harness --role admin
# prints:  Key: vk_xxxxxxxxxxxxxxxx   (shown ONCE — save it)
```

The predefined `admin` role already holds `admin`; creating one named `admin` with
explicit permissions is fine (the harness does exactly this).

## 4. Run the server

The JSON API is served by **`vultrino web`** (not `serve` — see
[ARCHITECTURE.md](ARCHITECTURE.md)):

```bash
vultrino web --bind 127.0.0.1:7879
# Vultrino Web UI running at http://127.0.0.1:7879
```

Health-check it:

```bash
curl -s http://127.0.0.1:7879/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

## 5. End-to-end: broker a credential without exposing it

Register a credential, allow it with a policy (default-deny means it is blocked
until you do), then have an agent use it through `/api/v1/execute`; the request
and confined response schemas do not contain the key.

```bash
ADMIN="vk_xxxxxxxxxxxxxxxx"
BASE="http://127.0.0.1:7879"

# (a) Store a credential (secret is write-only; never returned by any endpoint).
curl -sX POST "$BASE/api/v1/credentials" \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{
        "alias": "github-api",
        "data": { "type": "api_key", "key": "ghp_REAL_SECRET",
                  "header_name": "Authorization", "header_prefix": "Bearer " }
      }'

# (b) Allow it. Default-deny blocks an un-policied credential, so add an allow.
curl -sX POST "$BASE/api/v1/policies" \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{"name":"gh-allow","credential_pattern":"github-*","default_action":"allow"}'

# (c) Use it. The agent presents the alias; vultrino injects the real secret.
curl -sX POST "$BASE/api/v1/execute" \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"credential":"github-api","method":"GET","url":"https://api.github.com/user"}'
# -> {"status":200,"headers":{...},"body":"{\"login\":\"...\"}"}
```

What happened: `/api/v1/execute` resolved `github-api`, evaluated the policy
(allow), injected `Authorization: Bearer ghp_REAL_SECRET` server-side, forwarded
the GET to GitHub, scrubbed any reflected secret from the response, emitted a
`meter.observed` event, and returned the upstream response. The caller's bearer
token (`$ADMIN`) is **not** the GitHub secret.

> The proxied call must reach a **public** host. Vultrino's SSRF guard blocks
> requests to private/loopback/link-local addresses *after* policy admission, so a
> `127.0.0.1` target is denied at the transport step (see [SECURITY.md](SECURITY.md)).

## 6. Hand an agent a narrow use token instead

Mint a single-use, time-boxed grant and give the agent that (it works in the same
`Authorization: Bearer` slot as an API key):

```bash
vultrino token create deploy-once --credential "github-*" --action "http.request" --uses 1 --expires 10m
# Token: vut_xxxxxxxx…   (shown ONCE)

curl -sX POST "$BASE/api/v1/execute" \
  -H "Authorization: Bearer vut_xxxxxxxx…" -H "Content-Type: application/json" \
  -d '{"credential":"github-api","method":"GET","url":"https://api.github.com/user"}'
```

After one successful use the token is exhausted and the next call is rejected.

## CLI vs. server

The one-shot CLI subcommands (`add`, `list`, `key`, `role`, `token`, `approval`,
`meta`, `request`, `action`, `plugin`) open the vault directly (needing
`VULTRINO_PASSWORD`) and exit. `vultrino request <cred> <url>` and
`vultrino action <cred> <plugin.action>` run the **same PEP path** locally without
a running server (handy for testing a policy). Run `vultrino --help` and
`vultrino <cmd> --help` for the full flag set.
