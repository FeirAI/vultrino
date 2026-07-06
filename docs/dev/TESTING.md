# Testing & Development

How to run Vultrino's tests, the four-plane end-to-end harness, and a brief
contributing note.

## Running the tests

Vultrino is a standard Cargo project; its tests are pure Rust (unit tests in
`src/**` modules + integration tests in `tests/`):

```bash
# Everything (unit + integration):
cargo test

# A single integration suite:
cargo test --test approval_token_integration
cargo test --test outbox_integration
cargo test --test auth_integration
cargo test --test web_smoke

# A single test by name substring:
cargo test test_v13a_
```

The integration suites and their focus:

| Suite | Covers |
|-------|--------|
| `tests/auth_integration.rs` | API-key / use-token auth, role scoping, permission checks. |
| `tests/outbox_integration.rs` | Signed outbox: ordering, gap-free replay, dead-letter, delivery. |
| `tests/approval_token_integration.rs` | Use-token lifecycle, approval gating/lifecycle/dual-control, and the **V13a/V13b `meter.observed` emit** (`test_v13a_*`, `test_v13b_*`). |
| `tests/web_smoke.rs` | The `vultrino web` JSON API + admin surface end-to-end (in-process axum router). |

Unit tests also live alongside the code — notably `src/outbox.rs`
(`test_meter_observed_payload_shape`, `test_parse_token_usage_*`,
`test_meter_tokens_payload_*`), `src/policy/mod.rs` (engine evaluation, kill
switch, spend caps), `src/egress.rs` (secret scrubbing), `src/config/types.rs`
(config validation), and `src/plugins/http.rs` (SSRF guard).

> Tests run against the encrypted file vault using temp dirs; they do not need
> network except where a suite explicitly exercises an outbound call.

## The four-plane end-to-end harness

The capstone harness that runs Vultrino against the real sibling-plane binaries
lives in the govder repo at `/Users/dzcodes/Projects/feir-ai/govder/e2e` (Go,
`//go:build e2e`). It is the **authoritative reference for how `vultrino` is
actually built, configured, and run** in a realistic deployment — this dev set's
build/run commands and the minimal config in [QUICKSTART.md](QUICKSTART.md) are
drawn from it. It builds Vultrino with `cargo build` (debug), provisions an
isolated vault + `admin.json`, mints a `vk_` admin key via the CLI, and starts
`vultrino web --bind <addr>`, waiting on `GET /api/v1/health`.

Run it from the govder repo:

```bash
cd /Users/dzcodes/Projects/feir-ai/govder
go test -tags e2e ./e2e/ -timeout 600s -v -run TestFourPlaneE2E
```

Requirements: `go`, `cargo`, the system `htpasswd` (to seed Vultrino's web-login
record; the test SKIPs without it), and outbound network to a public host (the
legs need Vultrino's proxy to complete a real call so it emits `meter.observed`).

## Local manual run

For a quick local loop without the harness, follow [QUICKSTART.md](QUICKSTART.md):
build, `export VULTRINO_PASSWORD`, `vultrino init` (or hand-write config +
`admin.json`), mint an admin key, run `vultrino web`, and exercise the API with
`curl`. `vultrino request <cred> <url>` and `vultrino action <cred> <plugin.action>`
run the same PEP path locally (no server) and are handy for testing a policy.

## Contributing

- **Build/lint before sending changes:** `cargo build`, `cargo test`,
  `cargo clippy`, `cargo fmt`. The code uses fail-closed validation extensively —
  preserve it (a malformed glob/regex/config should error at load, never silently
  degrade to never-matching).
- **Accuracy of these docs:** if you change a route, env var, config key, payload
  shape, default, or guarantee, update the corresponding `docs/dev/*` file in the
  same change — this set is the implementation-accurate reference and is checked
  against the code.
- **Secrets discipline:** never log or return secret material; new credential
  types must contribute their secret strings to `CredentialData::secret_material`
  so egress scrubbing covers them, and new config secrets must redact in `Debug`
  (see `OutboxConfig`).
- **Plugins:** built-in plugins are registered in `src/plugins/mod.rs`; custom
  credential types/actions ship as WASM plugins (`docs/src/plugins/`).
