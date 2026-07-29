# Testing & Development

How to run Vultrino's tests, the four-plane end-to-end harness, and a brief
contributing note.

## Running the tests

Vultrino is a standard Cargo project; its tests are pure Rust (unit tests in
`src/**` modules + integration tests in `tests/`):

```bash
# Everything except the mock-govder delegate suite (unit + integration):
cargo test

# The delegate-approval integration suite (tenant-equality, D3 PEP floors,
# approver_kind outbox, signed webhook) — gated behind `mock-govder` so the
# src-side mock evaluator never ships in a default/production build (see
# src/delegation/mod.rs). Cargo's `[[test]] required-features` means plain
# `cargo test` silently skips this file entirely — BOTH invocations below are
# required to exercise the full suite; CI runs both.
cargo test --features mock-govder

# A single integration suite:
cargo test --test approval_token_integration
cargo test --test outbox_integration
cargo test --test auth_integration
cargo test --test web_smoke
cargo test --features mock-govder --test delegate_approval_integration

# A single test by name substring:
cargo test test_v13a_

# Universal approval-gating and credential-confinement theorems (Lean 4):
cd formal/lean
lake build --wfail
bash check-nanoda.sh       # slower, independent Rust checker; pinned + cached
```

The integration suites and their focus:

| Suite | Covers |
|-------|--------|
| `tests/auth_integration.rs` | API-key / use-token auth, role scoping, permission checks. |
| `tests/outbox_integration.rs` | Signed outbox: ordering, gap-free replay, dead-letter, delivery. |
| `tests/approval_token_integration.rs` | Use-token lifecycle, approval gating/lifecycle/dual-control, and the **V13a/V13b `meter.observed` emit** (`test_v13a_*`, `test_v13b_*`). |
| `tests/web_smoke.rs` | The `vultrino web` JSON API + admin surface end-to-end (in-process axum router). |
| `tests/llm_proxy_integration.rs` | The metered LLM proxy: provider gate, model allowlist, output-token clamp, buffered + streaming enforcement. |
| `tests/workload_exchange_integration.rs` | HTTP-level deny paths for `POST /api/v1/workload/exchange`: forged HMAC → `401`, replayed `jti` → `409`, identity-binding mismatch → `403`, expired assertion → `401`, feature disabled → `404`, enabled-but-unconfigured → `503`. |

(Further suites exist — `capability_mcp_integration.rs`, `mcp_http_integration.rs`
— run `ls tests/` for the full set.)

`tests/delegate_approval_integration.rs` covers tenant-equality, D3 PEP risk/
irreversibility floors, `approver_kind` outbox events, and the signed govder
webhook for delegate-agent approval decisions. It requires `--features
mock-govder` (see above) — it is **not** part of the plain `cargo test` run.

Unit tests also live alongside the code — notably `src/outbox.rs`
(`test_meter_observed_payload_shape`, `test_parse_token_usage_*`,
`test_meter_tokens_payload_*`), `src/policy/mod.rs` (engine evaluation, kill
switch, spend caps), `src/egress.rs` (secret scrubbing), `src/config/types.rs`
(config validation), and `src/plugins/http.rs` (SSRF guard).

> Tests run against the encrypted file vault using temp dirs; they do not need
> network except where a suite explicitly exercises an outbound call.

## The four-plane end-to-end harness

The capstone harness that runs Vultrino against the real sibling-plane binaries
lives in the govder repo at `e2e/` (`<workspace>/govder/e2e` in a four-plane
workspace checkout; Go, `//go:build e2e`). It is the **authoritative reference for how `vultrino` is
actually built, configured, and run** in a realistic deployment — this dev set's
build/run commands and the minimal config in [QUICKSTART.md](QUICKSTART.md) are
drawn from it. It builds Vultrino with `cargo build` (debug), provisions an
isolated vault + `admin.json`, mints a `vk_` admin key via the CLI, and starts
`vultrino web --bind <addr>`, waiting on `GET /api/v1/health`.

Run it from the govder repo:

```bash
cd <workspace>/govder   # the govder checkout, sibling to this vultrino repo
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

- **Build/lint before sending changes:** run `./ci-local.sh` from the repo root. It is
  `.github/workflows/ci.yml`'s job, step for step, with every exit code captured into a
  variable rather than read through a pipe: `cargo build`, `cargo test`, `cargo test
  --features mock-govder` (both test invocations are required — see above), and the
  zero-warning clippy gate **twice** — `cargo clippy --all-targets -- -D warnings` and
  `cargo clippy --all-targets --all-features -- -D warnings`. The second is not optional:
  the first does not compile the `mock-govder`-only test target, so it cannot lint it, and
  on 2026-07-27 a `clippy::type_complexity` error was sitting in that target while the gate
  read green. Add `cargo fmt` yourself; `ci-local.sh` deliberately runs nothing that
  rewrites files. It also runs `lake build --wfail` over `formal/lean`; CI repeats that
  proof check, then exports and checks all declarations with the independently
  implemented nanoda kernel. Both exporter and checker are full-commit pinned;
  `sorryAx` is not on nanoda's permitted-axiom list.
  Why the script exists at all: that same day the zero-warning gate was found RED with 11
  errors, of unknown age, because the documented loop was build+test and clippy lived only
  in a workflow no runner executes on the branches the work happens on.
  The code uses fail-closed validation extensively — preserve it (a malformed
  glob/regex/config should error at load, never silently degrade to never-matching).
- **Accuracy of these docs:** if you change a route, env var, config key, payload
  shape, default, or guarantee, update the corresponding `docs/dev/*` file in the
  same change — this set is the implementation-accurate reference and is checked
  against the code.
- **Secrets discipline:** never log or return secret material; new credential
  types must contribute their secret strings to `CredentialData::secret_material`
  so egress scrubbing covers them, and new config secrets must redact in `Debug`
  (see `OutboxConfig`).
- **Plugins:** trusted built-ins are registered in `src/plugins/mod.rs`; untrusted
  WASM ABI-v2 guests receive only alias/type handles and can implement actions
  that do not require plaintext until a narrow host capability exists
  (`docs/src/plugins/`).
