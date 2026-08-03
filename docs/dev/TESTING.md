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

# Source-shape / choke-point refinement gate (no Lean/Kani install needed):
bash formal/check-refinement.sh

# Kani pure-kernel proofs (optional locally; CI runs this as its own job).
# Requires Kani 0.67.0. Always use the wrapper — bare `cargo kani` under
# default features pulls wasmtime and fails Kani's rustc-1.93 MSRV check:
bash formal/run-kani.sh    # → cargo kani --no-default-features --harness …
```

Default Cargo features include `wasm-plugins` (wasmtime 47). Production
`cargo test` / `cargo build` keep that default. Formal Kani jobs deliberately
disable it; see [LIMITATIONS.md](LIMITATIONS.md) for the honest proof scope.

The integration suites and their focus:

| Suite | Covers |
|-------|--------|
| `tests/auth_integration.rs` | API-key / use-token auth, role scoping, permission checks. |
| `tests/outbox_integration.rs` | Signed outbox: ordering, gap-free replay, dead-letter, delivery. |
| `tests/approval_token_integration.rs` | Use-token lifecycle, approval gating/lifecycle/dual-control, declared-irreversibility direct-path refusal (including approvals disabled), strict undeclared-label and wrong-credential refusal, stale catalog- and recipe-authority refusal at approval resume, canonical-sibling non-borrowing, shared-canonical direct-path refusal, and the **V13a/V13b `meter.observed` emit** (`test_v13a_*`, `test_v13b_*`). |
| `tests/web_smoke.rs` | The `vultrino web` JSON API + admin surface end-to-end, including strict refusal of inconclusive recipe authority for a declared reversible action (in-process axum router). |
| `tests/llm_proxy_integration.rs` | The metered LLM proxy: provider gate, model allowlist, output-token clamp, buffered + streaming enforcement. |
| `tests/workload_exchange_integration.rs` | HTTP-level deny paths for `POST /api/v1/workload/exchange`: forged HMAC → `401`, replayed `jti` → `409`, identity-binding mismatch → `403`, expired assertion → `401`, feature disabled → `404`; also pins that an embedded server snapshots its verifier and does not reread the environment per request. The permissive embedded constructor's invalid state returns `503`. |
| `tests/startup_security_integration.rs` | Real-binary negative controls proving `vultrino web` refuses before serving when the policy-hash key is absent or enabled workload exchange lacks a valid verifier. Unit/refinement checks additionally pin strict declared-capability posture as a startup precondition set before validation and vault access. |

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
The egress unit set includes negative controls where the fixed redaction marker
reconstructs the credential, a terminal SSE frame contains a credential form,
a scrubbed header still contains the form, and a buffered fallback diagnostic
would repeat the credential. Each must withhold before the low sink.

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
  the local parity loop for the Rust + Lean + refinement half of
  `.github/workflows/ci.yml`, with every exit code captured into a variable rather than
  read through a pipe: `cargo build --locked`, refinement check, `cargo test --locked`,
  `cargo test --locked --features mock-govder` (both test invocations are required —
  see above), the zero-warning clippy gate **twice** (`cargo clippy --all-targets -- -D
  warnings` and `cargo clippy --all-targets --all-features -- -D warnings`), `cargo
  audit`, Lean `lake build --wfail`, and nanoda. The second clippy is not optional: the
  first does not compile the `mock-govder`-only test target, so it cannot lint it, and
  on 2026-07-27 a `clippy::type_complexity` error was sitting in that target while the
  gate read green. Add `cargo fmt` yourself; `ci-local.sh` deliberately runs nothing
  that rewrites files. **Kani is intentionally not in `ci-local.sh`** (separate CI job /
  `formal/run-kani.sh`) — do not treat a green local script as having run the Kani
  harnesses.
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
