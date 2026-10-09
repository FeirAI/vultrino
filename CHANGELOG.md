# Changelog

All notable changes to Vultrino are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `cargo test --no-default-features --lib` passes: the WASM ABI install test now runs only with `wasm-plugins`, and a twin test pins that a build without the feature refuses every WASM install before anything is copied. CI runs this command in the `rust` job.

### Changed

- For `UrlToken` credentials the `http` plugin now sends the judged canonical URL (including the merged `query` map) with the secret in place of the literal `{credential}` placeholder. Before, it sent the raw URL with the token substituted and let the client append the `query` map afterwards, so the bytes sent could differ from the judged string in spelling (escapes, hex case, trailing host dot, query order). A request is now refused when text other than a literal `{credential}` in the URL canonicalises to a spelling of the placeholder (for example `%7Bcredential%7D`, the half-encoded `%7Bcredential}`, or `%7Bcr%65dential%7D`, whose escaped letter canonicalisation decodes); before, such text was sent literally. This is tested on a list of spellings, not proved for every URL.
- A policy that fails validation when it is loaded from the vault (for example a `RateLimit` policy saved with an allow or prompt default before that was refused) now logs a WARNING once per process. It is still enforced as written.
- The scheme-prefix patterns `http*` and `https*` no longer log the star-in-host warning. Other scheme-less prefixes (`internal*`, `api*`) still do: they match no canonical `http(s)` URL.
- Reported with the permit-kernel change below: an approval whose stored action has no `.` now fails closed at resume with a binding mismatch, because the action is dispatched as `http.<action>`. Approvals opened by `prepare_execution` always store a dotted action.
- argon2 0.5.3 to 0.6.0. In the tested cases the vault master key is unchanged: tests/argon2_kat.rs opens vault files and AES-GCM blobs written by 0.5.3 and checks that new vaults persist the same cost parameters. These are fixed cases, not every password, salt or cost setting. One input now behaves differently: a salt longer than 48 bytes, which 0.5.3 rejected, is accepted; vultrino only creates 16-byte salts. Replaces Dependabot PR #32.

### Added

- Open-source release hygiene: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Dependabot, release/GHCR workflow, and committed `Cargo.lock`.
- Stage-1 formal verification artefacts under `formal/` (Lean critical-boundary model, Kani harnesses, refinement gate), with CI jobs on `main`.
- Declared human-floor / ambiguous shared-canonical actions require a committed Averin use seal before dispatch; Observe cannot weaken that floor. Unknown `[averin]` modes refuse at config load.

### Changed

- The execution permit is minted from the policy engine's evaluation of the request on the direct path, and from the approval grant plus the policy evaluation made at resume on the approved path. `authorize` recomputes the binding from the payload it is about to dispatch (plugin and action, credential alias, params digest, request or approval id, epoch, tenant, principal) instead of receiving a copy, and refuses a mismatch. Valid requests behave as before. A Deny that observe mode lets run is recorded on the permit as its own kind. The URL and method these evaluations judge are now taken from the params inside the policy engine (same `policy_url` function).
- `url_match` now compares a canonical URL (case, default port, dot segments, trailing host dot, percent-encoding) and the caller's `query` map is part of the judged URL. The `http` plugin sends the canonical string: unreserved percent escapes are decoded and hex is upper-cased, so an upstream that signs the literal encoded path can see different bytes. URLs with userinfo or that cannot be canonicalised are refused. Risky patterns log a warning and will be refused next release.
- Policies that contain a `RateLimit` condition (at any depth) must now set `default_action = "deny"`, like `SpendCap`. Config load and the admin API refuse other defaults, because when no other rule matches, an exhausted Allow-`RateLimit` rule falls through to the policy default, which would allow the request under an allow default (or ask for approval under a prompt default). Default deny does not stop another matching allow rule from allowing an over-limit request. Policies already stored in the vault are not re-validated on load, so an existing one keeps its old behaviour until it is re-saved.
- Docs: the rate-limit examples in the policies guide now put `rate_limit` inside the rule it limits. The earlier examples used a separate allow rule whose only condition was `rate_limit`, which allowed any URL on the credential until the limit was spent. The guide's evaluation order section now describes the kill check and the deny, prompt, allow tiers instead of "first matching rule in written order".
- Policy precedence is now decided by a lazy tier scan and a verdict-to-decision mapping in `src/policy/precedence.rs`; behaviour is unchanged. The former unreachable tail that returned Allow now denies.
- Repository identity targets the `FeirAI` GitHub organization (`https://github.com/FeirAI/vultrino`).
- Documentation install paths and clone URLs updated for the org cut; TLS requirements clarify rustls (no OpenSSL toolchain dependency).
- Bump Rust toolchain pin to **1.95.0** and wasmtime/wasmtime-wasi to **48.0.4** (RUSTSEC-2026-0314/0315/0316/0321/0322/0323/0324/0325/0326/0327; earlier: RUSTSEC-2026-0188, RUSTSEC-2026-0222).
- Default feature `wasm-plugins`; Kani CI / `formal/run-kani.sh` use `--no-default-features` so proofs stay off wasmtime’s rustc-1.95 MSRV (Kani 0.67 ships rustc 1.93).
- Dependency refreshes (API-adapted where needed): `aes-gcm` 0.11, `rand` 0.10 (`OsRng` → `SysRng`), `sha2` 0.11, `hmac` 0.13 (`KeyInit`), `sha3` 0.12, `k256` 0.14 (`to_sec1_point`), `bcrypt` 0.19.3, `base64` 0.23, `toml` 0.9, `tower-http` 0.7; GitHub Actions checkout/buildx/metadata/build-push/gh-release majors.
- `docs/dev/` refreshed for the org cut, formal-gate bounds (LIMITATIONS), and SysRng/crypto crate notes.

## [0.1.0] - 2026-08-03

### Added

- Credential proxy with encrypted vault, RBAC, policies, MCP server, web admin UI, use tokens, and action approvals.
- WASM plugin runtime, metered LLM proxy with streaming egress scrubbing, and optional Averin sealing / Govder integration surfaces.

[Unreleased]: https://github.com/FeirAI/vultrino/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FeirAI/vultrino/releases/tag/v0.1.0
