# Changelog

All notable changes to Vultrino are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Open-source release hygiene: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Dependabot, release/GHCR workflow, and committed `Cargo.lock`.
- Stage-1 formal verification artefacts under `formal/` (Lean critical-boundary model, Kani harnesses, refinement gate), with CI jobs on `main`.
- Declared human-floor / ambiguous shared-canonical actions require a committed Averin use seal before dispatch; Observe cannot weaken that floor. Unknown `[averin]` modes refuse at config load.

### Changed

- Repository identity targets the `FeirAI` GitHub organization (`https://github.com/FeirAI/vultrino`).
- Documentation install paths and clone URLs updated for the org cut; TLS requirements clarify rustls (no OpenSSL toolchain dependency).
- Bump Rust toolchain pin to **1.94.0** and wasmtime/wasmtime-wasi to **47** (RUSTSEC-2026-0188, RUSTSEC-2026-0222).

## [0.1.0] - 2026-08-03

### Added

- Credential proxy with encrypted vault, RBAC, policies, MCP server, web admin UI, use tokens, and action approvals.
- WASM plugin runtime, metered LLM proxy with streaming egress scrubbing, and optional Averin sealing / Govder integration surfaces.

[Unreleased]: https://github.com/FeirAI/vultrino/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FeirAI/vultrino/releases/tag/v0.1.0
