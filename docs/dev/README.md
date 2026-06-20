# Vultrino Developer Documentation

This `docs/dev/` set is the **implementation-accurate** reference for developers
who want to build, run, configure, integrate, or contribute to Vultrino. It
describes the **shipped binary** — every command, environment variable, route,
object, and guarantee here is verified against the source in this repository,
not against design intent.

> The user-facing guides in [`docs/src/`](../src/) (rendered as an mdBook) cover
> task-oriented usage and the *why* of the design. Where this dev set and the
> guides differ, **this set describes what the code actually does today** (the
> `serve` proxy, for example, is a stub — see [ARCHITECTURE](ARCHITECTURE.md)).

Vultrino is **alpha** (`Cargo.toml` version `0.1.0`). It is open-source and
**usable standalone**: a single Rust binary that brokers credentials for AI
agents and automated systems, so the agent uses a credential without ever seeing
its secret. You do not need any other component to run it.

## What Vultrino is

Vultrino is the **enforce plane** — an in-path Policy Enforcement Point (PEP) and
credential broker:

- **Credential isolation.** Secrets live encrypted at rest (AES-256-GCM, Argon2
  key derivation). An agent presents a *credential alias*; Vultrino injects the
  real secret server-side and never returns it.
- **Default-deny policy engine.** A credential that matches no policy is denied
  (fail-closed). Policies match on credential glob, principal, URL, method, rate,
  and per-action spend.
- **Scoped use tokens.** Narrow, single-purpose, optionally single-use and
  time-boxed grants (`vut_…`) you hand an agent in place of an API key.
- **Kill switch / halt.** Revoke an agent's tokens and install an authoritative
  per-agent kill policy in one admin call.
- **Human-in-the-loop approvals.** Gate an action on a human decision (admin
  panel, Telegram, webhook), with escalation/expiry SLAs and optional dual control.
- **Egress controls.** Scrub a credential's own reflected secret from a response,
  and block/redact secret-bearing endpoints.
- **Signed event outbox.** An ordered, replayable, HMAC-signed event log for
  approvals, halts, policy changes, credential rotation, and **usage metering**
  (the `meter.observed` events the leria plane consumes).

## Map of this dev set

| Doc | Covers |
|-----|--------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component model, the binary's run modes, request lifecycle, the core algorithms (policy evaluation, use-token consumption, approval lifecycle, halt, outbox), and the storage model. |
| [QUICKSTART.md](QUICKSTART.md) | Prerequisites, build from source, run the web server, and an end-to-end working example with real `curl` requests. |
| [CONFIGURATION.md](CONFIGURATION.md) | Every environment variable and config-file key the binary reads, defaults, required-ness, and fail-closed behavior. |
| [API.md](API.md) | The HTTP wire reference for `vultrino web`: routes, auth, request/response shapes, objects, enums, and error codes. |
| [METERING.md](METERING.md) | The `meter.observed` emit (V13a/V13b): when it fires, the exact payload shapes, the poll/replay contract, and the honest bounds of the guarantee. |
| [SECURITY.md](SECURITY.md) | Threat model, invariants, authn/authz, trust boundaries, and what Vultrino deliberately does **not** do. |
| [INTEGRATION.md](INTEGRATION.md) | Standalone integration (the client-facing API), then the optional cross-plane composition contracts. |
| [TESTING.md](TESTING.md) | Running the tests, the four-plane e2e harness, and a contributing note. |
| [LIMITATIONS.md](LIMITATIONS.md) | The honest v1 limits, non-goals, and deferred/documented-not-enforced items. |

## Project layout (Rust crate)

```
src/
  main.rs          CLI entrypoint (clap): serve, web, mcp, add, key, role, token, …
  lib.rs           Core types: Credential, CredentialData, ExecuteRequest/Response, VultrinoError
  config/          TOML → validated Config (config/types.rs is the raw TOML shape)
  server/          VultrinoServer — the PEP core: execute_gated, run_action, halt, sweeps, outbox delivery
  policy/          PolicyEngine + Policy/PolicyCondition/PolicyDecision
  auth/            Permission, Role, ApiKey, AuthResult, UseToken, AuthManager
  approval/        ApprovalRequest lifecycle + notifiers (Telegram/webhook)
  egress.rs        Response secret scrubbing + egress classification (V7)
  outbox.rs        Signed event outbox: event types, MeterEvent payloads, HMAC signing
  storage/         Encrypted file vault (storage/file.rs) behind the StorageBackend trait
  crypto/          AES-256-GCM + Argon2 key derivation
  plugins/         Built-in plugins (http, hmac, ecdsa, ssh, postgres) + WASM plugin loader
  web/             axum web server: admin panel (HTML) + JSON API (web/api.rs) + routes
  mcp/             MCP (Model Context Protocol) stdio server for LLM tool integration
  identity.rs      Inbound SPIFFE/OIDC workload-identity resolvers
  revocation.rs    Downstream OAuth2/STS revoke propagation on credential delete
  session.rs       In-flight execution registry + halt callbacks
tests/             Integration tests (auth, outbox, approvals/tokens, web smoke)
```
