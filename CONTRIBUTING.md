# Contributing to Vultrino

Thanks for helping improve Vultrino. This document is the short path from clone to a reviewable PR.

## Development setup

Requirements:

- Rust **1.94.0** (pinned in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it automatically)
- Optional for formal gates: [Lean 4.30.0](https://lean-lang.org/) via `elan`, and [Kani](https://model-checking.github.io/kani/) 0.67.0

```bash
git clone https://github.com/feir-ai/vultrino.git
cd vultrino
cargo build
cargo test
```

TLS uses **rustls** (no system OpenSSL development packages required for a normal build).

### Local CI parity

Run what GitHub Actions runs:

```bash
./ci-local.sh
```

Filter a step name substring if you are iterating:

```bash
./ci-local.sh clippy
./ci-local.sh Lean
```

## Project norms

- Prefer small, reviewable PRs with a clear security or product reason.
- Do not weaken fail-closed paths (default-deny policy, approval/evidence floors, egress redaction) without an explicit design note.
- Keep claims honest: update [`docs/dev/LIMITATIONS.md`](docs/dev/LIMITATIONS.md) when behavior changes.
- Match existing Rust style; `cargo clippy --all-targets --all-features -- -D warnings` must stay green.
- For dependency changes, keep [`Cargo.lock`](Cargo.lock) committed and build with `--locked` in CI/Docker.

## Formal / verified paths

Critical-boundary models live under [`formal/`](formal/). If you change approval, credential egress, startup security, or the execute permit path:

1. Update the Rust choke points.
2. Keep `formal/check-refinement.sh` green.
3. Keep `cd formal/lean && lake build --wfail` green when Lean models are affected.

These gates prove finite modeled invariants under stated TCB assumptions — not information-theoretic noninterference. See [`formal/lean/README.md`](formal/lean/README.md) and LIMITATIONS.

## Pull requests

1. Fork (or branch) from `main`.
2. Make the change with tests for the behavior you care about.
3. Ensure `./ci-local.sh` (or at least build/test/clippy) is green.
4. Open a PR with:
   - **Why** the change exists
   - **What** security-sensitive behavior changed, if any
   - **How** you tested it

## Security issues

Do **not** open a public issue for vulnerabilities. See [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the MIT License ([`LICENSE`](LICENSE)).
