# Installation

## Requirements

- Rust **1.94.0** (pinned in [`rust-toolchain.toml`](../../../rust-toolchain.toml); `rustup` installs it)
- No system OpenSSL packages — TLS uses **rustls**

## From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/FeirAI/vultrino.git
cd vultrino

# Build in release mode (uses committed Cargo.lock)
cargo build --release --locked

# The binary will be at target/release/vultrino
# Optionally, copy to your PATH
cp target/release/vultrino /usr/local/bin/
```

## Using Cargo

```bash
cargo install --git https://github.com/FeirAI/vultrino --locked --bin vultrino
```

## Pre-built Binaries

Download pre-built binaries from the [GitHub Releases](https://github.com/FeirAI/vultrino/releases) page (published when a `v*` tag is pushed).

### macOS

```bash
# Intel
curl -L https://github.com/FeirAI/vultrino/releases/latest/download/vultrino-x86_64-apple-darwin.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/

# Apple Silicon
curl -L https://github.com/FeirAI/vultrino/releases/latest/download/vultrino-aarch64-apple-darwin.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/
```

### Linux

```bash
# x86_64
curl -L https://github.com/FeirAI/vultrino/releases/latest/download/vultrino-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/

# ARM64
curl -L https://github.com/FeirAI/vultrino/releases/latest/download/vultrino-aarch64-unknown-linux-gnu.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/
```

## Docker / GHCR

```bash
docker pull ghcr.io/feirai/vultrino:latest
docker run --rm -p 7879:7879 \
  -e VULTRINO_PASSWORD=your-secure-password \
  ghcr.io/feirai/vultrino:latest
```

See [Docker deployment](../deployment/docker.md) for compose and volume layout.

## Verify Installation

```bash
vultrino --version
# vultrino 0.1.0
```

## Next Steps

Continue to [Quick Start](./quickstart.md) to initialize Vultrino and add your first credential.
