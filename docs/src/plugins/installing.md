# Installing Plugins

Vultrino plugins can be installed from local paths, git repositories, or archive URLs.

## Installation Sources

### From Local Path

Install a plugin from a local directory:

```bash
vultrino plugin install ./my-plugin
vultrino plugin install /absolute/path/to/plugin
vultrino plugin install ~/plugins/my-plugin
```

### From Git Repository

Install directly from GitHub, GitLab, or other git hosts:

```bash
# Latest commit
vultrino plugin install https://github.com/user/vultrino-plugin

# Specific tag or branch
vultrino plugin install https://github.com/user/vultrino-plugin#v1.0.0
vultrino plugin install https://github.com/user/vultrino-plugin#main
```

### From Archive URL

Install from a `.tar.gz` archive:

```bash
vultrino plugin install https://example.com/plugin-1.0.0.tar.gz
```

## Build Process

When installing a plugin with a `Cargo.toml`, Vultrino automatically:

1. Checks for the `wasm32-wasip1` target (installs if needed)
2. Runs `cargo build --release --target wasm32-wasip1`
3. Copies the built WASM module to the plugin directory

**Requirements:**
- Rust toolchain installed
- `rustup` available in PATH

## Managing Plugins

### List Installed Plugins

```bash
vultrino plugin list
```

Example output:
```
Installed plugins:

  public-transform v2.0.0
    Source: https://github.com/example/public-transform#v2.0.0
    Installed: 2024-01-15
    MCP tools: normalize_payload
```

### View Plugin Details

```bash
vultrino plugin info public-transform
```

### Remove a Plugin

```bash
vultrino plugin remove public-transform
```

### Reload a Plugin

Reload a plugin's WASM module without restarting:

```bash
vultrino plugin reload public-transform
```

## Plugin Discovery

Plugins can be discovered in the Vultrino plugin registry (coming soon) or by searching GitHub for repositories tagged with `vultrino-plugin`.

## Troubleshooting

### Build Fails

If the WASM build fails:

1. Ensure Rust is installed: `rustup --version`
2. Check the target: `rustup target list --installed`
3. Install the target manually: `rustup target add wasm32-wasip1`

### Plugin Not Loading

Vultrino requires the credential-confining WASM ABI v2. ABI v1 modules are
rejected because they accepted plaintext credential data. Installation validates
the module and ABI before it is copied into the plugin directory.

Check the plugin manifest is valid:

```bash
cd ~/.vultrino/plugins/my-plugin
cat plugin.toml
```

Verify the WASM module exists:

```bash
ls -la *.wasm
```

### Hot Reload Not Working

Make sure the Vultrino server has write access to the plugins directory and that the new WASM module compiles successfully.
