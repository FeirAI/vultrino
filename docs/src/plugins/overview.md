# Plugin System

Vultrino supports trusted built-in Rust connectors and sandboxed WASM extensions.
They occupy different credential trust boundaries.

```text
PluginRegistry
├── built-in Rust plugin ── receives CredentialData as a trusted injector
└── WASM plugin
    ├── PluginManifest
    └── Wasmtime ABI v2 ─── receives alias + credential type only
```

## WASM ABI v2 boundary

Installed WASM is untrusted. The host sends public action parameters and a
non-secret credential handle. It never serializes a vault credential, metadata,
or a general-purpose secret map into guest memory. ABI v1 modules fail
installation and loading.

WASM plugins can provide public transformations, validation, actions, and MCP
tools. They cannot currently perform an operation that needs private credential
bytes because no secret-using host capability exists. Such functionality must be
implemented as a reviewed built-in connector or wait for a narrow host operation
specific to the credential type.

Installed plugins live under the platform data directory's `vultrino/plugins/`
folder and contain `plugin.toml`, the declared `.wasm` module, and
`.installed.json`. The web server loads them at startup.

The old [PGP signing module](./pgp.md) is an archived ABI v1 rejection fixture,
not an available plugin.

## Next steps

- [Installing Plugins](./installing.md)
- [Developing Plugins](./developing.md)
- [Archived PGP fixture](./pgp.md)
