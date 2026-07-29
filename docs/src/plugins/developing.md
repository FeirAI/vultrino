# Developing WASM Plugins

Vultrino loads WASI Preview 1 modules through a credential-confining ABI. A
guest is untrusted: it receives public action parameters plus a non-secret
credential handle, never vault material.

## Current capability boundary

ABI v2 intentionally does not expose a generic “read credential” function. No
secret-using host operations exist yet. Therefore a WASM plugin can:

- validate and transform public action parameters;
- use the selected credential's alias and type as non-secret routing context;
- return a public result; and
- define actions and MCP tools in its manifest.

It cannot sign, authenticate, or otherwise operate on private credential bytes.
Those features require a narrow host-side capability for the particular
operation. Do not work around this by placing secrets in action parameters.

## Plugin structure

```text
my-plugin/
├── Cargo.toml
├── plugin.toml
└── src/
    └── lib.rs
```

A manifest may define actions and tools normally. Credential fields can still
describe the selected credential, but their values are held only by Vultrino;
the guest receives the handle below.

## ABI v2

The module must export:

- `vultrino_plugin_version() -> u32`, returning `2`;
- `vultrino_alloc(size: u32) -> u32`;
- `vultrino_free(ptr: u32, len: u32)`;
- `vultrino_execute(ptr: u32, len: u32) -> u64`; and
- optionally `vultrino_validate_params(action_ptr, action_len, params_ptr,
  params_len) -> i32`.

The execute request is JSON:

```json
{
  "action": "do_something",
  "credential_handle": {
    "alias": "selected-alias",
    "credential_type": "plugin:my-plugin:profile"
  },
  "parameters": {
    "input": "public data"
  }
}
```

There is deliberately no `credential`, secret map, metadata map, or credential
id. ABI v1 modules that expect a plaintext `credential` object are rejected at
installation and loading.

The response is JSON:

```json
{
  "code": 0,
  "data": "public result",
  "error": null
}
```

Nonzero result codes are failures. Guest error text is treated as potentially
secret-bearing after dispatch and is replaced with a constant message at the
public execution boundary.

## Build and test

```bash
cargo build --release --target wasm32-wasip1
vultrino plugin install ./my-plugin
```

Installation compiles source when necessary, verifies that the declared module
exists, instantiates it, and checks ABI v2 before copying it into the installed
plugin directory. The server loads installed plugins at startup.

Keep plugin results public, validate all parameters, bound memory use, and pin
dependencies. A future secret-using plugin API will expose operation-specific
host capabilities rather than plaintext credentials.
