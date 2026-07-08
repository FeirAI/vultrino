# Developing Plugins

This guide covers creating custom Vultrino plugins that add new credential types, actions, and MCP tools.

## Plugin Structure

A minimal plugin requires:

```
my-plugin/
├── Cargo.toml
├── plugin.toml
└── src/
    └── lib.rs
```

## Cargo.toml

Configure your crate for WASM compilation:

```toml
[package]
name = "my-plugin"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[profile.release]
opt-level = "s"
lto = true
```

## Plugin Manifest (plugin.toml)

Define your plugin's capabilities:

```toml
[plugin]
name = "my-plugin"
version = "1.0.0"
description = "My custom plugin"
author = "Your Name"
format = "wasm"
wasm_module = "my_plugin.wasm"

# Define custom credential types
[[credential_types]]
name = "my_credential"
display_name = "My Custom Credential"

[[credential_types.fields]]
name = "secret_value"
label = "Secret Value"
type = "password"      # text, password, or textarea
required = true
secret = true
help_text = "Enter your secret value"

[[credential_types.fields]]
name = "api_endpoint"
label = "API Endpoint"
type = "text"
required = false
placeholder = "https://api.example.com"

# Define actions your plugin can perform
[[actions]]
name = "do_something"
description = "Perform an action with the credential"

[[actions.parameters]]
name = "input"
type = "string"
required = true
description = "Input data for the action"

# Expose as MCP tools
[[mcp_tools]]
name = "my_plugin_action"
action = "do_something"
description = "Perform my plugin action"
```

## WASM ABI

Your plugin must export these functions:

### vultrino_plugin_version

Return the ABI version (currently 1):

```rust
#[no_mangle]
pub extern "C" fn vultrino_plugin_version() -> u32 {
    1
}
```

### vultrino_alloc

Allocate memory for the host to write data:

```rust
use std::alloc::{alloc, Layout};

#[no_mangle]
pub extern "C" fn vultrino_alloc(size: u32) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { alloc(layout) }
}
```

### vultrino_free

Free memory allocated by the plugin:

```rust
use std::alloc::{dealloc, Layout};

#[no_mangle]
pub extern "C" fn vultrino_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let layout = Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { dealloc(ptr, layout) }
}
```

### vultrino_execute

Execute an action. Takes JSON request, returns packed pointer/length to JSON response:

```rust
#[no_mangle]
pub extern "C" fn vultrino_execute(request_ptr: *const u8, request_len: u32) -> u64 {
    // Read request JSON
    let request_str = read_string(request_ptr, request_len);
    let request: ExecuteRequest = serde_json::from_str(&request_str).unwrap();

    // Process action
    let response = match request.action.as_str() {
        "do_something" => handle_do_something(&request),
        _ => error_response("Unknown action"),
    };

    // Return response
    let json = serde_json::to_string(&response).unwrap();
    let bytes = json.into_bytes();
    let ptr = vultrino_alloc(bytes.len() as u32);
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()); }

    // Pack pointer and length into u64
    ((ptr as u64) << 32) | (bytes.len() as u64)
}
```

### vultrino_validate_params

Validate action parameters before execution:

```rust
#[no_mangle]
pub extern "C" fn vultrino_validate_params(
    action_ptr: *const u8,
    action_len: u32,
    params_ptr: *const u8,
    params_len: u32,
) -> i32 {
    // Return 0 for valid, negative for error
    0
}
```

## Request/Response Format

### Execute Request

```json
{
  "action": "do_something",
  "credential": {
    "secret_value": "my-secret",
    "api_endpoint": "https://api.example.com"
  },
  "parameters": {
    "input": "some data"
  }
}
```

### Execute Response

```json
{
  "code": 0,
  "data": "result string",
  "error": null
}
```

Result codes:
- `0`: Success
- `-1`: General error
- `-2`: Invalid action
- `-3`: Invalid parameters

## Building

Build your plugin for WASM:

```bash
cargo build --release --target wasm32-wasip1
```

The output will be at `target/wasm32-wasip1/release/my_plugin.wasm`.

## Testing Locally

1. Copy or symlink your plugin to `~/.vultrino/plugins/my-plugin/`
2. Ensure `plugin.toml` and the `.wasm` file are present
3. Start Vultrino: `vultrino web` (or `vultrino mcp` for the MCP server)
4. The plugin should be loaded automatically

## Best Practices

1. **Handle errors gracefully** — Always return proper error responses
2. **Validate inputs** — Check parameters before processing
3. **Keep secrets secure** — Never log or expose credential data
4. **Optimize size** — Use `opt-level = "s"` and LTO for smaller WASM
5. **Version carefully** — Bump version when changing the manifest
