//! WASM runtime implementations
//!
//! This module provides the WasmRuntime trait and implementations for
//! different WASM runtimes (Wasmtime for local/VPS).

use super::{WasmPtr, WASM_ABI_VERSION};
use crate::plugins::types::{CredentialTypeDefinition, McpToolDefinition, PluginManifest};
use crate::plugins::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse, Secret};
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use wasmtime::*;
use wasmtime_wasi::preview1::{WasiP1Ctx};

/// Trait for WASM runtime implementations
pub trait WasmRuntime: Send + Sync {
    /// Load a WASM module from bytes
    fn load_module(&mut self, bytes: &[u8]) -> Result<(), PluginError>;

    /// Get the ABI version from the module
    fn get_abi_version(&self) -> Result<u32, PluginError>;

    /// Execute an action
    fn execute_action(
        &self,
        action: &str,
        credential: &serde_json::Value,
        params: &serde_json::Value,
    ) -> Result<ExecuteResponse, PluginError>;

    /// Validate parameters for an action
    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError>;
}

/// Request sent to WASM plugin
#[derive(Debug, Serialize, Deserialize)]
struct WasmRequest {
    action: String,
    credential: serde_json::Value,
    parameters: serde_json::Value,
}

/// Response from WASM plugin
#[derive(Debug, Serialize, Deserialize)]
struct WasmResponse {
    code: i32,
    data: Option<String>,
    error: Option<String>,
}

/// CPU budget per plugin invocation, in wasmtime fuel units (~1 unit per
/// wasm instruction). Generous enough for heavy crypto (e.g. PGP signing),
/// small enough that a spinning plugin traps within seconds instead of
/// hanging the proxy forever.
const PLUGIN_FUEL: u64 = 5_000_000_000;

/// Hard cap on a plugin instance's linear memory growth.
const PLUGIN_MAX_MEMORY_BYTES: usize = 128 * 1024 * 1024;

/// Wall-clock bound on a single plugin invocation. Belt-and-braces on top of
/// fuel: fuel bounds wasm CPU, this bounds the caller's wait.
const PLUGIN_WALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// State for WASM store
struct WasmState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// Wasmtime-based WASM runtime
pub struct WasmtimeRuntime {
    engine: Engine,
    module: RwLock<Option<Module>>,
}

impl WasmtimeRuntime {
    /// Create a new Wasmtime runtime
    pub fn new() -> Result<Self, PluginError> {
        let mut config = Config::new();
        config.wasm_backtrace_details(WasmBacktraceDetails::Enable);
        config.consume_fuel(true);

        let engine = Engine::new(&config)
            .map_err(|e| PluginError::Wasm(format!("Engine creation failed: {}", e)))?;

        Ok(Self {
            engine,
            module: RwLock::new(None),
        })
    }

    /// Create a runtime and load a module from a file
    pub fn from_file(path: &PathBuf) -> Result<Self, PluginError> {
        let mut runtime = Self::new()?;
        let bytes = std::fs::read(path)?;
        runtime.load_module(&bytes)?;
        Ok(runtime)
    }

    /// Create a store with WASI context
    fn create_store(&self) -> Store<WasmState> {
        // Deliberately NOT inherit_stdio(): in MCP mode the host's stdout *is*
        // the JSON-RPC channel to the agent, so a plugin with the real fds
        // could leak the decrypted credential to the agent or inject protocol
        // messages. With nothing set, WASI stdin reads empty and
        // stdout/stderr discard.
        let wasi = wasmtime_wasi::WasiCtxBuilder::new().build_p1();

        let limits = StoreLimitsBuilder::new()
            .memory_size(PLUGIN_MAX_MEMORY_BYTES)
            .build();

        let mut store = Store::new(&self.engine, WasmState { wasi, limits });
        store.limiter(|state| &mut state.limits);
        // Only errors when fuel is not enabled on the engine; it always is.
        let _ = store.set_fuel(PLUGIN_FUEL);
        store
    }

    /// Create a linker with WASI imports
    fn create_linker(&self) -> Result<Linker<WasmState>, PluginError> {
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |state: &mut WasmState| &mut state.wasi)
            .map_err(|e| PluginError::Wasm(format!("Failed to add WASI to linker: {}", e)))?;
        Ok(linker)
    }

    /// Allocate memory in WASM and write data
    fn write_to_wasm(
        store: &mut Store<WasmState>,
        memory: &Memory,
        alloc_fn: &TypedFunc<u32, u32>,
        data: &[u8],
    ) -> Result<WasmPtr, PluginError> {
        let len = data.len() as u32;
        let offset = alloc_fn
            .call(&mut *store, len)
            .map_err(|e| PluginError::Wasm(format!("Allocation failed: {}", e)))?;

        memory
            .write(&mut *store, offset as usize, data)
            .map_err(|e| PluginError::Wasm(format!("Memory write failed: {}", e)))?;

        Ok(WasmPtr::new(offset, len))
    }

    /// Read data from WASM memory
    fn read_from_wasm(store: &Store<WasmState>, memory: &Memory, ptr: &WasmPtr) -> Result<Vec<u8>, PluginError> {
        let mut buffer = vec![0u8; ptr.len as usize];
        memory
            .read(store, ptr.offset as usize, &mut buffer)
            .map_err(|e| PluginError::Wasm(format!("Memory read failed: {}", e)))?;

        Ok(buffer)
    }

    /// Free memory in WASM
    fn free_in_wasm(
        store: &mut Store<WasmState>,
        free_fn: &TypedFunc<(u32, u32), ()>,
        ptr: &WasmPtr,
    ) -> Result<(), PluginError> {
        free_fn
            .call(&mut *store, (ptr.offset, ptr.len))
            .map_err(|e| PluginError::Wasm(format!("Free failed: {}", e)))?;

        Ok(())
    }
}

impl Default for WasmtimeRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create WASM runtime")
    }
}

impl WasmRuntime for WasmtimeRuntime {
    fn load_module(&mut self, bytes: &[u8]) -> Result<(), PluginError> {
        let module = Module::new(&self.engine, bytes)
            .map_err(|e| PluginError::Wasm(format!("Module loading failed: {}", e)))?;

        // Validate that required exports exist
        let exports: Vec<_> = module.exports().map(|e| e.name().to_string()).collect();

        let required = [
            "vultrino_plugin_version",
            "vultrino_execute",
            "vultrino_alloc",
            "vultrino_free",
        ];
        for name in required {
            if !exports.contains(&name.to_string()) {
                return Err(PluginError::Wasm(format!(
                    "Missing required export: {}",
                    name
                )));
            }
        }

        *self.module.write() = Some(module);
        Ok(())
    }

    fn get_abi_version(&self) -> Result<u32, PluginError> {
        let module_guard = self.module.read();
        let module = module_guard
            .as_ref()
            .ok_or_else(|| PluginError::Wasm("No module loaded".to_string()))?;

        let mut store = self.create_store();
        let linker = self.create_linker()?;
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| PluginError::Wasm(format!("Instantiation failed: {}", e)))?;

        let version_fn = instance
            .get_typed_func::<(), u32>(&mut store, "vultrino_plugin_version")
            .map_err(|e| PluginError::Wasm(format!("Failed to get version function: {}", e)))?;

        let version = version_fn
            .call(&mut store, ())
            .map_err(|e| PluginError::Wasm(format!("Version call failed: {}", e)))?;

        Ok(version)
    }

    fn execute_action(
        &self,
        action: &str,
        credential: &serde_json::Value,
        params: &serde_json::Value,
    ) -> Result<ExecuteResponse, PluginError> {
        let module_guard = self.module.read();
        let module = module_guard
            .as_ref()
            .ok_or_else(|| PluginError::Wasm("No module loaded".to_string()))?;

        let mut store = self.create_store();
        let linker = self.create_linker()?;
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| PluginError::Wasm(format!("Instantiation failed: {}", e)))?;

        // Get required functions
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PluginError::Wasm("Memory not found".to_string()))?;

        let alloc_fn = instance
            .get_typed_func::<u32, u32>(&mut store, "vultrino_alloc")
            .map_err(|e| PluginError::Wasm(format!("Failed to get alloc: {}", e)))?;

        let free_fn = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, "vultrino_free")
            .map_err(|e| PluginError::Wasm(format!("Failed to get free: {}", e)))?;

        let execute_fn = instance
            .get_typed_func::<(u32, u32), u64>(&mut store, "vultrino_execute")
            .map_err(|e| PluginError::Wasm(format!("Failed to get execute: {}", e)))?;

        // Build request
        let request = WasmRequest {
            action: action.to_string(),
            credential: credential.clone(),
            parameters: params.clone(),
        };

        let request_json = serde_json::to_string(&request)
            .map_err(|e| PluginError::Wasm(format!("Failed to serialize request: {}", e)))?;

        // Write request to WASM memory
        let request_ptr = Self::write_to_wasm(&mut store, &memory, &alloc_fn, request_json.as_bytes())?;

        // Call execute
        let result = execute_fn
            .call(&mut store, (request_ptr.offset, request_ptr.len))
            .map_err(|e| PluginError::Wasm(format!("Execute call failed: {}", e)))?;

        // Unpack result (high 32 bits = ptr, low 32 bits = len)
        let response_ptr = WasmPtr::new((result >> 32) as u32, (result & 0xFFFFFFFF) as u32);

        // Read response
        let response_bytes = Self::read_from_wasm(&store, &memory, &response_ptr)?;
        let response_str = String::from_utf8(response_bytes)
            .map_err(|e| PluginError::Wasm(format!("Invalid UTF-8 in response: {}", e)))?;

        // Free memory
        Self::free_in_wasm(&mut store, &free_fn, &response_ptr)?;

        // Parse response
        let wasm_response: WasmResponse = serde_json::from_str(&response_str)
            .map_err(|e| PluginError::Wasm(format!("Failed to parse response: {}", e)))?;

        // Convert to ExecuteResponse
        if wasm_response.code == 0 {
            let body = wasm_response.data.unwrap_or_default();
            Ok(ExecuteResponse {
                status: 200,
                headers: HashMap::new(),
                body: body.into_bytes(),
                updated_credential: None,
            })
        } else {
            let error_msg = wasm_response.error.unwrap_or_else(|| "Unknown error".to_string());
            Err(PluginError::ExecutionFailed(error_msg))
        }
    }

    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError> {
        let module_guard = self.module.read();
        let module = module_guard
            .as_ref()
            .ok_or_else(|| PluginError::Wasm("No module loaded".to_string()))?;

        let mut store = self.create_store();
        let linker = self.create_linker()?;
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| PluginError::Wasm(format!("Instantiation failed: {}", e)))?;

        // Check if validate function exists
        let validate_fn = match instance.get_typed_func::<(u32, u32, u32, u32), i32>(
            &mut store,
            "vultrino_validate_params",
        ) {
            Ok(f) => f,
            Err(_) => return Ok(()), // Validation is optional
        };

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PluginError::Wasm("Memory not found".to_string()))?;

        let alloc_fn = instance
            .get_typed_func::<u32, u32>(&mut store, "vultrino_alloc")
            .map_err(|e| PluginError::Wasm(format!("Failed to get alloc: {}", e)))?;

        // Write action and params to memory
        let action_ptr = Self::write_to_wasm(&mut store, &memory, &alloc_fn, action.as_bytes())?;
        let params_json = serde_json::to_string(params)
            .map_err(|e| PluginError::Wasm(format!("Failed to serialize params: {}", e)))?;
        let params_ptr = Self::write_to_wasm(&mut store, &memory, &alloc_fn, params_json.as_bytes())?;

        // Call validate
        let result = validate_fn
            .call(
                &mut store,
                (action_ptr.offset, action_ptr.len, params_ptr.offset, params_ptr.len),
            )
            .map_err(|e| PluginError::Wasm(format!("Validate call failed: {}", e)))?;

        match result {
            0 => Ok(()),
            -3 => Err(PluginError::InvalidParams("Invalid parameters".to_string())),
            -2 => Err(PluginError::UnsupportedAction(format!("Unknown action: {}", action))),
            _ => Err(PluginError::InvalidParams("Validation failed".to_string())),
        }
    }
}

/// WASM-based plugin implementation
pub struct WasmPlugin {
    manifest: PluginManifest,
    runtime: Arc<RwLock<WasmtimeRuntime>>,
    directory: PathBuf,
}

impl WasmPlugin {
    /// Create a new WASM plugin from a directory
    pub fn from_directory(directory: PathBuf) -> Result<Self, PluginError> {
        let manifest_path = directory.join("plugin.toml");
        let manifest = PluginManifest::from_file(&manifest_path)?;

        // Find WASM module
        let wasm_path = if let Some(module_name) = manifest.wasm_module_path() {
            directory.join(module_name)
        } else {
            // Try default name
            let default_name = format!("{}.wasm", manifest.plugin.name.replace('-', "_"));
            directory.join(default_name)
        };

        if !wasm_path.exists() {
            return Err(PluginError::Wasm(format!(
                "WASM module not found: {}",
                wasm_path.display()
            )));
        }

        let runtime = WasmtimeRuntime::from_file(&wasm_path)?;

        // Verify ABI version
        let version = runtime.get_abi_version()?;
        if version != WASM_ABI_VERSION {
            return Err(PluginError::Wasm(format!(
                "ABI version mismatch: expected {}, got {}",
                WASM_ABI_VERSION, version
            )));
        }

        Ok(Self {
            manifest,
            runtime: Arc::new(RwLock::new(runtime)),
            directory,
        })
    }

    /// Get the plugin directory
    pub fn directory(&self) -> &PathBuf {
        &self.directory
    }
}

#[async_trait]
impl Plugin for WasmPlugin {
    fn name(&self) -> &str {
        &self.manifest.plugin.name
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        // Return custom credential types for each defined type
        self.manifest
            .credential_types
            .iter()
            .map(|ct| CredentialType::Custom(format!("plugin:{}:{}", self.manifest.plugin.name, ct.name)))
            .collect()
    }

    fn supported_actions(&self) -> Vec<&str> {
        self.manifest.actions.iter().map(|a| a.name.as_str()).collect()
    }

    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError> {
        self.runtime.read().validate_params(action, params)
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        // Convert credential to JSON
        let cred_json = serde_json::to_value(&request.credential.data)
            .map_err(|e| PluginError::ExecutionFailed(format!("Failed to serialize credential: {}", e)))?;

        // Wasm execution is synchronous; run it on the blocking pool so a slow
        // plugin cannot stall the async workers serving other requests, and
        // bound the caller's wait. On timeout the detached task still ends:
        // fuel exhaustion traps the guest.
        let runtime = self.runtime.clone();
        let action = request.action.clone();
        let params = request.params.clone();
        let name = self.manifest.plugin.name.clone();
        let task = tokio::task::spawn_blocking(move || {
            runtime.read().execute_action(&action, &cred_json, &params)
        });
        match tokio::time::timeout(PLUGIN_WALL_TIMEOUT, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(join_err)) => Err(PluginError::Wasm(format!(
                "plugin '{}' execution task failed: {}",
                name, join_err
            ))),
            Err(_) => Err(PluginError::ExecutionFailed(format!(
                "plugin '{}' timed out after {}s",
                name,
                PLUGIN_WALL_TIMEOUT.as_secs()
            ))),
        }
    }

    fn manifest(&self) -> Option<&PluginManifest> {
        Some(&self.manifest)
    }

    fn credential_type_definitions(&self) -> Vec<CredentialTypeDefinition> {
        self.manifest.credential_types.clone()
    }

    fn mcp_tool_definitions(&self) -> Vec<McpToolDefinition> {
        self.manifest.mcp_tools.clone()
    }

    fn handles_credential_type(&self, type_name: &str) -> bool {
        // Check for plugin:name:type format
        if let Some(rest) = type_name.strip_prefix("plugin:") {
            if let Some((plugin_name, cred_type)) = rest.split_once(':') {
                if plugin_name == self.manifest.plugin.name {
                    return self
                        .manifest
                        .credential_types
                        .iter()
                        .any(|ct| ct.name == cred_type);
                }
            }
        }

        // Also check direct type name
        self.manifest
            .credential_types
            .iter()
            .any(|ct| ct.name == type_name)
    }

    fn parse_credential_data(
        &self,
        type_name: &str,
        form_data: &HashMap<String, String>,
    ) -> Result<CredentialData, PluginError> {
        // Find the credential type definition
        let cred_type = self
            .manifest
            .credential_types
            .iter()
            .find(|ct| ct.name == type_name)
            .ok_or_else(|| PluginError::InvalidParams(format!("Unknown credential type: {}", type_name)))?;

        // Validate required fields and build credential data
        let mut secrets = HashMap::new();

        for field in &cred_type.fields {
            let value = form_data.get(&field.name);

            if field.required && value.map(|v| v.is_empty()).unwrap_or(true) {
                return Err(PluginError::InvalidParams(format!(
                    "Required field '{}' is missing",
                    field.name
                )));
            }

            if let Some(v) = value {
                if !v.is_empty() {
                    // Store all fields as secrets for Custom credential type
                    secrets.insert(field.name.clone(), Secret::new(v.clone()));
                }
            }
        }

        Ok(CredentialData::Custom(secrets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_is_fuel_limited() {
        let runtime = WasmtimeRuntime::new().unwrap();
        let store = runtime.create_store();
        assert_eq!(store.get_fuel().unwrap(), PLUGIN_FUEL);
    }
}
