//! MCP Server implementation
//!
//! Exposes Vultrino capabilities through the Model Context Protocol.

use super::types::*;
use crate::approval::ApprovalStatus;
use crate::auth::{AuthManager, AuthResult, Permission, UseToken};
use crate::server::{ExecAuth, VultrinoServer};
use crate::{CredentialMetadata, ExecuteRequest, ExecutionOutcome};
use glob::Pattern;
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// A successfully authenticated MCP caller — either a long-lived API key or a
/// narrow, ephemeral use token.
enum McpPrincipal {
    ApiKey(AuthResult),
    UseToken { auth: AuthResult, token: Box<UseToken> },
}

impl McpPrincipal {
    /// Stable id of the underlying principal (api key id or use token id).
    fn id(&self) -> &str {
        match self {
            McpPrincipal::ApiKey(a) => &a.api_key.id,
            McpPrincipal::UseToken { token, .. } => &token.id,
        }
    }

    /// The permission/scope source for this principal.
    fn auth(&self) -> &AuthResult {
        match self {
            McpPrincipal::ApiKey(a) => a,
            McpPrincipal::UseToken { auth, .. } => auth,
        }
    }
}


/// MCP Server for Vultrino
pub struct McpServer {
    /// Vultrino server instance. Held as a bare `Arc` (not behind a `RwLock`):
    /// every MCP method only ever *reads* the server — the engine mutates its own
    /// interior state behind its internal locks — so the transport never needs a
    /// write lock. This lets the networked HTTP transport drive the SAME handler
    /// off the web process's shared `Arc<VultrinoServer>` (see `web::mcp_http`).
    vultrino: Arc<VultrinoServer>,
    /// Whether initialized
    initialized: bool,
    /// Auth manager for validating API keys (required)
    auth_manager: Arc<RwLock<AuthManager>>,
}

impl McpServer {
    /// Create a new MCP server with auth manager (required)
    pub fn new(vultrino: Arc<VultrinoServer>, auth_manager: Arc<RwLock<AuthManager>>) -> Self {
        Self {
            vultrino,
            initialized: false,
            auth_manager,
        }
    }

    /// Validate an API key and return auth result
    async fn validate_api_key(&self, api_key: &str) -> Result<AuthResult, String> {
        let manager = self.auth_manager.read().await;
        let (key, role) = manager
            .validate_key(api_key)
            .map_err(|e| format!("Invalid API key: {}", e))?;

        Ok(AuthResult {
            api_key: key,
            role,
        })
    }

    /// Check permission for a validated auth
    fn check_permission(auth: &AuthResult, permission: Permission) -> Result<(), String> {
        if !auth.has_permission(permission) {
            return Err(format!("Permission denied: requires '{}' permission", permission));
        }
        Ok(())
    }

    /// Check credential access for a validated auth
    fn check_credential_access(auth: &AuthResult, alias: &str) -> Result<(), String> {
        if !auth.can_access_credential(alias) {
            return Err(format!("Access denied to credential: {}", alias));
        }
        Ok(())
    }

    /// Resolve a presented secret into an authenticated principal. The secret
    /// may be an API key (`vk_...`) or a use token (`vut_...`).
    async fn resolve_principal(&self, secret: &str) -> Result<McpPrincipal, String> {
        if UseToken::looks_like_token(secret) {
            // Use tokens live in storage; reload so a token minted by the web UI
            // or CLI after this server started is visible.
            let vultrino = &self.vultrino;
            let _ = vultrino.storage().reload().await;
            let token = vultrino
                .storage()
                .get_use_token_by_hash(&UseToken::hash(secret))
                .await
                .map_err(|e| format!("Storage error: {}", e))?
                .ok_or_else(|| "Invalid use token".to_string())?;

            token
                .check_usable()
                .map_err(|e| format!("Use token cannot be used: {}", e))?;

            let auth = AuthResult::for_use_token(&token);
            Ok(McpPrincipal::UseToken {
                auth,
                token: Box::new(token),
            })
        } else {
            let auth = self.validate_api_key(secret).await?;
            Ok(McpPrincipal::ApiKey(auth))
        }
    }

    /// Resolve a secret to a principal for a **read-only** operation (polling an
    /// approval). Unlike [`Self::resolve_principal`], a use token that has become
    /// exhausted or expired is still accepted — polling is not an execution, and
    /// a single-use token legitimately becomes exhausted exactly when its
    /// approved action runs. A *revoked* token is still rejected.
    async fn resolve_principal_for_read(&self, secret: &str) -> Result<McpPrincipal, String> {
        if UseToken::looks_like_token(secret) {
            let vultrino = &self.vultrino;
            let _ = vultrino.storage().reload().await;
            let token = vultrino
                .storage()
                .get_use_token_by_hash(&UseToken::hash(secret))
                .await
                .map_err(|e| format!("Storage error: {}", e))?
                .ok_or_else(|| "Invalid use token".to_string())?;

            if token.revoked {
                return Err("Use token has been revoked".to_string());
            }
            let auth = AuthResult::for_use_token(&token);
            Ok(McpPrincipal::UseToken {
                auth,
                token: Box::new(token),
            })
        } else {
            let auth = self.validate_api_key(secret).await?;
            Ok(McpPrincipal::ApiKey(auth))
        }
    }

    /// Build an [`ExecAuth`] for the given principal. A use token's credential
    /// and action scope is enforced authoritatively in the server
    /// (`execute_gated`), so this is a straight conversion.
    fn build_exec_auth(principal: &McpPrincipal) -> ExecAuth {
        match principal {
            McpPrincipal::ApiKey(auth) => ExecAuth::from_api_key(auth.clone()),
            McpPrincipal::UseToken { token, .. } => ExecAuth::from_use_token((**token).clone()),
        }
    }

    /// Render the agent-facing message for an action that is now waiting on a
    /// human approval. Clarity here is the whole point: the agent must
    /// understand it is blocked and exactly how to retrieve the result later.
    fn format_pending(approval: &crate::approval::ApprovalRequest) -> String {
        format!(
            "\u{23F3} APPROVAL REQUIRED — this action has NOT run yet.\n\n\
             Your request ({summary}) needs a human to approve it before Vultrino will execute it. \
             No result is available yet, and nothing has changed on the target system.\n\n\
             approval_id: {id}\n\
             status: pending\n\
             expires: {expires}\n\n\
             HOW TO PROCEED:\n\
             1. Call the `check_approval` tool with approval_id \"{id}\", re-presenting the same \
             credential (API key or use token) you made this request with — only that same \
             principal may poll this approval.\n\
             2. If it returns \"pending\", a human has not decided yet — wait about 10-30 seconds, \
             then call `check_approval` again.\n\
             3. Once approved, `check_approval` will run the action and return the real result.\n\
             4. If denied or expired, `check_approval` will tell you, and you should not retry.",
            summary = approval.summary,
            id = approval.id,
            expires = approval.expires_at.format("%Y-%m-%d %H:%M UTC"),
        )
    }

    /// Run the MCP server over stdio
    pub async fn run_stdio(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        info!("MCP server starting on stdio");

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;

            if bytes_read == 0 {
                // EOF
                break;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            debug!(request = %line, "Received MCP request");

            let response = self.handle_message(line).await;

            if let Some(response) = response {
                let response_str = serde_json::to_string(&response)?;
                debug!(response = %response_str, "Sending MCP response");
                stdout.write_all(response_str.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }

        info!("MCP server shutting down");
        Ok(())
    }

    /// Drive a single JSON-RPC message and return the response, for in-process
    /// testing (mirrors `WebServer::into_router`). Production drives messages via
    /// [`Self::run_stdio`]; this exposes the same handler without binding stdio so
    /// the connector capability flow (`tools/list` / `tools/call`) is testable.
    pub async fn handle_jsonrpc(&mut self, message: &str) -> Option<JsonRpcResponse> {
        self.handle_message(message).await
    }

    /// Handle a single JSON-RPC message
    async fn handle_message(&mut self, message: &str) -> Option<JsonRpcResponse> {
        // Parse JSON-RPC request
        let request: JsonRpcRequest = match serde_json::from_str(message) {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to parse JSON-RPC request");
                return Some(JsonRpcResponse::error(
                    JsonRpcId::Null,
                    PARSE_ERROR,
                    format!("Parse error: {}", e),
                ));
            }
        };

        // Route to handler
        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(&request).await,
            "initialized" => {
                // Notification, no response
                self.initialized = true;
                info!("MCP client initialized");
                return None;
            }
            "tools/list" => self.handle_tools_list(&request).await,
            "tools/call" => self.handle_tools_call(&request).await,
            "resources/list" => self.handle_resources_list(&request).await,
            "ping" => Ok(json!({})),
            method => {
                warn!(method = %method, "Unknown MCP method");
                Err((METHOD_NOT_FOUND, format!("Method not found: {}", method)))
            }
        };

        match result {
            Ok(value) => Some(JsonRpcResponse::success(request.id, value)),
            Err((code, message)) => Some(JsonRpcResponse::error(request.id, code, message)),
        }
    }

    /// Handle initialize request
    async fn handle_initialize(
        &mut self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                resources: Some(ResourcesCapability {
                    subscribe: Some(false),
                    list_changed: Some(false),
                }),
                prompts: None,
            },
            server_info: ServerInfo {
                name: "vultrino".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "Vultrino is a credential proxy for AI agents. Use the available tools to:\n\
                 - List available credentials (without seeing secrets)\n\
                 - Make authenticated HTTP requests to APIs\n\
                 - Get information about specific credentials\n\n\
                 The credentials themselves are never exposed - only their aliases and metadata."
                    .to_string(),
            ),
        };

        serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
    }

    /// Handle tools/list request
    async fn handle_tools_list(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        let mut tools = vec![
            Tool {
                name: "list_credentials".to_string(),
                description: "List available credential aliases. Returns metadata about stored \
                             credentials without exposing the actual secrets. Use this to discover \
                             what credentials are available for making authenticated requests."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "Optional glob pattern to filter credentials (e.g., 'github-*')"
                        }
                    },
                    "required": ["api_key"]
                }),
            },
            Tool {
                name: "http_request".to_string(),
                description: "Make an authenticated HTTP request using stored credentials. \
                             Vultrino will inject the appropriate authentication headers \
                             without exposing the credential values."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                        },
                        "credential": {
                            "type": "string",
                            "description": "The credential alias to use for the request"
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)",
                            "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                        },
                        "url": {
                            "type": "string",
                            "description": "The target URL for the request"
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers to include",
                            "additionalProperties": { "type": "string" }
                        },
                        "body": {
                            "description": "Request body (for POST, PUT, PATCH requests)"
                        },
                        "query": {
                            "type": "object",
                            "description": "Query parameters to append to the URL",
                            "additionalProperties": { "type": "string" }
                        }
                    },
                    "required": ["api_key", "credential", "method", "url"]
                }),
            },
            Tool {
                name: "get_credential_info".to_string(),
                description: "Get detailed information about a specific credential, including \
                             its type and metadata. Does not expose the actual secret values."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                        },
                        "credential": {
                            "type": "string",
                            "description": "The credential alias or ID"
                        }
                    },
                    "required": ["api_key", "credential"]
                }),
            },
            Tool {
                name: "check_approval".to_string(),
                description: "Check the status of an action that is awaiting human approval. \
                             When a tool call returns 'APPROVAL REQUIRED' with an approval_id, poll \
                             this tool with that id. While the status is 'pending', a human has not \
                             decided yet \u{2014} wait ~10-30 seconds and call again. Once approved, this \
                             tool runs the original action and returns its real result. If denied or \
                             expired, it says so and you should not retry. You can only poll \
                             approvals created by the same principal (API key or use token) that \
                             made the original request."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "description": "The same Vultrino API key or use token you made the original request with"
                        },
                        "approval_id": {
                            "type": "string",
                            "description": "The approval_id returned by the gated tool call (starts with 'appr_')"
                        }
                    },
                    "required": ["api_key", "approval_id"]
                }),
            },
        ];

        // Add tools from every live plugin in the registry (built-in + loaded
        // installed plugins). The registry is the single source of truth —
        // disabled installed plugins are filtered out at load time.
        tools.extend(self.get_plugin_tools().await);

        // Connector model: a scoped USE-TOKEN (vut_) agent — a harness connected via
        // a govder-provisioned use-token — sees ONLY its granted named capabilities,
        // never vultrino's generic built-in tools (http_request / ssh_* / postgres_* /
        // list_credentials / get_credential_info). The generic surface is for a direct
        // admin/operator (vk_) key. We keep `check_approval` (the control tool an agent
        // legitimately needs to poll an approval it triggered). The built-ins are still
        // default-deny enforced regardless; this is about not OFFERING a generic tool to
        // a governed agent (it must act through its named capabilities).
        if matches!(
            self.resolve_list_principal(request).await,
            Some(McpPrincipal::UseToken { .. })
        ) {
            tools.retain(|t| t.name == "check_approval");
        }

        // Connector M1: add the CAPABILITIES (named MCP tools) this principal is
        // permitted to use. tools/list optionally carries the caller's Bearer
        // secret (api_key/token) in its params; when present and valid, we resolve
        // the principal and surface only the capabilities whose action the
        // principal's policy ALLOWS — a denied/halted/unscoped principal sees
        // none. (No secret presented → no principal → no capability tools, since a
        // capability is meaningless without a principal to gate it.)
        tools.extend(self.get_capability_tools(request).await);

        let result = ToolsListResult { tools };
        serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
    }

    /// Resolve the optional principal for a `tools/list` call from the secret in
    /// its params (`api_key` or `token`; the HTTP transport injects the header
    /// Bearer here). Read-only (does not consume a single-use token); `None` when
    /// absent or invalid — `tools/list` stays a benign discovery call.
    async fn resolve_list_principal(&self, request: &JsonRpcRequest) -> Option<McpPrincipal> {
        let secret = request
            .params
            .as_ref()
            .and_then(|p| {
                p.get("api_key")
                    .or_else(|| p.get("token"))
                    .and_then(|v| v.as_str())
            })?
            .to_string();
        self.resolve_principal_for_read(&secret).await.ok()
    }

    /// Enumerate the capability (named-MCP-tool) tools the calling principal is
    /// permitted to see (connector M1). The principal is resolved from an optional
    /// `api_key`/`token` field in the `tools/list` params; absent or invalid → no
    /// capability tools (they require a principal to be policy-gated). Each allowed
    /// capability becomes a named tool with the operator's input schema (plus the
    /// injected `api_key` auth field) and description.
    async fn get_capability_tools(&self, request: &JsonRpcRequest) -> Vec<Tool> {
        // Resolve the calling principal from the list params (read-only; the HTTP
        // transport injects the header Bearer there). Absent/invalid → no capability
        // tools (they require a principal to be policy-gated).
        let Some(principal) = self.resolve_list_principal(request).await else {
            return Vec::new();
        };
        let auth = principal.auth().clone();

        let capabilities = self.vultrino.list_capabilities_for(Some(&auth)).await;

        capabilities
            .into_iter()
            // An LLM-proxy capability is the model channel (it backs `POST /llm`),
            // not an LLM-callable tool — never surface it in tools/list.
            .filter(|cap| !cap.is_llm_proxy())
            .map(|cap| Tool {
                name: cap.tool_name.clone(),
                description: if cap.description.trim().is_empty() {
                    format!("{} (vultrino capability)", cap.action)
                } else {
                    cap.description.clone()
                },
                input_schema: cap.mcp_input_schema(),
            })
            .collect()
    }

    /// Enumerate MCP tools from every live plugin in the registry.
    ///
    /// Tool names are prefixed with the plugin name — `{plugin}_{tool}` — so
    /// two plugins can expose same-named tools without collision. Schemas are
    /// sourced in priority order:
    ///   1. Manifest-derived (installed plugins: pulls action parameters)
    ///   2. `McpToolDefinition::input_schema` (built-in plugins set this)
    ///   3. A minimal `{credential}` default
    async fn get_plugin_tools(&self) -> Vec<Tool> {
        let plugins = self.vultrino.plugins().all();

        let mut tools = Vec::new();
        for plugin in plugins {
            let plugin_name = plugin.name().to_string();
            let manifest = plugin.manifest();

            for mcp_tool in plugin.mcp_tool_definitions() {
                let mut input_schema = manifest
                    .and_then(|m| m.actions.iter().find(|a| a.name == mcp_tool.action))
                    .map(|action| mcp_tool.generate_input_schema(action))
                    .or_else(|| mcp_tool.input_schema.clone())
                    .unwrap_or_else(|| {
                        json!({
                            "type": "object",
                            "properties": {
                                "credential": {
                                    "type": "string",
                                    "description": "Credential alias to use"
                                }
                            },
                            "required": ["credential"]
                        })
                    });

                if let Some(props) = input_schema.get_mut("properties") {
                    props["api_key"] = json!({
                        "type": "string",
                        "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                    });
                }
                if let Some(required) = input_schema.get_mut("required") {
                    if let Some(arr) = required.as_array_mut() {
                        if !arr.iter().any(|v| v.as_str() == Some("api_key")) {
                            arr.insert(0, json!("api_key"));
                        }
                    }
                }

                let tool_name = format!("{}_{}", plugin_name.replace('-', "_"), mcp_tool.name);
                let description = mcp_tool
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("{} from {} plugin", mcp_tool.action, plugin_name));

                tools.push(Tool {
                    name: tool_name,
                    description,
                    input_schema,
                });
            }
        }
        tools
    }

    /// Handle tools/call request
    async fn handle_tools_call(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        let params: ToolCallParams = request
            .params
            .as_ref()
            .and_then(|p| serde_json::from_value(p.clone()).ok())
            .ok_or_else(|| (INVALID_PARAMS, "Missing or invalid params".to_string()))?;

        // Principal ALLOWLIST gate (GLM review #1 + Codex pass 4): a use-token
        // (`vut_`) surfaces ONLY its granted named capabilities + check_approval at
        // tools/list, but tools/call dispatches purely by name. A denylist of the
        // three generic built-ins is INSUFFICIENT — any other name (e.g. `ssh_run`,
        // `postgres_run_sql`, `ssh_deploy`) falls through to `try_plugin_tool` and
        // runs a raw plugin tool, bypassing the named-capability registry. So for a
        // use-token, ALLOW ONLY `check_approval` and a tool name that resolves to a
        // stored named Capability; reject everything else here. (Admin `vk_` keys
        // keep the full surface — they skip this gate.)
        let caller_is_use_token = params
            .arguments
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(|k| k.starts_with("vut_"))
            .unwrap_or(false);
        if caller_is_use_token {
            let is_named_capability =
                self.vultrino.capability_by_tool_name(&params.name).await.is_some();
            if params.name != "check_approval" && !is_named_capability {
                return Err((
                    INVALID_PARAMS,
                    format!(
                        "tool '{}' is not available to a use-token; call your granted named capabilities instead",
                        params.name
                    ),
                ));
            }
        }

        let result = match params.name.as_str() {
            "list_credentials" => self.tool_list_credentials(params.arguments).await,
            "http_request" => self.tool_http_request(params.arguments).await,
            "get_credential_info" => self.tool_get_credential_info(params.arguments).await,
            "check_approval" => self.tool_check_approval(params.arguments).await,
            tool => {
                // Connector M1: a named capability tool? Look it up by tool name
                // and run it through the SAME enforced path the generic tools use.
                // Checked before the plugin fallthrough so a capability can shadow
                // a plugin-prefixed name only if it owns that exact name (capability
                // names are validated to not collide with the generic built-ins).
                let capability = {
                    let vultrino = &self.vultrino;
                    vultrino.capability_by_tool_name(tool).await
                };
                if let Some(capability) = capability {
                    self.tool_call_capability(&capability, params.arguments).await
                } else if let Some(result) = self.try_plugin_tool(tool, params.arguments).await {
                    // Otherwise check if it's a plugin tool (format: plugin_tool).
                    result
                } else {
                    return Err((INVALID_PARAMS, format!("Unknown tool: {}", tool)));
                }
            }
        };

        match result {
            Ok(content) => {
                let result = ToolCallResult {
                    content,
                    is_error: None,
                };
                serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
            }
            Err(e) => {
                let result = ToolCallResult {
                    content: vec![ToolContent::Text { text: e }],
                    is_error: Some(true),
                };
                serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
            }
        }
    }

    /// Try to execute a plugin tool
    async fn try_plugin_tool(
        &self,
        tool_name: &str,
        args: serde_json::Value,
    ) -> Option<Result<Vec<ToolContent>, String>> {
        // Extract the presented secret (API key or use token).
        let secret = match args.get("api_key").and_then(|v| v.as_str()) {
            Some(k) => k,
            None => return Some(Err("Missing 'api_key' argument".to_string())),
        };

        let principal = match self.resolve_principal(secret).await {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };

        // Walk the registry (single source of truth for live plugins) to
        // find the plugin that owns `tool_name`.
        let plugins = self.vultrino.plugins().all();

        for plugin in plugins {
            let plugin_name = plugin.name().to_string();
            let prefix = format!("{}_", plugin_name.replace('-', "_"));
            if !tool_name.starts_with(&prefix) {
                continue;
            }
            let short_name = &tool_name[prefix.len()..];

            let mcp_tool = match plugin
                .mcp_tool_definitions()
                .into_iter()
                .find(|t| t.name == short_name)
            {
                Some(t) => t,
                None => continue,
            };

            let credential = match args.get("credential").and_then(|v| v.as_str()) {
                Some(c) => c.to_string(),
                None => return Some(Err("Missing 'credential' argument".to_string())),
            };

            let full_action = format!("{}.{}", plugin_name, mcp_tool.action);
            let exec_auth = Self::build_exec_auth(&principal);

            // Strip the caller's bearer secret out of the action params before
            // forwarding them to the plugin. `args` contains the `api_key`
            // (which may be an API key OR a use token) used to authenticate this
            // call; it must never reach a plugin — and, when the action is
            // approval-gated, must never be persisted into the approval record.
            let mut params = args.clone();
            if let Some(obj) = params.as_object_mut() {
                obj.remove("api_key");
            }

            let request = ExecuteRequest {
                credential: credential.clone(),
                action: full_action.clone(),
                params,
            };

            let vultrino = &self.vultrino;
            let response = match vultrino.execute_gated(request, exec_auth).await {
                Ok(ExecutionOutcome::Completed(resp)) => resp,
                Ok(ExecutionOutcome::Pending(approval)) => {
                    return Some(Ok(vec![ToolContent::Text {
                        text: Self::format_pending(&approval),
                    }]));
                }
                Err(e) => return Some(Err(format!("Plugin execution failed: {}", e))),
            };

            let body_text = String::from_utf8_lossy(&response.body);
            let output = format!(
                "Plugin: {} | Action: {}\nStatus: {}\n\nResult:\n{}",
                plugin_name, mcp_tool.action, response.status, body_text
            );
            return Some(Ok(vec![ToolContent::Text { text: output }]));
        }

        None
    }

    /// Execute a named **capability** tool (connector M1).
    ///
    /// Compiles the capability and the LLM args into an [`ExecuteRequest`] (action
    /// = the capability's V8 action label; credential = its `credential_ref`;
    /// params mapped from the args within the capability's target scope) and runs
    /// it through the SAME enforced path the generic tools use, `execute_gated`,
    /// which applies permission, credential-access, V11 tenant isolation,
    /// default-deny policy, single-use token consumption, V7 egress scrub, and the
    /// feir/leria emits. A principal whose policy does NOT allow the action is
    /// denied here (returns an MCP error), so even though the tool is normally
    /// hidden in `tools/list`, a guessed/forged `tools/call` cannot bypass the
    /// gate. The Bearer secret (`api_key`) is stripped from the args before they
    /// reach the plugin.
    async fn tool_call_capability(
        &self,
        capability: &crate::capability::Capability,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        // An LLM-proxy capability is the model channel (it backs `POST /llm`), not
        // an LLM-callable tool — it is hidden from tools/list, and a guessed/forged
        // tools/call against its name is rejected here (defense in depth).
        if capability.is_llm_proxy() {
            return Err(format!("Unknown tool: {}", capability.tool_name));
        }

        // The agent presents its use token / API key as the `api_key` argument,
        // mirroring the generic tools (and the architecture's Bearer model).
        let secret = match args.get("api_key").and_then(|v| v.as_str()) {
            Some(k) => k.to_string(),
            None => return Err("Missing 'api_key' argument".to_string()),
        };

        let principal = self.resolve_principal(&secret).await?;
        let exec_auth = Self::build_exec_auth(&principal);

        // Strip the bearer secret out of the args BEFORE mapping them into the
        // action params — it must never reach a plugin or be persisted into an
        // approval record (same invariant as try_plugin_tool).
        let mut clean_args = args.clone();
        if let Some(obj) = clean_args.as_object_mut() {
            obj.remove("api_key");
        }

        // Resolve the canonical plugin for this capability's action so we shape the
        // params correctly (http canonical request vs. plugin-param overlay).
        let (canonical_action, _label) = self
            .vultrino
            .config()
            .resolve_action(&capability.action);
        let plugin_name = canonical_action
            .split_once('.')
            .map(|(p, _)| p)
            .unwrap_or("http")
            .to_string();

        let params = crate::capability::build_action_params(capability, &plugin_name, &clean_args);

        // The request carries the capability's action label (V8) verbatim;
        // execute_gated resolves it to the canonical action and enforces the
        // use-token's action scope against both forms.
        let request = ExecuteRequest {
            credential: capability.credential_ref.clone(),
            action: capability.action.clone(),
            params,
        };

        let vultrino = &self.vultrino;
        let response = match vultrino.execute_gated(request, exec_auth).await {
            Ok(ExecutionOutcome::Completed(resp)) => resp,
            Ok(ExecutionOutcome::Pending(approval)) => {
                return Ok(vec![ToolContent::Text {
                    text: Self::format_pending(&approval),
                }]);
            }
            // A policy/scope/tenant denial surfaces as an MCP tool error, never a
            // bypass — the agent is told it is not permitted.
            Err(e) => return Err(format!("Capability '{}' denied or failed: {}", capability.tool_name, e)),
        };

        // The body has already been egress-scrubbed inside run_action, so no
        // secret/PII reflection leaks in the tool output.
        let body_text = String::from_utf8_lossy(&response.body);
        let formatted_body = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|j| serde_json::to_string_pretty(&j).ok())
            .unwrap_or_else(|| body_text.to_string());
        let output = format!(
            "Capability: {} | Action: {}\nStatus: {}\n\nResult:\n{}",
            capability.tool_name, capability.action, response.status, formatted_body
        );
        Ok(vec![ToolContent::Text { text: output }])
    }

    /// Handle resources/list request
    async fn handle_resources_list(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        // Principal-scoped vault enumeration (GLM review #3 + Codex pass 4). This
        // gate lives in the SHARED handler so BOTH stdio and HTTP are covered
        // uniformly (the HTTP transport injects the Bearer into params.api_key):
        //   - absent/invalid key  -> empty (fail-closed: never enumerate the vault
        //                            to an unauthenticated caller).
        //   - UseToken (vut_)     -> empty (a governed agent has named capabilities,
        //                            not vault-enumeration rights).
        //   - ApiKey (vk_)        -> only the credentials its role can access.
        let empty = ResourcesListResult { resources: vec![] };
        let api_key = request
            .params
            .as_ref()
            .and_then(|p| p.get("api_key"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if api_key.is_empty() {
            return serde_json::to_value(empty).map_err(|e| (INTERNAL_ERROR, e.to_string()));
        }
        let principal = match self.resolve_principal_for_read(api_key).await {
            Ok(p) => p,
            Err(_) => return serde_json::to_value(empty).map_err(|e| (INTERNAL_ERROR, e.to_string())),
        };
        if matches!(principal, McpPrincipal::UseToken { .. }) {
            return serde_json::to_value(empty).map_err(|e| (INTERNAL_ERROR, e.to_string()));
        }
        let auth = principal.auth();

        let vultrino = &self.vultrino;
        let credentials = vultrino
            .storage()
            .list()
            .await
            .map_err(|e| (INTERNAL_ERROR, e.to_string()))?;

        let resources: Vec<Resource> = credentials
            .iter()
            .filter(|c| auth.can_access_credential(&c.alias))
            .map(|c| Resource {
                uri: format!("vultrino://credential/{}", c.alias),
                name: c.alias.clone(),
                description: c.metadata.get("description").cloned(),
                mime_type: Some("application/json".to_string()),
            })
            .collect();

        let result = ResourcesListResult { resources };
        serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
    }

    /// Tool: list_credentials
    async fn tool_list_credentials(
        &self,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        #[derive(serde::Deserialize)]
        struct Args {
            api_key: String,
            pattern: Option<String>,
        }

        let args: Args = serde_json::from_value(args)
            .map_err(|e| format!("Invalid arguments: {}. api_key is required.", e))?;

        // Authenticate (API key or use token) and check permission.
        let principal = self.resolve_principal(&args.api_key).await?;
        let auth = principal.auth();
        Self::check_permission(auth, Permission::Read)?;

        let vultrino = &self.vultrino;
        let credentials = vultrino
            .storage()
            .list()
            .await
            .map_err(|e| format!("Failed to list credentials: {}", e))?;

        // Filter by pattern if provided
        let filtered: Vec<&CredentialMetadata> = if let Some(pattern) = &args.pattern {
            let glob = Pattern::new(pattern).map_err(|e| format!("Invalid pattern: {}", e))?;
            credentials.iter().filter(|c| glob.matches(&c.alias)).collect()
        } else {
            credentials.iter().collect()
        };

        // Filter by credential scopes based on role
        let filtered: Vec<&CredentialMetadata> = filtered
            .into_iter()
            .filter(|c| auth.can_access_credential(&c.alias))
            .collect();

        // Format output
        let output = if filtered.is_empty() {
            "No credentials found (or none accessible with your API key).".to_string()
        } else {
            let mut lines = vec!["Available credentials:".to_string()];
            for cred in filtered {
                let desc = cred
                    .metadata
                    .get("description")
                    .map(|d| format!(" - {}", d))
                    .unwrap_or_default();
                lines.push(format!(
                    "- {} (type: {}){}",
                    cred.alias, cred.credential_type, desc
                ));
            }
            lines.join("\n")
        };

        Ok(vec![ToolContent::Text { text: output }])
    }

    /// Tool: http_request
    async fn tool_http_request(
        &self,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        let args: HttpRequestArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}. api_key is required.", e))?;

        // Resolve the caller (API key or use token) and build the auth context.
        let principal = self.resolve_principal(&args.api_key).await?;
        let exec_auth = Self::build_exec_auth(&principal);

        // Build execute request
        let request = ExecuteRequest {
            credential: args.credential.clone(),
            action: "http.request".to_string(),
            params: json!({
                "method": args.method,
                "url": args.url,
                "headers": args.headers,
                "body": args.body,
                "query": args.query,
            }),
        };

        // Execute through Vultrino, gating on approval when required.
        let vultrino = &self.vultrino;
        let response = match vultrino
            .execute_gated(request, exec_auth)
            .await
            .map_err(|e| format!("Request failed: {}", e))?
        {
            ExecutionOutcome::Completed(resp) => resp,
            ExecutionOutcome::Pending(approval) => {
                return Ok(vec![ToolContent::Text {
                    text: Self::format_pending(&approval),
                }]);
            }
        };

        // Format response
        let body_text = String::from_utf8_lossy(&response.body);

        // Try to pretty-print JSON
        let formatted_body = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text)
        {
            serde_json::to_string_pretty(&json).unwrap_or_else(|_| body_text.to_string())
        } else {
            body_text.to_string()
        };

        let output = format!(
            "HTTP {} {}\nStatus: {}\n\nResponse:\n{}",
            args.method, args.url, response.status, formatted_body
        );

        Ok(vec![ToolContent::Text { text: output }])
    }

    /// Tool: get_credential_info
    async fn tool_get_credential_info(
        &self,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        let args: GetCredentialInfoArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}. api_key is required.", e))?;

        // Authenticate (API key or use token) and check permissions.
        let principal = self.resolve_principal(&args.api_key).await?;
        let auth = principal.auth();
        Self::check_permission(auth, Permission::Read)?;
        Self::check_credential_access(auth, &args.credential)?;

        let vultrino = &self.vultrino;

        // Try to get by alias first, then by ID
        let storage = vultrino.storage();
        let credential = storage
            .get_by_alias(&args.credential)
            .await
            .map_err(|e| format!("Storage error: {}", e))?
            .or(storage
                .get(&args.credential)
                .await
                .map_err(|e| format!("Storage error: {}", e))?);

        match credential {
            Some(cred) => {
                let mut info = vec![
                    format!("Alias: {}", cred.alias),
                    format!("ID: {}", cred.id),
                    format!("Type: {}", cred.credential_type),
                    format!("Created: {}", cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")),
                    format!("Updated: {}", cred.updated_at.format("%Y-%m-%d %H:%M:%S UTC")),
                ];

                if !cred.metadata.is_empty() {
                    info.push("\nMetadata:".to_string());
                    for (key, value) in &cred.metadata {
                        info.push(format!("  {}: {}", key, value));
                    }
                }

                Ok(vec![ToolContent::Text {
                    text: info.join("\n"),
                }])
            }
            None => Err(format!("Credential not found: {}", args.credential)),
        }
    }

    /// Tool: check_approval — poll a pending approval, and run the action once
    /// it has been approved, returning the real result.
    async fn tool_check_approval(
        &self,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        #[derive(serde::Deserialize)]
        struct Args {
            api_key: String,
            approval_id: String,
        }
        let args: Args = serde_json::from_value(args)
            .map_err(|e| format!("Invalid arguments: {}. api_key and approval_id are required.", e))?;

        // Authenticate the caller (API key or use token). Polling is a read, so
        // an exhausted/expired use token is still allowed — only revoked is not.
        let principal = self.resolve_principal_for_read(&args.api_key).await?;
        let caller_id = principal.id().to_string();

        // The ownership check is enforced inside check_and_resume_approval BEFORE
        // any execution, so a non-owner can never trigger the approved action.
        let approval = self
            .vultrino
            .check_and_resume_approval(&args.approval_id, Some(&caller_id))
            .await
            .map_err(|e| e.to_string())?;

        // V12: surface dual-control (M-of-N) progress so an MCP agent knows it's
        // awaiting additional distinct approvers, not stalled (only meaningful
        // while the request is still open — it's only used by the open arms below).
        let dual_control_note = if approval.status.is_open() && approval.effective_required_approvals() > 1 {
            format!(
                " Dual control: {} of {} distinct approvals so far ({} more needed).",
                approval.signoffs.len(),
                approval.effective_required_approvals(),
                approval.approvals_remaining(),
            )
        } else {
            String::new()
        };
        let text = match approval.status {
            ApprovalStatus::Pending => format!(
                "\u{23F3} Approval {} is still PENDING. A human has not decided yet.{} Wait about \
                 10-30 seconds, then call `check_approval` again with the same approval_id.\nExpires: {}",
                approval.id,
                dual_control_note,
                approval.expires_at.format("%Y-%m-%d %H:%M UTC"),
            ),
            // V5: escalated is still awaiting a decision — same agent contract.
            ApprovalStatus::Escalated => format!(
                "\u{23F3} Approval {} is still PENDING (ESCALATED to a second reviewer window). \
                 A human has not decided yet.{} Wait about 10-30 seconds, then call `check_approval` \
                 again with the same approval_id.\nExpires: {}",
                approval.id,
                dual_control_note,
                approval.expires_at.format("%Y-%m-%d %H:%M UTC"),
            ),
            ApprovalStatus::Denied => format!(
                "\u{274C} Approval {} was DENIED{}. The action did not run. Do not retry.",
                approval.id,
                approval
                    .decision_note
                    .as_deref()
                    .map(|n| format!(" (reason: {})", n))
                    .unwrap_or_default(),
            ),
            ApprovalStatus::Expired => format!(
                "\u{23F0} Approval {} EXPIRED before a human decided. The action did not run. \
                 Submit a fresh request if you still need it.",
                approval.id,
            ),
            ApprovalStatus::Approved => {
                if !approval.executed {
                    // Approved, but the action hasn't finished running yet (another
                    // worker holds the execution claim, or a transient start error).
                    let note = approval
                        .result_error
                        .as_deref()
                        .map(|e| format!(" ({})", e))
                        .unwrap_or_default();
                    format!(
                        "\u{2705} Approval {} was APPROVED and the action is being executed now{}. \
                         Wait about 10-30 seconds, then call `check_approval` again with the same \
                         approval_id to get the result.",
                        approval.id, note
                    )
                } else if let Some(err) = &approval.result_error {
                    format!(
                        "\u{2705} Approval {} was APPROVED, but the action then failed to execute:\n{}",
                        approval.id, err
                    )
                } else {
                    let status = approval.result_status.unwrap_or(0);
                    let body = approval.result_body.clone().unwrap_or_default();
                    let formatted = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|j| serde_json::to_string_pretty(&j).ok())
                        .unwrap_or(body);
                    format!(
                        "\u{2705} Approval {} was APPROVED and the action has now run.\nStatus: {}\n\nResult:\n{}",
                        approval.id, status, formatted
                    )
                }
            }
        };

        Ok(vec![ToolContent::Text { text }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definitions() {
        // Verify tool schemas are valid JSON
        let tools = vec![
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "credential": { "type": "string" },
                    "method": { "type": "string" },
                    "url": { "type": "string" }
                },
                "required": ["credential", "method", "url"]
            }),
        ];

        for tool in tools {
            assert!(tool.is_object());
        }
    }
}
