//! MCP protocol types
//!
//! Based on the Model Context Protocol specification.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: JsonRpcId,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: JsonRpcId, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: JsonRpcId, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// JSON-RPC notification (no response expected)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC ID (can be string, number, or null)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum JsonRpcId {
    String(String),
    Number(i64),
    #[default]
    Null,
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// Standard JSON-RPC error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// MCP Initialize request params
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

/// MCP Client capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientCapabilities {
    #[serde(default)]
    pub roots: Option<RootsCapability>,
    #[serde(default)]
    pub sampling: Option<SamplingCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootsCapability {
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingCapability {}

/// MCP Client info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// MCP Initialize result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// MCP Server capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// MCP Server info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// MCP Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// MCP tools/list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsListResult {
    pub tools: Vec<Tool>,
}

/// MCP tools/call params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// MCP tools/call result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    /// MCP structured tool output. Older clients continue to consume `content`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// MCP tool content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ToolContent {
    Text { text: String },
    Image { data: String, mime_type: String },
    Resource { resource: ResourceReference },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReference {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// MCP Resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// MCP resources/list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesListResult {
    pub resources: Vec<Resource>,
}

// Vultrino-specific tool arguments

/// Arguments for list_credentials tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListCredentialsArgs {
    /// Optional pattern to filter credentials (glob-style)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

/// Arguments for http_request tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestArgs {
    /// Vultrino API key for authentication
    pub api_key: String,
    /// Credential alias to use for the request
    pub credential: String,
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,
    /// Target URL
    pub url: String,
    /// Request headers (optional)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    /// Request body (optional, for POST/PUT/PATCH)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    /// Query parameters (optional)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub query: HashMap<String, String>,
}

/// Arguments for get_credential_info tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCredentialInfoArgs {
    /// Vultrino API key for authentication
    pub api_key: String,
    /// Credential alias or ID
    pub credential: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonrpc_response_success() {
        let response =
            JsonRpcResponse::success(JsonRpcId::Number(1), serde_json::json!({"status": "ok"}));

        assert!(response.error.is_none());
        assert!(response.result.is_some());
    }

    #[test]
    fn test_jsonrpc_response_error() {
        let response = JsonRpcResponse::error(
            JsonRpcId::String("req-1".to_string()),
            INVALID_PARAMS,
            "Invalid parameters",
        );

        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_tool_content_serialization() {
        let content = ToolContent::Text {
            text: "Hello".to_string(),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"text\""));
    }
}
