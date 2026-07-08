//! Plugin manifest types and definitions
//!
//! This module defines the types used to describe plugin capabilities,
//! including credential types, actions, and MCP tools.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;

/// Errors related to plugin manifests
#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("Failed to parse manifest: {0}")]
    Parse(String),

    #[error("Invalid manifest: {0}")]
    Invalid(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Plugin format type
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginFormat {
    /// WebAssembly module
    #[default]
    Wasm,
    /// Built-in Rust plugin
    Builtin,
}

/// Basic plugin information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique plugin name (e.g., "pgp-signing")
    pub name: String,
    /// Plugin version (semver)
    pub version: String,
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
    /// Plugin author
    #[serde(default)]
    pub author: Option<String>,
    /// License identifier
    #[serde(default)]
    pub license: Option<String>,
    /// Homepage URL
    #[serde(default)]
    pub homepage: Option<String>,
    /// Repository URL
    #[serde(default)]
    pub repository: Option<String>,
    /// Plugin format
    #[serde(default)]
    pub format: PluginFormat,
    /// WASM module filename (relative to plugin directory)
    #[serde(default)]
    pub wasm_module: Option<String>,
    /// Minimum Vultrino version required
    #[serde(default)]
    pub min_vultrino_version: Option<String>,
}

/// Complete plugin manifest (parsed from plugin.toml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin information
    pub plugin: PluginInfo,
    /// Credential types defined by this plugin
    #[serde(default)]
    pub credential_types: Vec<CredentialTypeDefinition>,
    /// Actions provided by this plugin
    #[serde(default)]
    pub actions: Vec<ActionDefinition>,
    /// MCP tools exposed by this plugin
    #[serde(default)]
    pub mcp_tools: Vec<McpToolDefinition>,
    /// URL patterns this plugin handles
    #[serde(default)]
    pub url_patterns: Vec<String>,
}

impl PluginManifest {
    /// Parse a manifest from TOML string
    pub fn from_toml(content: &str) -> Result<Self, ManifestError> {
        let manifest: Self = toml::from_str(content)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Parse a manifest from a file path
    pub fn from_file(path: &PathBuf) -> Result<Self, ManifestError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Validate the manifest
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.plugin.name.is_empty() {
            return Err(ManifestError::Invalid(
                "Plugin name is required".to_string(),
            ));
        }

        if self.plugin.version.is_empty() {
            return Err(ManifestError::Invalid(
                "Plugin version is required".to_string(),
            ));
        }

        // Validate plugin name format (alphanumeric + hyphens)
        if !self
            .plugin
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ManifestError::Invalid(
                "Plugin name must only contain alphanumeric characters, hyphens, and underscores"
                    .to_string(),
            ));
        }

        // WASM plugins must have wasm_module defined
        if self.plugin.format == PluginFormat::Wasm && self.plugin.wasm_module.is_none() {
            return Err(ManifestError::Invalid(
                "WASM plugins must specify wasm_module".to_string(),
            ));
        }

        // Validate credential type definitions
        for cred_type in &self.credential_types {
            cred_type.validate()?;
        }

        // Validate action definitions
        for action in &self.actions {
            action.validate()?;
        }

        // Validate MCP tool definitions
        for tool in &self.mcp_tools {
            tool.validate()?;
        }

        Ok(())
    }

    /// Get the WASM module path relative to plugin directory
    pub fn wasm_module_path(&self) -> Option<&str> {
        self.plugin.wasm_module.as_deref()
    }
}

/// Definition of a credential type provided by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTypeDefinition {
    /// Internal name (e.g., "pgp_key")
    pub name: String,
    /// Human-readable display name (e.g., "PGP/GPG Key")
    pub display_name: String,
    /// Description of this credential type
    #[serde(default)]
    pub description: Option<String>,
    /// Icon name (for UI)
    #[serde(default)]
    pub icon: Option<String>,
    /// Fields required for this credential type
    #[serde(default)]
    pub fields: Vec<CredentialFieldDefinition>,
}

impl CredentialTypeDefinition {
    /// Validate the credential type definition
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.name.is_empty() {
            return Err(ManifestError::Invalid(
                "Credential type name is required".to_string(),
            ));
        }

        if self.display_name.is_empty() {
            return Err(ManifestError::Invalid(
                "Credential type display_name is required".to_string(),
            ));
        }

        // Validate name format
        if !self.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(ManifestError::Invalid(
                "Credential type name must only contain alphanumeric characters and underscores"
                    .to_string(),
            ));
        }

        for field in &self.fields {
            field.validate()?;
        }

        Ok(())
    }

    /// Get a field by name
    pub fn get_field(&self, name: &str) -> Option<&CredentialFieldDefinition> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Get all required fields
    pub fn required_fields(&self) -> Vec<&CredentialFieldDefinition> {
        self.fields.iter().filter(|f| f.required).collect()
    }
}

/// Field type for credential forms
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// Single-line text input
    #[default]
    Text,
    /// Password field (hidden input)
    Password,
    /// Multi-line textarea
    Textarea,
    /// Select dropdown
    Select,
    /// Checkbox
    Checkbox,
    /// File upload
    File,
    /// Hidden field
    Hidden,
}

/// Option for select fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectOption {
    /// Value to store
    pub value: String,
    /// Display label
    pub label: String,
}

/// Definition of a field in a credential form
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialFieldDefinition {
    /// Field name (used as key in credential data)
    pub name: String,
    /// Display label
    pub label: String,
    /// Field type for rendering
    #[serde(rename = "type", default)]
    pub field_type: FieldType,
    /// Whether field is required
    #[serde(default)]
    pub required: bool,
    /// Whether field contains sensitive data (should be encrypted)
    #[serde(default)]
    pub secret: bool,
    /// Help text shown below field
    #[serde(default)]
    pub help_text: Option<String>,
    /// Placeholder text
    #[serde(default)]
    pub placeholder: Option<String>,
    /// Default value
    #[serde(default)]
    pub default: Option<String>,
    /// Options for select fields
    #[serde(default)]
    pub options: Vec<SelectOption>,
    /// Validation pattern (regex)
    #[serde(default)]
    pub validation_pattern: Option<String>,
    /// Validation error message
    #[serde(default)]
    pub validation_message: Option<String>,
    /// Maximum length
    #[serde(default)]
    pub max_length: Option<usize>,
    /// Minimum length
    #[serde(default)]
    pub min_length: Option<usize>,
}

impl CredentialFieldDefinition {
    /// Validate the field definition
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.name.is_empty() {
            return Err(ManifestError::Invalid("Field name is required".to_string()));
        }

        if self.label.is_empty() {
            return Err(ManifestError::Invalid(
                "Field label is required".to_string(),
            ));
        }

        // Validate name format
        if !self.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(ManifestError::Invalid(
                "Field name must only contain alphanumeric characters and underscores".to_string(),
            ));
        }

        // Select fields must have options
        if self.field_type == FieldType::Select && self.options.is_empty() {
            return Err(ManifestError::Invalid(
                "Select fields must have at least one option".to_string(),
            ));
        }

        Ok(())
    }
}

/// Definition of an action provided by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDefinition {
    /// Action name (e.g., "sign", "verify")
    pub name: String,
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
    /// Credential types this action can be used with
    #[serde(default)]
    pub credential_types: Vec<String>,
    /// Parameters this action accepts
    #[serde(default)]
    pub parameters: Vec<ActionParameterDefinition>,
    /// Whether this action requires a credential
    #[serde(default = "default_true")]
    pub requires_credential: bool,
}

fn default_true() -> bool {
    true
}

impl ActionDefinition {
    /// Validate the action definition
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.name.is_empty() {
            return Err(ManifestError::Invalid(
                "Action name is required".to_string(),
            ));
        }

        // Validate name format
        if !self.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(ManifestError::Invalid(
                "Action name must only contain alphanumeric characters and underscores".to_string(),
            ));
        }

        for param in &self.parameters {
            param.validate()?;
        }

        Ok(())
    }
}

/// Parameter type for action parameters
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ParameterType {
    #[default]
    String,
    Integer,
    Number,
    Boolean,
    Object,
    Array,
}

/// Definition of a parameter for an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParameterDefinition {
    /// Parameter name
    pub name: String,
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
    /// Parameter type
    #[serde(rename = "type", default)]
    pub param_type: ParameterType,
    /// Whether parameter is required
    #[serde(default)]
    pub required: bool,
    /// Default value (as JSON)
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    /// Enum values (for string type)
    #[serde(default)]
    pub enum_values: Vec<String>,
}

impl ActionParameterDefinition {
    /// Validate the parameter definition
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.name.is_empty() {
            return Err(ManifestError::Invalid(
                "Parameter name is required".to_string(),
            ));
        }

        Ok(())
    }
}

/// Definition of an MCP tool exposed by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    /// Tool name (e.g., "pgp_sign")
    pub name: String,
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
    /// Action this tool invokes
    pub action: String,
    /// Input schema (JSON Schema)
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
    /// Custom parameter mappings (tool param -> action param)
    #[serde(default)]
    pub parameter_mappings: HashMap<String, String>,
}

impl McpToolDefinition {
    /// Validate the MCP tool definition
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.name.is_empty() {
            return Err(ManifestError::Invalid(
                "MCP tool name is required".to_string(),
            ));
        }

        if self.action.is_empty() {
            return Err(ManifestError::Invalid(
                "MCP tool must specify an action".to_string(),
            ));
        }

        // Validate name format (lowercase alphanumeric + underscores)
        if !self
            .name
            .chars()
            .all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(ManifestError::Invalid(
                "MCP tool name must only contain lowercase alphanumeric characters and underscores"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Generate a JSON Schema for this tool's input
    pub fn generate_input_schema(&self, action: &ActionDefinition) -> serde_json::Value {
        if let Some(schema) = &self.input_schema {
            return schema.clone();
        }

        // Generate schema from action parameters
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        // Add credential parameter
        properties.insert(
            "credential".to_string(),
            serde_json::json!({
                "type": "string",
                "description": "Credential alias or ID to use"
            }),
        );
        required.push(serde_json::Value::String("credential".to_string()));

        // Add action parameters
        for param in &action.parameters {
            let param_name = self
                .parameter_mappings
                .get(&param.name)
                .unwrap_or(&param.name)
                .clone();

            let param_schema = match param.param_type {
                ParameterType::String => {
                    let mut schema = serde_json::json!({
                        "type": "string"
                    });
                    if !param.enum_values.is_empty() {
                        schema["enum"] = serde_json::json!(param.enum_values);
                    }
                    schema
                }
                ParameterType::Integer => serde_json::json!({
                    "type": "integer"
                }),
                ParameterType::Number => serde_json::json!({
                    "type": "number"
                }),
                ParameterType::Boolean => serde_json::json!({
                    "type": "boolean"
                }),
                ParameterType::Object => serde_json::json!({
                    "type": "object"
                }),
                ParameterType::Array => serde_json::json!({
                    "type": "array"
                }),
            };

            let mut schema_obj = param_schema.as_object().unwrap().clone();
            if let Some(desc) = &param.description {
                schema_obj.insert("description".to_string(), serde_json::json!(desc));
            }

            properties.insert(param_name.clone(), serde_json::Value::Object(schema_obj));

            if param.required {
                required.push(serde_json::Value::String(param_name));
            }
        }

        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required
        })
    }
}

/// Installed plugin metadata (stored in plugin directory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPluginInfo {
    /// Plugin manifest
    pub manifest: PluginManifest,
    /// Installation source (git URL, local path, etc.)
    pub source: String,
    /// Installation timestamp
    pub installed_at: chrono::DateTime<chrono::Utc>,
    /// Whether plugin is enabled
    pub enabled: bool,
    /// Plugin directory path
    pub directory: PathBuf,
}

impl InstalledPluginInfo {
    /// Create new installed plugin info
    pub fn new(manifest: PluginManifest, source: String, directory: PathBuf) -> Self {
        Self {
            manifest,
            source,
            installed_at: chrono::Utc::now(),
            enabled: true,
            directory,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let toml = r#"
[plugin]
name = "pgp-signing"
version = "1.0.0"
description = "PGP signing and verification"
format = "wasm"
wasm_module = "plugin.wasm"

[[credential_types]]
name = "pgp_key"
display_name = "PGP/GPG Key"

[[credential_types.fields]]
name = "private_key"
label = "Private Key"
type = "textarea"
required = true
secret = true
help_text = "Paste your ASCII-armored private key"

[[credential_types.fields]]
name = "passphrase"
label = "Passphrase"
type = "password"
required = false
secret = true

[[actions]]
name = "sign"
description = "Sign data with PGP key"

[[actions.parameters]]
name = "data"
description = "Data to sign"
type = "string"
required = true

[[actions.parameters]]
name = "armor"
description = "Output ASCII-armored signature"
type = "boolean"
default = true

[[mcp_tools]]
name = "pgp_sign"
action = "sign"
description = "Sign data using a PGP key"
"#;

        let manifest = PluginManifest::from_toml(toml).unwrap();

        assert_eq!(manifest.plugin.name, "pgp-signing");
        assert_eq!(manifest.plugin.version, "1.0.0");
        assert_eq!(manifest.plugin.format, PluginFormat::Wasm);
        assert_eq!(manifest.plugin.wasm_module, Some("plugin.wasm".to_string()));

        assert_eq!(manifest.credential_types.len(), 1);
        let cred_type = &manifest.credential_types[0];
        assert_eq!(cred_type.name, "pgp_key");
        assert_eq!(cred_type.display_name, "PGP/GPG Key");
        assert_eq!(cred_type.fields.len(), 2);

        let private_key_field = &cred_type.fields[0];
        assert_eq!(private_key_field.name, "private_key");
        assert_eq!(private_key_field.field_type, FieldType::Textarea);
        assert!(private_key_field.required);
        assert!(private_key_field.secret);

        assert_eq!(manifest.actions.len(), 1);
        let action = &manifest.actions[0];
        assert_eq!(action.name, "sign");
        assert_eq!(action.parameters.len(), 2);

        assert_eq!(manifest.mcp_tools.len(), 1);
        let tool = &manifest.mcp_tools[0];
        assert_eq!(tool.name, "pgp_sign");
        assert_eq!(tool.action, "sign");
    }

    #[test]
    fn test_manifest_validation() {
        // Missing plugin name
        let toml = r#"
[plugin]
name = ""
version = "1.0.0"
"#;
        assert!(PluginManifest::from_toml(toml).is_err());

        // Invalid plugin name
        let toml = r#"
[plugin]
name = "invalid name with spaces"
version = "1.0.0"
"#;
        assert!(PluginManifest::from_toml(toml).is_err());

        // WASM plugin without wasm_module
        let toml = r#"
[plugin]
name = "test-plugin"
version = "1.0.0"
format = "wasm"
"#;
        assert!(PluginManifest::from_toml(toml).is_err());
    }

    #[test]
    fn test_generate_input_schema() {
        let action = ActionDefinition {
            name: "sign".to_string(),
            description: Some("Sign data".to_string()),
            credential_types: vec!["pgp_key".to_string()],
            parameters: vec![
                ActionParameterDefinition {
                    name: "data".to_string(),
                    description: Some("Data to sign".to_string()),
                    param_type: ParameterType::String,
                    required: true,
                    default: None,
                    enum_values: vec![],
                },
                ActionParameterDefinition {
                    name: "armor".to_string(),
                    description: Some("ASCII armor output".to_string()),
                    param_type: ParameterType::Boolean,
                    required: false,
                    default: Some(serde_json::json!(true)),
                    enum_values: vec![],
                },
            ],
            requires_credential: true,
        };

        let tool = McpToolDefinition {
            name: "pgp_sign".to_string(),
            description: Some("Sign data with PGP".to_string()),
            action: "sign".to_string(),
            input_schema: None,
            parameter_mappings: HashMap::new(),
        };

        let schema = tool.generate_input_schema(&action);

        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["credential"].is_object());
        assert!(schema["properties"]["data"].is_object());
        assert!(schema["properties"]["armor"].is_object());
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("credential")));
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("data")));
    }
}
