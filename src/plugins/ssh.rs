//! SSH plugin for deploying code and running remote commands.
//!
//! Provides two actions, both authenticated with a stored `SshPassword` credential:
//!
//! - `deploy` — rsync a local directory to the remote host.
//! - `run` — execute a sequence of shell commands over SSH (one SSH invocation
//!   per command), collecting per-command exit status, stdout, and stderr.
//!
//! # Per-instance configuration
//!
//! Each credential alias is an "instance". Defaults for action inputs live in
//! the credential's `metadata` map (flat `String -> String`). JSON-encoded
//! arrays are used for list values (e.g. `deploy.excludes`, `run.commands`).
//!
//! Deploy keys:
//!   - `deploy.source_dir`    - local directory (trailing `/` is significant to rsync)
//!   - `deploy.dest_dir`      - remote directory
//!   - `deploy.excludes`      - JSON array of patterns, e.g. `'[".git","node_modules"]'`
//!   - `deploy.flags`         - rsync flags string (default: `-avz`)
//!   - `deploy.allow_override` - `"true"` to let callers override the fields above
//!
//! Run keys:
//!   - `run.commands`         - JSON array of shell commands
//!   - `run.stop_on_error`    - `"true"` / `"false"` (default: `false`)
//!   - `run.interval_ms`      - ms to sleep between commands (default: `0`)
//!   - `run.timeout_secs`     - per-command timeout in seconds (default: `300`)
//!   - `run.allow_override`   - `"true"` to let callers pass a custom `commands` array
//!
//! Shared SSH keys:
//!   - `ssh.strict_host_key_checking` - override (default: `accept-new`)
//!
//! # Authentication
//!
//! Password authentication is driven by the external `sshpass` binary. The
//! password is passed via the `SSHPASS` environment variable of the child
//! process (not visible in `ps`). The agent invoking the plugin only sees the
//! credential alias.

use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use std::collections::HashMap;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;

const DEFAULT_RSYNC_FLAGS: &str = "-avz";
const DEFAULT_HOST_KEY_CHECKING: &str = "accept-new";
const DEFAULT_RUN_TIMEOUT_SECS: u64 = 300;
const DEFAULT_DEPLOY_TIMEOUT_SECS: u64 = 1800;

/// SSH plugin: rsync-based deploys and remote command execution.
pub struct SshPlugin;

impl SshPlugin {
    pub fn new() -> Self {
        Self
    }

    fn extract_ssh_credential(
        data: &CredentialData,
    ) -> Result<(String, u16, String, String), PluginError> {
        match data {
            CredentialData::SshPassword {
                host,
                port,
                user,
                password,
            } => Ok((
                host.clone(),
                *port,
                user.clone(),
                password.expose().to_string(),
            )),
            _ => Err(PluginError::UnsupportedCredentialType(
                "ssh plugin requires an ssh_password credential".to_string(),
            )),
        }
    }

    fn metadata_bool(metadata: &HashMap<String, String>, key: &str, default: bool) -> bool {
        metadata
            .get(key)
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"))
            .unwrap_or(default)
    }

    fn metadata_u64(metadata: &HashMap<String, String>, key: &str, default: u64) -> u64 {
        metadata
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    fn parse_json_string_array(value: &str, context: &str) -> Result<Vec<String>, PluginError> {
        let parsed: Vec<String> = serde_json::from_str(value).map_err(|e| {
            PluginError::InvalidParams(format!(
                "{} must be a JSON array of strings: {}",
                context, e
            ))
        })?;
        Ok(parsed)
    }

    fn host_key_check_value(metadata: &HashMap<String, String>) -> String {
        metadata
            .get("ssh.strict_host_key_checking")
            .cloned()
            .unwrap_or_else(|| DEFAULT_HOST_KEY_CHECKING.to_string())
    }

    fn base_ssh_args(port: u16, metadata: &HashMap<String, String>) -> Vec<String> {
        let host_check = Self::host_key_check_value(metadata);
        vec![
            "-p".to_string(),
            port.to_string(),
            "-o".to_string(),
            format!("StrictHostKeyChecking={}", host_check),
            "-o".to_string(),
            "ConnectTimeout=30".to_string(),
        ]
    }

    async fn check_binary_available(name: &str) -> Result<(), PluginError> {
        match Command::new(name).arg("-V").output().await {
            Ok(_) => Ok(()),
            Err(_) => {
                // Some binaries (like `ssh`) don't support `-V`; retry with `-h`
                // and with no arg. Either way, a missing binary yields
                // NotFound and surfaces as an install hint.
                match Command::new(name).output().await {
                    Ok(_) => Ok(()),
                    Err(_) => Err(PluginError::ExecutionFailed(format!(
                        "required binary '{}' not found on PATH. Install it (e.g. `brew install hudochenkov/sshpass/sshpass` for sshpass) and retry.",
                        name
                    ))),
                }
            }
        }
    }

    async fn execute_deploy(
        &self,
        params: serde_json::Value,
        metadata: &HashMap<String, String>,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let (host, port, user, password) = Self::extract_ssh_credential(cred_data)?;

        let allow_override = Self::metadata_bool(metadata, "deploy.allow_override", false);
        let param_obj = params.as_object();
        let param = |key: &str| -> Option<String> {
            param_obj
                .and_then(|o| o.get(key))
                .and_then(|v| v.as_str().map(String::from))
        };

        let locked_param_present = ["source_dir", "dest_dir", "excludes", "flags"]
            .iter()
            .any(|k| param_obj.map(|o| o.contains_key(*k)).unwrap_or(false));
        if locked_param_present && !allow_override {
            return Err(PluginError::InvalidParams(
                "deploy.allow_override is not enabled on this credential; cannot override source_dir/dest_dir/excludes/flags. Set metadata deploy.allow_override=true to allow."
                    .to_string(),
            ));
        }

        let source_dir = if allow_override {
            param("source_dir").or_else(|| metadata.get("deploy.source_dir").cloned())
        } else {
            metadata.get("deploy.source_dir").cloned()
        }
        .ok_or_else(|| {
            PluginError::InvalidParams(
                "no source_dir configured: set metadata deploy.source_dir".to_string(),
            )
        })?;

        let dest_dir = if allow_override {
            param("dest_dir").or_else(|| metadata.get("deploy.dest_dir").cloned())
        } else {
            metadata.get("deploy.dest_dir").cloned()
        }
        .ok_or_else(|| {
            PluginError::InvalidParams(
                "no dest_dir configured: set metadata deploy.dest_dir".to_string(),
            )
        })?;

        let excludes: Vec<String> = {
            let from_param = if allow_override {
                param_obj
                    .and_then(|o| o.get("excludes"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
            } else {
                None
            };
            if let Some(e) = from_param {
                e
            } else if let Some(meta) = metadata.get("deploy.excludes") {
                Self::parse_json_string_array(meta, "metadata deploy.excludes")?
            } else {
                Vec::new()
            }
        };

        let flags_str = if allow_override {
            param("flags")
                .or_else(|| metadata.get("deploy.flags").cloned())
                .unwrap_or_else(|| DEFAULT_RSYNC_FLAGS.to_string())
        } else {
            metadata
                .get("deploy.flags")
                .cloned()
                .unwrap_or_else(|| DEFAULT_RSYNC_FLAGS.to_string())
        };

        let dry_run = param_obj
            .and_then(|o| o.get("dry_run"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let timeout_secs = param_obj
            .and_then(|o| o.get("timeout_secs"))
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                Self::metadata_u64(metadata, "deploy.timeout_secs", DEFAULT_DEPLOY_TIMEOUT_SECS)
            });

        Self::check_binary_available("sshpass").await?;
        Self::check_binary_available("rsync").await?;

        let ssh_args = Self::base_ssh_args(port, metadata);
        let ssh_cmd = format!("ssh {}", ssh_args.join(" "));

        let mut cmd = Command::new("sshpass");
        cmd.env("SSHPASS", &password);
        cmd.arg("-e").arg("rsync");
        for f in flags_str.split_whitespace() {
            cmd.arg(f);
        }
        for ex in &excludes {
            cmd.arg(format!("--exclude={}", ex));
        }
        if dry_run {
            cmd.arg("--dry-run");
        }
        cmd.arg("-e").arg(&ssh_cmd);
        cmd.arg(&source_dir);
        cmd.arg(format!("{}@{}:{}", user, host, dest_dir));
        cmd.stdin(Stdio::null());
        cmd.kill_on_drop(true);

        let started = Instant::now();
        let result = timeout(Duration::from_secs(timeout_secs), cmd.output()).await;
        let duration_ms = started.elapsed().as_millis() as u64;

        let (exit_code, stdout, stderr, timed_out) = match result {
            Ok(Ok(output)) => (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
                false,
            ),
            Ok(Err(e)) => {
                return Err(PluginError::ExecutionFailed(format!(
                    "rsync failed to spawn: {}",
                    e
                )))
            }
            Err(_) => (
                -1,
                String::new(),
                format!(
                    "rsync timed out after {}s (local process killed; remote rsync may continue briefly until it detects EOF)",
                    timeout_secs
                ),
                true,
            ),
        };

        let command_display = format!(
            "sshpass -e rsync {}{} -e \"{}\" {} {}@{}:{}",
            flags_str,
            excludes
                .iter()
                .map(|e| format!(" --exclude={}", e))
                .collect::<String>(),
            ssh_cmd,
            source_dir,
            user,
            host,
            dest_dir
        );

        let body = serde_json::json!({
            "ok": exit_code == 0 && !timed_out,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "command_display": command_display,
            "dry_run": dry_run,
        });

        Ok(ExecuteResponse {
            status: if exit_code == 0 && !timed_out {
                200
            } else {
                500
            },
            headers: HashMap::new(),
            body: serde_json::to_vec(&body).unwrap_or_default(),
            updated_credential: None,
        })
    }

    async fn execute_run(
        &self,
        params: serde_json::Value,
        metadata: &HashMap<String, String>,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let (host, port, user, password) = Self::extract_ssh_credential(cred_data)?;

        let allow_override = Self::metadata_bool(metadata, "run.allow_override", false);
        let param_obj = params.as_object();

        let commands: Vec<String> = {
            let from_param_array = param_obj
                .and_then(|o| o.get("commands"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                });
            if from_param_array.is_some() && !allow_override {
                return Err(PluginError::InvalidParams(
                    "run.allow_override is not enabled on this credential; cannot pass a custom commands array. Set metadata run.allow_override=true to allow.".to_string(),
                ));
            }
            if let Some(cmds) = from_param_array {
                cmds
            } else if let Some(meta) = metadata.get("run.commands") {
                Self::parse_json_string_array(meta, "metadata run.commands")?
            } else {
                return Err(PluginError::InvalidParams(
                    "no commands configured: set metadata run.commands (JSON array) or pass commands param with run.allow_override enabled".to_string(),
                ));
            }
        };

        if commands.is_empty() {
            return Err(PluginError::InvalidParams(
                "commands list is empty".to_string(),
            ));
        }

        let stop_on_error = param_obj
            .and_then(|o| o.get("stop_on_error"))
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| Self::metadata_bool(metadata, "run.stop_on_error", false));

        let interval_ms = param_obj
            .and_then(|o| o.get("interval_ms"))
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| Self::metadata_u64(metadata, "run.interval_ms", 0));

        let timeout_secs = param_obj
            .and_then(|o| o.get("timeout_secs"))
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                Self::metadata_u64(metadata, "run.timeout_secs", DEFAULT_RUN_TIMEOUT_SECS)
            });

        Self::check_binary_available("sshpass").await?;

        let ssh_base_args = Self::base_ssh_args(port, metadata);
        let destination = format!("{}@{}", user, host);

        let mut results: Vec<serde_json::Value> = Vec::with_capacity(commands.len());
        let mut overall_ok = true;

        for (idx, command) in commands.iter().enumerate() {
            if idx > 0 && interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }

            let mut cmd = Command::new("sshpass");
            cmd.env("SSHPASS", &password);
            cmd.arg("-e").arg("ssh");
            for a in &ssh_base_args {
                cmd.arg(a);
            }
            cmd.arg(&destination);
            cmd.arg(command);
            cmd.stdin(Stdio::null());
            cmd.kill_on_drop(true);

            let started = Instant::now();
            let output_result = timeout(Duration::from_secs(timeout_secs), cmd.output()).await;
            let duration_ms = started.elapsed().as_millis() as u64;

            let (exit_code, stdout, stderr, timed_out) = match output_result {
                Ok(Ok(output)) => (
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                    false,
                ),
                Ok(Err(e)) => (
                    -1,
                    String::new(),
                    format!("failed to spawn ssh: {}", e),
                    false,
                ),
                Err(_) => (
                    -1,
                    String::new(),
                    format!(
                        "command timed out after {}s (local ssh killed; remote command may continue briefly until sshd detects channel close)",
                        timeout_secs
                    ),
                    true,
                ),
            };

            let ok = exit_code == 0 && !timed_out;
            if !ok {
                overall_ok = false;
            }

            results.push(serde_json::json!({
                "index": idx,
                "command": command,
                "ok": ok,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": duration_ms,
                "timed_out": timed_out,
            }));

            if !ok && stop_on_error {
                break;
            }
        }

        let body = serde_json::json!({
            "ok": overall_ok,
            "results": results,
        });

        Ok(ExecuteResponse {
            status: if overall_ok { 200 } else { 500 },
            headers: HashMap::new(),
            body: serde_json::to_vec(&body).unwrap_or_default(),
            updated_credential: None,
        })
    }
}

impl Default for SshPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for SshPlugin {
    fn name(&self) -> &str {
        "ssh"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::SshPassword]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["deploy", "run"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        let metadata = request.credential.metadata.clone();
        match request.action.as_str() {
            "deploy" => {
                self.execute_deploy(request.params, &metadata, &request.credential.data)
                    .await
            }
            "run" => {
                self.execute_run(request.params, &metadata, &request.credential.data)
                    .await
            }
            _ => Err(PluginError::UnsupportedAction(request.action)),
        }
    }

    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError> {
        if !params.is_null() && !params.is_object() {
            return Err(PluginError::InvalidParams(
                "params must be a JSON object or null".to_string(),
            ));
        }
        match action {
            "deploy" => {
                if let Some(obj) = params.as_object() {
                    if let Some(v) = obj.get("dry_run") {
                        if !v.is_boolean() {
                            return Err(PluginError::InvalidParams(
                                "dry_run must be a boolean".to_string(),
                            ));
                        }
                    }
                    if let Some(v) = obj.get("excludes") {
                        if !v.is_array() {
                            return Err(PluginError::InvalidParams(
                                "excludes must be an array of strings".to_string(),
                            ));
                        }
                    }
                }
                Ok(())
            }
            "run" => {
                if let Some(obj) = params.as_object() {
                    if let Some(v) = obj.get("commands") {
                        if !v.is_array() {
                            return Err(PluginError::InvalidParams(
                                "commands must be an array of strings".to_string(),
                            ));
                        }
                    }
                    if let Some(v) = obj.get("stop_on_error") {
                        if !v.is_boolean() {
                            return Err(PluginError::InvalidParams(
                                "stop_on_error must be a boolean".to_string(),
                            ));
                        }
                    }
                    if let Some(v) = obj.get("interval_ms") {
                        if !v.is_u64() {
                            return Err(PluginError::InvalidParams(
                                "interval_ms must be a non-negative integer".to_string(),
                            ));
                        }
                    }
                    if let Some(v) = obj.get("timeout_secs") {
                        if !v.is_u64() {
                            return Err(PluginError::InvalidParams(
                                "timeout_secs must be a non-negative integer".to_string(),
                            ));
                        }
                    }
                }
                Ok(())
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }

    fn mcp_tool_definitions(&self) -> Vec<super::types::McpToolDefinition> {
        // Names are deliberately bare: the MCP layer prefixes them with the
        // plugin name, yielding `ssh_deploy` and `ssh_run`.
        vec![
            super::types::McpToolDefinition {
                name: "deploy".to_string(),
                action: "deploy".to_string(),
                description: Some(
                    "Rsync a local directory to the remote host configured in the ssh_password credential. Uses per-credential defaults from metadata; param overrides require deploy.allow_override=true.".to_string(),
                ),
                input_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "credential": {
                            "type": "string",
                            "description": "Credential alias or ID to deploy with"
                        },
                        "dry_run": {
                            "type": "boolean",
                            "description": "Preview the rsync without transferring files. Always allowed."
                        },
                        "source_dir": { "type": "string", "description": "Override local source dir (requires deploy.allow_override=true)" },
                        "dest_dir":   { "type": "string", "description": "Override remote dest dir (requires deploy.allow_override=true)" },
                        "excludes":   { "type": "array", "items": {"type": "string"}, "description": "Override exclude patterns (requires deploy.allow_override=true)" },
                        "flags":      { "type": "string", "description": "Override rsync flags (requires deploy.allow_override=true)" }
                    },
                    "required": ["credential"]
                })),
                parameter_mappings: HashMap::new(),
            },
            super::types::McpToolDefinition {
                name: "run".to_string(),
                action: "run".to_string(),
                description: Some(
                    "Run a sequence of shell commands on the remote host. Commands come from credential metadata run.commands unless run.allow_override=true.".to_string(),
                ),
                input_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "credential": {
                            "type": "string",
                            "description": "Credential alias or ID to run commands against"
                        },
                        "commands": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Override command list (requires run.allow_override=true)"
                        },
                        "stop_on_error": { "type": "boolean", "description": "Halt the sequence on the first non-zero exit" },
                        "interval_ms":   { "type": "integer", "minimum": 0, "description": "Milliseconds to sleep between commands" },
                        "timeout_secs":  { "type": "integer", "minimum": 1, "description": "Per-command timeout (local process is killed on expiry)" }
                    },
                    "required": ["credential"]
                })),
                parameter_mappings: HashMap::new(),
            },
        ]
    }

    fn description(&self) -> Option<&str> {
        Some("SSH-based deploy (rsync) and remote command execution, authenticated via stored password.")
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
}

// (removed the dead `DeployParams`/`RunParams` "doc structs": they were never deserialized — the action
// impls parse the params map by hand — so an unenforced parallel schema would only drift from reality.)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Credential, RequestContext, Secret};

    fn mk_cred(metadata: HashMap<String, String>) -> Credential {
        let mut cred = Credential::new(
            "test-ssh".to_string(),
            CredentialData::SshPassword {
                host: "example.com".to_string(),
                port: 22,
                user: "root".to_string(),
                password: Secret::new("unused-in-unit-tests"),
            },
        );
        cred.metadata = metadata;
        cred
    }

    fn mk_request(
        action: &str,
        params: serde_json::Value,
        metadata: HashMap<String, String>,
    ) -> PluginRequest {
        PluginRequest {
            credential: mk_cred(metadata),
            action: action.to_string(),
            params,
            context: RequestContext::default(),
        }
    }

    #[test]
    fn test_name_and_actions() {
        let p = SshPlugin::new();
        assert_eq!(p.name(), "ssh");
        assert_eq!(p.supported_actions(), vec!["deploy", "run"]);
        assert_eq!(
            p.supported_credential_types(),
            vec![CredentialType::SshPassword]
        );
    }

    #[test]
    fn test_validate_deploy_ok() {
        let p = SshPlugin::new();
        assert!(p.validate_params("deploy", &serde_json::json!({})).is_ok());
        assert!(p
            .validate_params("deploy", &serde_json::json!({"dry_run": true}))
            .is_ok());
        assert!(p
            .validate_params(
                "deploy",
                &serde_json::json!({"excludes": ["node_modules", ".git"]})
            )
            .is_ok());
    }

    #[test]
    fn test_validate_deploy_bad_types() {
        let p = SshPlugin::new();
        assert!(p
            .validate_params("deploy", &serde_json::json!({"dry_run": "yes"}))
            .is_err());
        assert!(p
            .validate_params("deploy", &serde_json::json!({"excludes": "nope"}))
            .is_err());
    }

    #[test]
    fn test_validate_run_ok() {
        let p = SshPlugin::new();
        assert!(p
            .validate_params(
                "run",
                &serde_json::json!({"commands": ["ls", "pwd"], "stop_on_error": true})
            )
            .is_ok());
    }

    #[test]
    fn test_validate_run_bad_types() {
        let p = SshPlugin::new();
        assert!(p
            .validate_params("run", &serde_json::json!({"commands": "ls"}))
            .is_err());
        assert!(p
            .validate_params("run", &serde_json::json!({"stop_on_error": 1}))
            .is_err());
        assert!(p
            .validate_params("run", &serde_json::json!({"interval_ms": -5}))
            .is_err());
    }

    #[test]
    fn test_validate_unknown_action() {
        let p = SshPlugin::new();
        assert!(p.validate_params("delete", &serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn test_deploy_without_metadata_errors() {
        let p = SshPlugin::new();
        let req = mk_request("deploy", serde_json::json!({}), HashMap::new());
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("deploy.source_dir"));
    }

    #[tokio::test]
    async fn test_deploy_override_locked_by_default() {
        let p = SshPlugin::new();
        let mut meta = HashMap::new();
        meta.insert("deploy.source_dir".to_string(), "/src".to_string());
        meta.insert("deploy.dest_dir".to_string(), "/dest".to_string());
        let req = mk_request("deploy", serde_json::json!({"source_dir": "/evil"}), meta);
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("allow_override"));
    }

    #[tokio::test]
    async fn test_run_without_metadata_errors() {
        let p = SshPlugin::new();
        let req = mk_request("run", serde_json::json!({}), HashMap::new());
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("run.commands"));
    }

    #[tokio::test]
    async fn test_run_override_locked_by_default() {
        let p = SshPlugin::new();
        let mut meta = HashMap::new();
        meta.insert("run.commands".to_string(), r#"["echo safe"]"#.to_string());
        let req = mk_request("run", serde_json::json!({"commands": ["rm -rf /"]}), meta);
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("allow_override"));
    }

    #[tokio::test]
    async fn test_run_bad_metadata_json() {
        let p = SshPlugin::new();
        let mut meta = HashMap::new();
        meta.insert("run.commands".to_string(), "not json".to_string());
        let req = mk_request("run", serde_json::json!({}), meta);
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("JSON array"));
    }

    #[test]
    fn test_parse_json_string_array() {
        assert_eq!(
            SshPlugin::parse_json_string_array(r#"["a","b"]"#, "x").unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(SshPlugin::parse_json_string_array("not json", "x").is_err());
    }

    #[test]
    fn test_metadata_bool() {
        let mut m = HashMap::new();
        m.insert("k".to_string(), "true".to_string());
        assert!(SshPlugin::metadata_bool(&m, "k", false));
        m.insert("k".to_string(), "YES".to_string());
        assert!(SshPlugin::metadata_bool(&m, "k", false));
        m.insert("k".to_string(), "0".to_string());
        assert!(!SshPlugin::metadata_bool(&m, "k", true));
        assert!(SshPlugin::metadata_bool(&m, "missing", true));
    }

    #[test]
    fn test_base_ssh_args_uses_metadata_host_key() {
        let mut m = HashMap::new();
        m.insert("ssh.strict_host_key_checking".to_string(), "no".to_string());
        let args = SshPlugin::base_ssh_args(2222, &m);
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"2222".to_string()));
        assert!(args.iter().any(|a| a == "StrictHostKeyChecking=no"));
    }

    #[test]
    fn test_base_ssh_args_default_host_key_is_accept_new() {
        let m = HashMap::new();
        let args = SshPlugin::base_ssh_args(22, &m);
        assert!(args.iter().any(|a| a == "StrictHostKeyChecking=accept-new"));
    }

    #[test]
    fn test_mcp_tools_exposed() {
        let p = SshPlugin::new();
        let tools = p.mcp_tool_definitions();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        // Bare names — MCP layer prefixes with the plugin name for the final tool ID.
        assert!(names.contains(&"deploy"));
        assert!(names.contains(&"run"));
        assert!(tools.iter().all(|t| t.input_schema.is_some()));
    }
}
