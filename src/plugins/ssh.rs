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
//!   - `deploy.flags`         - rsync flags string (default: `-avz`); allowlisted, see `ALLOWED_RSYNC_FLAGS`
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
//!   - `ssh.strict_host_key_checking` - one of `yes`, `no`, `accept-new`, `ask`, `off` (default: `accept-new`)
//!
//! # Authentication
//!
//! Password authentication is driven by the external `sshpass` binary. The
//! password is passed via the `SSHPASS` environment variable of the child
//! process (not visible in `ps`). The agent invoking the plugin only sees the
//! credential alias.

use super::child_process::{tokio_command, ChildEnv};
use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use std::collections::HashMap;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const DEFAULT_RSYNC_FLAGS: &str = "-avz";
const DEFAULT_HOST_KEY_CHECKING: &str = "accept-new";
const DEFAULT_RUN_TIMEOUT_SECS: u64 = 300;
const DEFAULT_DEPLOY_TIMEOUT_SECS: u64 = 1800;

/// The only accepted values of `ssh.strict_host_key_checking`. The validated value is always
/// returned as one of these `'static` strings, never as the caller's text.
const ALLOWED_HOST_KEY_CHECKING: &[&str] = &["yes", "no", "accept-new", "ask", "off"];
/// rsync flags accepted exactly as written.
const ALLOWED_RSYNC_FLAGS: &[&str] = &[
    "-a",
    "--archive",
    "-z",
    "--compress",
    "-v",
    "--verbose",
    "-n",
    "--dry-run",
    "--delete",
    "--delete-after",
    "--checksum",
    "-c",
    "--human-readable",
    "-h",
    "--partial",
    "--times",
    "-t",
    "--recursive",
    "-r",
];
/// Letters allowed inside a combined short flag such as `-avz`: the single-letter entries of
/// `ALLOWED_RSYNC_FLAGS`.
const ALLOWED_RSYNC_SHORT_LETTERS: &str = "azvnchtr";
const MAX_HOST_LEN: usize = 253;
const MAX_USER_LEN: usize = 64;

fn refuse(msg: String) -> PluginError {
    PluginError::InvalidParams(msg)
}

/// Debug-escaped, truncated copy of a value for an error message (never used for secrets).
fn shown(value: &str) -> String {
    let t: String = value.chars().take(64).collect();
    format!("{:?}", t)
}

fn has_control(value: &str) -> bool {
    value.chars().any(|c| c.is_control())
}

/// Accepts only the exact values in `ALLOWED_HOST_KEY_CHECKING` (case-sensitive, after trimming).
fn validate_host_key_checking(raw: &str) -> Result<&'static str, PluginError> {
    let v = raw.trim();
    ALLOWED_HOST_KEY_CHECKING
        .iter()
        .find(|a| **a == v)
        .copied()
        .ok_or_else(|| {
            refuse(format!(
                "ssh.strict_host_key_checking is not an allowed value; must be one of: {}",
                ALLOWED_HOST_KEY_CHECKING.join(", ")
            ))
        })
}

/// Hostname (letters, digits, `-`, `.`), IPv4 or IPv6 literal.
fn validate_host(host: &str) -> Result<(), PluginError> {
    let bad = |why: &str| refuse(format!("ssh credential host is invalid: {}", why));
    if host.is_empty() {
        return Err(bad("empty"));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(bad("longer than 253 characters"));
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(());
    }
    if host.starts_with('-') || host.starts_with('.') {
        return Err(bad("must not start with '-' or '.'"));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(bad(
            "only letters, digits, '-' and '.' are allowed in a hostname",
        ));
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return Err(bad("empty or over-long label"));
    }
    Ok(())
}

fn validate_user(user: &str) -> Result<(), PluginError> {
    let bad = |why: &str| refuse(format!("ssh credential user is invalid: {}", why));
    if user.is_empty() {
        return Err(bad("empty"));
    }
    if user.len() > MAX_USER_LEN {
        return Err(bad("longer than 64 characters"));
    }
    if user.starts_with('-') {
        return Err(bad("must not start with '-'"));
    }
    if !user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(bad("only letters, digits, '.', '_' and '-' are allowed"));
    }
    Ok(())
}

fn validate_port(port: u16) -> Result<(), PluginError> {
    if port == 0 {
        return Err(refuse(
            "ssh credential port is invalid: must be 1-65535".to_string(),
        ));
    }
    Ok(())
}

/// Local directory handed to rsync as a positional source.
fn validate_source_dir(v: &str) -> Result<(), PluginError> {
    let bad = |why: &str| refuse(format!("source_dir is invalid: {}", why));
    if v.is_empty() {
        return Err(bad("empty"));
    }
    if has_control(v) {
        return Err(bad("contains a control character"));
    }
    if v.starts_with('-') {
        return Err(bad("must not start with '-'"));
    }
    // rsync reads `host:path` and `rsync://` as a remote source; a local path with a colon
    // before its first slash would change where the data is read from.
    if v.split('/').next().is_some_and(|first| first.contains(':')) {
        return Err(bad(
            "must not contain ':' before the first '/' (use ./ for a relative path)",
        ));
    }
    Ok(())
}

/// Remote path appended after `user@host:`.
fn validate_dest_dir(v: &str) -> Result<(), PluginError> {
    let bad = |why: &str| refuse(format!("dest_dir is invalid: {}", why));
    if v.is_empty() {
        return Err(bad("empty"));
    }
    if has_control(v) {
        return Err(bad("contains a control character"));
    }
    if v.starts_with('-') || v.starts_with("~-") {
        return Err(bad("must not start with '-' or '~-'"));
    }
    // `user@host::path` would select rsync daemon mode instead of the ssh transport.
    if v.starts_with(':') {
        return Err(bad("must not start with ':'"));
    }
    Ok(())
}

/// An rsync include/exclude pattern: non-empty, no control characters, not starting with `-`.
fn validate_filter_pattern(pattern: &str, what: &str) -> Result<(), PluginError> {
    if pattern.is_empty() || has_control(pattern) || pattern.starts_with('-') {
        return Err(refuse(format!(
            "{} pattern {} is invalid: must be non-empty, without control characters and must not start with '-'",
            what,
            shown(pattern)
        )));
    }
    Ok(())
}

/// A remote command is one argument after the destination; local ssh re-reads options that
/// follow the destination, so a command starting with `-` could be taken as an ssh option.
fn validate_remote_command(cmd: &str, idx: usize) -> Result<(), PluginError> {
    if cmd.is_empty() || cmd.starts_with('-') || cmd.contains('\0') {
        return Err(refuse(format!(
            "commands[{}] is invalid: must be non-empty, must not start with '-' and must not contain NUL",
            idx
        )));
    }
    Ok(())
}

/// Parses an rsync flags string (metadata `deploy.flags` or the caller's `flags`) against the
/// allowlist. Combined short flags such as `-avz` are accepted only when every letter is one of
/// `ALLOWED_RSYNC_SHORT_LETTERS`. Returns the tokens to pass, or refuses naming the flag.
fn parse_rsync_flags(raw: &str) -> Result<Vec<String>, PluginError> {
    let mut out = Vec::new();
    for tok in raw.split_whitespace() {
        let ok = if ALLOWED_RSYNC_FLAGS.contains(&tok) {
            true
        } else if let Some(p) = tok
            .strip_prefix("--exclude=")
            .or_else(|| tok.strip_prefix("--include="))
        {
            validate_filter_pattern(p, "rsync flag")?;
            true
        } else if let Some(letters) = tok.strip_prefix('-') {
            !letters.starts_with('-')
                && letters.chars().count() > 1
                && letters
                    .chars()
                    .all(|c| ALLOWED_RSYNC_SHORT_LETTERS.contains(c))
        } else {
            false
        };
        if !ok {
            return Err(refuse(format!(
                "rsync flag {} is not allowed; allowed flags: {}, --exclude=<pattern>, --include=<pattern>, or combinations of the letters {}",
                shown(tok),
                ALLOWED_RSYNC_FLAGS.join(" "),
                ALLOWED_RSYNC_SHORT_LETTERS
            )));
        }
        out.push(tok.to_string());
    }
    Ok(out)
}

/// A token that is safe inside the whitespace-split `rsync -e` value: no whitespace, quote,
/// backslash or shell metacharacter.
fn is_remote_shell_token(tok: &str) -> bool {
    !tok.is_empty()
        && tok
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '=' | '.' | '_'))
}

/// Connection values that passed validation. Only this type reaches argv construction.
struct SshTarget {
    host: String,
    port: u16,
    user: String,
    host_key: &'static str,
}

impl SshTarget {
    fn new(
        host: &str,
        port: u16,
        user: &str,
        metadata: &HashMap<String, String>,
    ) -> Result<Self, PluginError> {
        validate_host(host)?;
        validate_user(user)?;
        validate_port(port)?;
        let host_key = match metadata.get("ssh.strict_host_key_checking") {
            Some(v) => validate_host_key_checking(v)?,
            None => DEFAULT_HOST_KEY_CHECKING,
        };
        Ok(Self {
            host: host.to_string(),
            port,
            user: user.to_string(),
            host_key,
        })
    }

    fn ssh_args(&self) -> Vec<String> {
        vec![
            "-p".to_string(),
            self.port.to_string(),
            "-o".to_string(),
            format!("StrictHostKeyChecking={}", self.host_key),
            "-o".to_string(),
            "ConnectTimeout=30".to_string(),
        ]
    }

    /// The `rsync -e` value. Built only from `ssh_args()` and every element is checked, so a
    /// field added there without validation cannot reach the whitespace-split string.
    fn rsync_remote_shell(&self) -> Result<String, PluginError> {
        let args = self.ssh_args();
        if !args.iter().all(|a| is_remote_shell_token(a)) {
            return Err(PluginError::ExecutionFailed(
                "internal error: ssh option is not safe for the rsync remote-shell string"
                    .to_string(),
            ));
        }
        Ok(format!("ssh {}", args.join(" ")))
    }

    /// `user@host` for ssh.
    fn ssh_destination(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// `user@host:` prefix for rsync; an IPv6 literal needs brackets.
    fn rsync_destination(&self, dest_dir: &str) -> String {
        if self.host.contains(':') {
            format!("{}@[{}]:{}", self.user, self.host, dest_dir)
        } else {
            format!("{}@{}:{}", self.user, self.host, dest_dir)
        }
    }
}

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

    async fn check_binary_available(name: &str) -> Result<(), PluginError> {
        match tokio_command(name, ChildEnv::Ssh).arg("-V").output().await {
            Ok(_) => Ok(()),
            Err(_) => {
                // Some binaries (like `ssh`) don't support `-V`; retry with `-h`
                // and with no arg. Either way, a missing binary yields
                // NotFound and surfaces as an install hint.
                match tokio_command(name, ChildEnv::Ssh).output().await {
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
        let target = SshTarget::new(&host, port, &user, metadata)?;

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

        validate_source_dir(&source_dir)?;

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

        validate_dest_dir(&dest_dir)?;

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

        for ex in &excludes {
            validate_filter_pattern(ex, "exclude")?;
        }
        let rsync_flags = parse_rsync_flags(&flags_str)?;
        let ssh_cmd = target.rsync_remote_shell()?;
        let rsync_dest = target.rsync_destination(&dest_dir);

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

        let mut cmd = tokio_command("sshpass", ChildEnv::Ssh);
        cmd.env("SSHPASS", &password);
        cmd.arg("-e").arg("rsync");
        for f in &rsync_flags {
            cmd.arg(f);
        }
        for ex in &excludes {
            cmd.arg(format!("--exclude={}", ex));
        }
        if dry_run {
            cmd.arg("--dry-run");
        }
        cmd.arg("-e").arg(&ssh_cmd);
        // `--` ends option parsing so source and destination can never be read as options.
        cmd.arg("--");
        cmd.arg(&source_dir);
        cmd.arg(&rsync_dest);
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
            "sshpass -e rsync {}{} -e \"{}\" -- {} {}",
            rsync_flags.join(" "),
            excludes
                .iter()
                .map(|e| format!(" --exclude={}", e))
                .collect::<String>(),
            ssh_cmd,
            source_dir,
            rsync_dest
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
        let target = SshTarget::new(&host, port, &user, metadata)?;

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

        for (idx, c) in commands.iter().enumerate() {
            validate_remote_command(c, idx)?;
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

        let ssh_base_args = target.ssh_args();
        let destination = target.ssh_destination();

        let mut results: Vec<serde_json::Value> = Vec::with_capacity(commands.len());
        let mut overall_ok = true;

        for (idx, command) in commands.iter().enumerate() {
            if idx > 0 && interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }

            let mut cmd = tokio_command("sshpass", ChildEnv::Ssh);
            cmd.env("SSHPASS", &password);
            cmd.arg("-e").arg("ssh");
            for a in &ssh_base_args {
                cmd.arg(a);
            }
            // `--` ends option parsing so the destination is never read as an option.
            cmd.arg("--");
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

    fn target(meta: &HashMap<String, String>) -> SshTarget {
        SshTarget::new("example.com", 2222, "root", meta).unwrap()
    }

    #[test]
    fn test_ssh_args_use_metadata_host_key() {
        let mut m = HashMap::new();
        m.insert(
            "ssh.strict_host_key_checking".to_string(),
            " no ".to_string(),
        );
        let args = target(&m).ssh_args();
        assert_eq!(
            args,
            vec![
                "-p",
                "2222",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=30"
            ]
        );
    }

    #[test]
    fn test_ssh_args_default_host_key_is_accept_new() {
        let args = target(&HashMap::new()).ssh_args();
        assert!(args.iter().any(|a| a == "StrictHostKeyChecking=accept-new"));
    }

    #[test]
    fn test_rsync_remote_shell_exact() {
        assert_eq!(
            target(&HashMap::new()).rsync_remote_shell().unwrap(),
            "ssh -p 2222 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30"
        );
    }

    #[test]
    fn test_remote_shell_token_check() {
        for ok in ["-p", "2222", "StrictHostKeyChecking=accept-new", "a.b_c"] {
            assert!(is_remote_shell_token(ok), "{ok}");
        }
        for bad in [
            "", "a b", "a\"b", "a'b", "a\\b", "a;b", "a$b", "a\nb", "a`b", "a|b",
        ] {
            assert!(!is_remote_shell_token(bad), "{bad:?}");
        }
    }

    #[test]
    fn test_host_key_checking_values() {
        for ok in ["yes", "no", "accept-new", "ask", "off", "  yes\n"] {
            assert!(validate_host_key_checking(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "Yes",
            "NO",
            "yes -o ProxyCommand=x",
            "no\nProxyCommand x",
            "yes'",
            "\"yes\"",
            "-o",
            "accept_new",
        ] {
            let e = validate_host_key_checking(bad).unwrap_err().to_string();
            assert!(e.contains("accept-new"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn test_validate_host() {
        for ok in [
            "example.com",
            "a-b.example.com",
            "host1",
            "10.0.0.1",
            "::1",
            "2001:db8::1",
            "example.com.",
        ] {
            assert!(validate_host(ok).is_ok(), "{ok}");
        }
        let long = format!("{}.com", "a".repeat(250));
        let long_label = format!("{}.com", "a".repeat(64));
        for bad in [
            "",
            "-oProxyCommand=x",
            ".example.com",
            "a b",
            "a\tb",
            "ex ample.com",
            "a_b.com",
            "a'b",
            "a;b",
            "a..b",
            "host\n",
            "user@host",
            "a:b",
            "fe80::1%eth0",
            &long,
            &long_label,
        ] {
            assert!(validate_host(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_validate_user_and_port() {
        for ok in ["root", "deploy.user", "a_b-c", "U1"] {
            assert!(validate_user(ok).is_ok(), "{ok}");
        }
        let long = "a".repeat(65);
        for bad in ["", "-oFoo", "a b", "a@b", "a\nb", "a'b", "a;b", &long] {
            assert!(validate_user(bad).is_err(), "{bad:?}");
        }
        assert!(validate_user(&"a".repeat(64)).is_ok());
        assert!(validate_port(1).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_dirs() {
        for ok in [
            "/srv/app/",
            "relative/dir",
            "./a:b",
            "/tmp/with space",
            "~/x",
        ] {
            assert!(validate_dest_dir(ok).is_ok(), "{ok}");
        }
        for ok in ["/src/", "src/", "./a:b", "/a:b"] {
            assert!(validate_source_dir(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "-x", "--delete", "a\nb", "a\0b", "::module", ":x", "~-", "~-/x",
        ] {
            assert!(validate_dest_dir(bad).is_err(), "{bad:?}");
        }
        for bad in [
            "",
            "-x",
            "--delete",
            "a\nb",
            "a\u{7f}b",
            "host:path",
            "rsync://h/m",
        ] {
            assert!(validate_source_dir(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_parse_rsync_flags_accepts_allowlist() {
        let all = ALLOWED_RSYNC_FLAGS.join(" ");
        assert_eq!(
            parse_rsync_flags(&all).unwrap().len(),
            ALLOWED_RSYNC_FLAGS.len()
        );
        assert_eq!(
            parse_rsync_flags(DEFAULT_RSYNC_FLAGS).unwrap(),
            vec!["-avz"]
        );
        assert_eq!(
            parse_rsync_flags("-a  --exclude=*.log --include=keep.txt").unwrap(),
            vec!["-a", "--exclude=*.log", "--include=keep.txt"]
        );
        assert!(parse_rsync_flags("").unwrap().is_empty());
        assert!(parse_rsync_flags("-rtn").is_ok());
    }

    #[test]
    fn test_parse_rsync_flags_refuses_others() {
        for bad in [
            "-e",
            "-e ssh",
            "--rsh=ssh",
            "--rsh",
            "-avze",
            "-avx",
            "-",
            "--",
            "---a",
            "-a -e",
            "--exclude=",
            "--exclude=-x",
            "--include=",
            "--exclude",
            "--delete-excluded",
            "--files-from=/etc/passwd",
            "--config=/x",
            "--rsync-path=x",
            "a",
            "--ARCHIVE",
            "-A",
        ] {
            let e = parse_rsync_flags(bad).unwrap_err().to_string();
            assert!(
                e.contains("rsync flag") || e.contains("pattern"),
                "{bad:?}: {e}"
            );
        }
        // A second flag after a space is checked token by token.
        let e = parse_rsync_flags("-a --rsh=x").unwrap_err().to_string();
        assert!(e.contains("--rsh=x"), "{e}");
    }

    #[test]
    fn test_validate_remote_command_and_filter() {
        assert!(validate_remote_command("uptime", 0).is_ok());
        assert!(validate_remote_command("echo hi; ls", 0).is_ok());
        for bad in ["", "-oProxyCommand=x", "-v"] {
            assert!(validate_remote_command(bad, 3)
                .unwrap_err()
                .to_string()
                .contains("commands[3]"));
        }
        assert!(validate_filter_pattern("*.log", "exclude").is_ok());
        for bad in ["", "-x", "a\nb"] {
            assert!(validate_filter_pattern(bad, "exclude").is_err());
        }
    }

    #[test]
    fn test_rsync_destination_brackets_ipv6() {
        let t = SshTarget::new("::1", 22, "u", &HashMap::new()).unwrap();
        assert_eq!(t.rsync_destination("/d"), "u@[::1]:/d");
        assert_eq!(t.ssh_destination(), "u@::1");
        let t = SshTarget::new("h.example", 22, "u", &HashMap::new()).unwrap();
        assert_eq!(t.rsync_destination("/d"), "u@h.example:/d");
    }

    #[test]
    fn test_target_refuses_bad_metadata_host_key() {
        let mut m = HashMap::new();
        m.insert(
            "ssh.strict_host_key_checking".to_string(),
            "no -o ProxyCommand=x".to_string(),
        );
        assert!(SshTarget::new("example.com", 22, "root", &m).is_err());
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
