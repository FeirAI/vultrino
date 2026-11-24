//! PostgreSQL plugin for running SQL and taking backups.
//!
//! Two actions, both authenticated with a stored `Postgres` credential:
//!
//! - `run_sql` — execute SQL (raw string or from a file) against the DB.
//! - `backup`  — run `pg_dump` and write the output to a local file.
//!
//! # Per-instance configuration
//!
//! Each credential alias is an "instance". Defaults for action inputs live in
//! the credential's `metadata` map (flat `String -> String`).
//!
//! run_sql keys:
//!   - `run_sql.sql`             - default SQL string (mutually exclusive with `run_sql.file`)
//!   - `run_sql.file`            - default path to a `.sql` file on the local machine
//!   - `run_sql.transaction`     - `"true"` (default) to wrap in a single transaction
//!   - `run_sql.statement_timeout_ms` - Postgres `statement_timeout` (default `0` = no limit)
//!   - `run_sql.timeout_secs`    - total wall-clock timeout for the psql process (default 600s)
//!   - `run_sql.allow_override`  - `"true"` to let callers pass `sql` / `file` in params
//!
//! backup keys:
//!   - `backup.output_dir` - directory on the local machine to write the dump into
//!   - `backup.filename_template` - filename template. Supported tokens: `{alias}`,
//!     `{date}` (`YYYY-MM-DD`), `{time}` (`HH-MM-SS`), `{timestamp}` (unix seconds).
//!     Default: `"{alias}-{timestamp}.sql"`
//!   - `backup.format` - pg_dump `-F` flag: `plain` (default), `custom`, `directory`, `tar`
//!   - `backup.timeout_secs` - total timeout for pg_dump (default 1800s)
//!   - `backup.allow_override` - `"true"` to let callers pass `output_path` / `format`
//!
//! # Caller-supplied SQL runs in psql's restricted mode
//!
//! With `run_sql.allow_override=true` a caller may pass `sql` or `file`. psql executes
//! backslash meta-commands from its input (`\!` runs a shell command on the proxy host as
//! the proxy's user; `\copy .. to program`, `\o |cmd`, `\g |cmd`, `\i`, `\w`, `\cd`,
//! `\setenv`, `\gexec` are also dangerous). So caller-supplied SQL (inline, or the content
//! of a caller-named file) is fed on stdin after a `\restrict <random key>` line. In
//! restricted mode psql refuses every meta-command except `\unrestrict <key>`, and the key
//! is 128 random bits that the caller never sees, so nothing can lift the restriction. psql
//! must support `\restrict` (17.6, 16.10, 15.14, 14.19, 13.22, or 18 and later); with an
//! older or unrecognised psql, caller-supplied SQL is refused. SQL authored by the operator
//! in credential metadata (`run_sql.sql`, `run_sql.file`) is trusted configuration and runs
//! as before, meta-commands included.
//!
//! # Authentication
//!
//! The password is passed to `psql` and `pg_dump` via the `PGPASSWORD`
//! environment variable of the child process. It is never visible in `ps`
//! output and never touches disk. The agent invoking the plugin only sees the
//! credential alias.

use super::child_process::{tokio_command, ChildEnv};
use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

const DEFAULT_RUN_SQL_TIMEOUT_SECS: u64 = 600;
const DEFAULT_BACKUP_TIMEOUT_SECS: u64 = 1800;
const DEFAULT_BACKUP_FILENAME_TEMPLATE: &str = "{alias}-{timestamp}.sql";
const DEFAULT_BACKUP_FORMAT: &str = "plain";
/// Largest caller-named SQL file the plugin will read into the restricted stdin script.
const MAX_CALLER_SQL_FILE_BYTES: u64 = 64 * 1024 * 1024;
const VALID_FORMATS: &[&str] = &["plain", "custom", "directory", "tar"];

/// Postgres plugin: `run_sql` and `backup` actions.
pub struct PostgresPlugin;

impl PostgresPlugin {
    pub fn new() -> Self {
        Self
    }

    fn extract_postgres_credential(data: &CredentialData) -> Result<PgConn, PluginError> {
        match data {
            CredentialData::Postgres {
                host,
                port,
                database,
                user,
                password,
                sslmode,
            } => Ok(PgConn {
                host: host.clone(),
                port: *port,
                database: database.clone(),
                user: user.clone(),
                password: password.expose().to_string(),
                sslmode: sslmode.clone(),
            }),
            _ => Err(PluginError::UnsupportedCredentialType(
                "postgres plugin requires a postgres credential".to_string(),
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

    /// `(major, minor)` from `psql --version` output such as
    /// `psql (PostgreSQL) 18.3 (Homebrew)`. A pre-release (`18beta1`, `19devel`) or anything
    /// else unrecognised yields `None`, which callers treat as "not supported".
    fn parse_psql_version(output: &str) -> Option<(u32, u32)> {
        let token = output
            .split("(PostgreSQL)")
            .nth(1)?
            .split_whitespace()
            .next()?;
        let (major, rest) = token.split_once('.')?;
        let minor_digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        Some((major.parse().ok()?, minor_digits.parse().ok()?))
    }

    /// Whether this psql has `\restrict` (CVE-2025-8714 fix, 2025-08-14 minor releases).
    fn psql_supports_restrict(version: (u32, u32)) -> bool {
        let (major, minor) = version;
        match major {
            13 => minor >= 22,
            14 => minor >= 19,
            15 => minor >= 14,
            16 => minor >= 10,
            17 => minor >= 6,
            m => m >= 18,
        }
    }

    /// Runs `psql --version` once for this call. `Err` if psql is missing.
    async fn psql_version_output() -> Result<String, PluginError> {
        match tokio_command("psql", ChildEnv::Postgres)
            .arg("--version")
            .output()
            .await
        {
            Ok(o) => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
            Err(_) => Err(PluginError::ExecutionFailed(
                "required binary 'psql' not found on PATH. Install the postgresql-client package (or Homebrew's `libpq`) and ensure `psql` and `pg_dump` are available.".to_string(),
            )),
        }
    }

    /// A fresh psql restrict key: 128 random bits as 32 hex characters (psql accepts only
    /// alphanumerics). Never logged, never returned.
    fn new_restrict_key() -> String {
        use rand::TryRng;
        let mut bytes = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .expect("SysRng failure");
        hex::encode(bytes)
    }

    /// The stdin script for caller-supplied SQL: restricted mode first, then the optional
    /// statement timeout, then the caller's text. `\unrestrict` is never sent.
    fn restricted_script(key: &str, statement_timeout_ms: u64, sql: &str) -> String {
        let mut script = format!("\\restrict {key}\n");
        if statement_timeout_ms > 0 {
            script.push_str(&format!(
                "SET statement_timeout = {statement_timeout_ms};\n"
            ));
        }
        script.push_str(sql);
        script
    }

    async fn check_binary_available(name: &str) -> Result<(), PluginError> {
        match tokio_command(name, ChildEnv::Postgres).arg("--version").output().await {
            Ok(_) => Ok(()),
            Err(_) => Err(PluginError::ExecutionFailed(format!(
                "required binary '{}' not found on PATH. Install the postgresql-client package (or Homebrew's `libpq`) and ensure `psql` and `pg_dump` are available.",
                name
            ))),
        }
    }

    fn base_psql_args(conn: &PgConn) -> Vec<String> {
        vec![
            "-h".to_string(),
            conn.host.clone(),
            "-p".to_string(),
            conn.port.to_string(),
            "-U".to_string(),
            conn.user.clone(),
            "-d".to_string(),
            conn.database.clone(),
        ]
    }

    fn render_filename_template(template: &str, alias: &str, now: chrono::DateTime<Utc>) -> String {
        template
            .replace("{alias}", alias)
            .replace("{date}", &now.format("%Y-%m-%d").to_string())
            .replace("{time}", &now.format("%H-%M-%S").to_string())
            .replace("{timestamp}", &now.timestamp().to_string())
    }

    async fn execute_run_sql(
        &self,
        params: serde_json::Value,
        metadata: &HashMap<String, String>,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let conn = Self::extract_postgres_credential(cred_data)?;

        let allow_override = Self::metadata_bool(metadata, "run_sql.allow_override", false);
        let param_obj = params.as_object();

        let sql_param = param_obj
            .and_then(|o| o.get("sql"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let file_param = param_obj
            .and_then(|o| o.get("file"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if (sql_param.is_some() || file_param.is_some()) && !allow_override {
            return Err(PluginError::InvalidParams(
                "run_sql.allow_override is not enabled on this credential; cannot pass sql/file params. Set metadata run_sql.allow_override=true to allow.".to_string(),
            ));
        }

        // Resolve the actual SQL source: param (if allowed) > metadata > error.
        enum SqlSource {
            /// Operator-authored inline SQL (metadata): trusted, meta-commands allowed.
            Inline(String),
            /// Operator-authored file (metadata): trusted, run with `-f`.
            File(PathBuf),
            /// Caller-supplied SQL or file content (needs `allow_override`): run in psql's
            /// restricted mode. The second field is the `source` shown in the response.
            Caller(String, String),
        }

        let sql_source: SqlSource = if let Some(s) = sql_param {
            SqlSource::Caller(s, "inline".to_string())
        } else if let Some(f) = file_param {
            // The file is read here and fed through the restricted stdin script, never given
            // to psql as `-f`, because psql would execute meta-commands found in the file.
            let p = PathBuf::from(&f);
            if !p.is_file() {
                return Err(PluginError::InvalidParams(format!(
                    "SQL file not found or not a regular file: {}",
                    p.display()
                )));
            }
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(u64::MAX);
            if len > MAX_CALLER_SQL_FILE_BYTES {
                return Err(PluginError::InvalidParams(format!(
                    "SQL file is larger than {} bytes: {}",
                    MAX_CALLER_SQL_FILE_BYTES,
                    p.display()
                )));
            }
            let content = std::fs::read_to_string(&p).map_err(|e| {
                PluginError::InvalidParams(format!(
                    "SQL file cannot be read as UTF-8 text: {}: {}",
                    p.display(),
                    e
                ))
            })?;
            SqlSource::Caller(content, format!("file:{}", p.display()))
        } else if let Some(s) = metadata.get("run_sql.sql") {
            SqlSource::Inline(s.clone())
        } else if let Some(f) = metadata.get("run_sql.file") {
            SqlSource::File(PathBuf::from(f))
        } else {
            return Err(PluginError::InvalidParams(
                "no SQL configured: set metadata run_sql.sql or run_sql.file, or pass one as a param with run_sql.allow_override enabled".to_string(),
            ));
        };

        // Validate file path exists and is readable before spawning psql.
        if let SqlSource::File(ref p) = sql_source {
            if !Path::new(p).is_file() {
                return Err(PluginError::InvalidParams(format!(
                    "SQL file not found or not a regular file: {}",
                    p.display()
                )));
            }
        }

        let wrap_in_transaction = param_obj
            .and_then(|o| o.get("transaction"))
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| Self::metadata_bool(metadata, "run_sql.transaction", true));

        let statement_timeout_ms = Self::metadata_u64(metadata, "run_sql.statement_timeout_ms", 0);

        let wall_timeout_secs = param_obj
            .and_then(|o| o.get("timeout_secs"))
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                Self::metadata_u64(
                    metadata,
                    "run_sql.timeout_secs",
                    DEFAULT_RUN_SQL_TIMEOUT_SECS,
                )
            });

        let version_output = Self::psql_version_output().await?;
        let restrict_key = if matches!(sql_source, SqlSource::Caller(..)) {
            // Fail closed: caller-supplied SQL is only ever run in restricted mode.
            match Self::parse_psql_version(&version_output) {
                Some(v) if Self::psql_supports_restrict(v) => Some(Self::new_restrict_key()),
                _ => {
                    return Err(PluginError::ExecutionFailed(format!(
                        "caller-supplied SQL refused: the installed psql ({}) cannot be confirmed to support \\restrict, which keeps caller SQL from running psql meta-commands such as \\!. Upgrade psql to 17.6, 16.10, 15.14, 14.19, 13.22 or 18 and later, or put the SQL in credential metadata (run_sql.sql / run_sql.file).",
                        version_output.trim()
                    )))
                }
            }
        } else {
            None
        };

        let mut cmd = tokio_command("psql", ChildEnv::Postgres);
        cmd.env("PGPASSWORD", &conn.password);
        cmd.env("PGSSLMODE", &conn.sslmode);
        cmd.env("PGCONNECT_TIMEOUT", "30");
        for arg in Self::base_psql_args(&conn) {
            cmd.arg(arg);
        }
        cmd.arg("--no-psqlrc");
        cmd.arg("-v").arg("ON_ERROR_STOP=1");
        if wrap_in_transaction {
            cmd.arg("--single-transaction");
        }
        match &sql_source {
            SqlSource::File(p) => {
                if statement_timeout_ms > 0 {
                    cmd.arg("-c")
                        .arg(format!("SET statement_timeout = {};", statement_timeout_ms));
                }
                cmd.arg("-f").arg(p);
                cmd.stdin(Stdio::null());
            }
            // With `-c` psql does not read stdin at all, so for stdin-fed SQL the timeout is
            // set by a statement inside the script instead.
            SqlSource::Inline(_) | SqlSource::Caller(..) => {
                cmd.stdin(Stdio::piped());
            }
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        let started = Instant::now();
        let spawn_result = cmd.spawn();
        let mut child = match spawn_result {
            Ok(c) => c,
            Err(e) => {
                return Err(PluginError::ExecutionFailed(format!(
                    "psql failed to spawn: {}",
                    e
                )))
            }
        };

        // Feed inline SQL via stdin (safe against shell injection; not via -c).
        let stdin_script: Option<String> = match &sql_source {
            SqlSource::Caller(sql, _) => Some(Self::restricted_script(
                restrict_key.as_deref().unwrap_or_default(),
                statement_timeout_ms,
                sql,
            )),
            SqlSource::Inline(sql) => Some(if statement_timeout_ms > 0 {
                format!("SET statement_timeout = {statement_timeout_ms};\n{sql}")
            } else {
                sql.clone()
            }),
            SqlSource::File(_) => None,
        };
        if let Some(script) = stdin_script {
            if let Some(mut stdin) = child.stdin.take() {
                let bytes = script.into_bytes();
                if let Err(e) = stdin.write_all(&bytes).await {
                    return Err(PluginError::ExecutionFailed(format!(
                        "failed to write SQL to psql stdin: {}",
                        e
                    )));
                }
                let _ = stdin.shutdown().await;
                drop(stdin);
            }
        }

        let wait_result = timeout(
            Duration::from_secs(wall_timeout_secs),
            child.wait_with_output(),
        )
        .await;
        let duration_ms = started.elapsed().as_millis() as u64;

        let (exit_code, stdout, stderr, timed_out) = match wait_result {
            Ok(Ok(output)) => (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
                false,
            ),
            Ok(Err(e)) => {
                return Err(PluginError::ExecutionFailed(format!(
                    "psql wait failed: {}",
                    e
                )))
            }
            Err(_) => (
                -1,
                String::new(),
                format!(
                    "psql timed out after {}s (local process killed; the current transaction will be rolled back on disconnect)",
                    wall_timeout_secs
                ),
                true,
            ),
        };

        let source_display = match &sql_source {
            SqlSource::File(p) => format!("file:{}", p.display()),
            SqlSource::Inline(_) => "inline".to_string(),
            SqlSource::Caller(_, shown) => shown.clone(),
        };

        let body = serde_json::json!({
            "ok": exit_code == 0 && !timed_out,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "source": source_display,
            "transaction": wrap_in_transaction,
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

    async fn execute_backup(
        &self,
        params: serde_json::Value,
        metadata: &HashMap<String, String>,
        credential_alias: &str,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let conn = Self::extract_postgres_credential(cred_data)?;

        let allow_override = Self::metadata_bool(metadata, "backup.allow_override", false);
        let param_obj = params.as_object();

        let output_path_param = param_obj
            .and_then(|o| o.get("output_path"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let format_param = param_obj
            .and_then(|o| o.get("format"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if (output_path_param.is_some() || format_param.is_some()) && !allow_override {
            return Err(PluginError::InvalidParams(
                "backup.allow_override is not enabled on this credential; cannot pass output_path/format params. Set metadata backup.allow_override=true to allow.".to_string(),
            ));
        }

        let format = format_param
            .or_else(|| metadata.get("backup.format").cloned())
            .unwrap_or_else(|| DEFAULT_BACKUP_FORMAT.to_string());
        if !VALID_FORMATS.contains(&format.as_str()) {
            return Err(PluginError::InvalidParams(format!(
                "invalid backup format '{}'; must be one of: {}",
                format,
                VALID_FORMATS.join(", ")
            )));
        }

        // Resolve output path: explicit param > output_dir + filename_template.
        let output_path = if let Some(p) = output_path_param {
            PathBuf::from(p)
        } else {
            let output_dir = metadata.get("backup.output_dir").cloned().ok_or_else(|| {
                PluginError::InvalidParams(
                    "no backup destination configured: set metadata backup.output_dir, or pass output_path with backup.allow_override enabled".to_string(),
                )
            })?;
            let template = metadata
                .get("backup.filename_template")
                .cloned()
                .unwrap_or_else(|| DEFAULT_BACKUP_FILENAME_TEMPLATE.to_string());
            let filename = Self::render_filename_template(&template, credential_alias, Utc::now());
            PathBuf::from(output_dir).join(filename)
        };

        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(PluginError::InvalidParams(format!(
                    "backup destination directory does not exist: {}",
                    parent.display()
                )));
            }
        }

        let wall_timeout_secs = param_obj
            .and_then(|o| o.get("timeout_secs"))
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                Self::metadata_u64(metadata, "backup.timeout_secs", DEFAULT_BACKUP_TIMEOUT_SECS)
            });

        Self::check_binary_available("pg_dump").await?;

        let mut cmd = tokio_command("pg_dump", ChildEnv::Postgres);
        cmd.env("PGPASSWORD", &conn.password);
        cmd.env("PGSSLMODE", &conn.sslmode);
        cmd.env("PGCONNECT_TIMEOUT", "30");
        cmd.arg("-h").arg(&conn.host);
        cmd.arg("-p").arg(conn.port.to_string());
        cmd.arg("-U").arg(&conn.user);
        cmd.arg("-d").arg(&conn.database);
        cmd.arg("-F").arg(format_flag(&format));
        cmd.arg("-f").arg(&output_path);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        let started = Instant::now();
        let result = timeout(Duration::from_secs(wall_timeout_secs), cmd.output()).await;
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
                    "pg_dump failed to spawn: {}",
                    e
                )))
            }
            Err(_) => (
                -1,
                String::new(),
                format!("pg_dump timed out after {}s (local process killed; partial output file may exist and should be deleted)", wall_timeout_secs),
                true,
            ),
        };

        let bytes_written: Option<u64> = std::fs::metadata(&output_path).ok().map(|m| m.len());

        let body = serde_json::json!({
            "ok": exit_code == 0 && !timed_out,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "output_path": output_path.display().to_string(),
            "format": format,
            "bytes_written": bytes_written,
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
}

fn format_flag(format: &str) -> &str {
    match format {
        "plain" => "p",
        "custom" => "c",
        "directory" => "d",
        "tar" => "t",
        // Validated earlier; fall back defensively.
        _ => "p",
    }
}

/// Resolved connection tuple used internally.
struct PgConn {
    host: String,
    port: u16,
    database: String,
    user: String,
    password: String,
    sslmode: String,
}

impl Default for PostgresPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for PostgresPlugin {
    fn name(&self) -> &str {
        "postgres"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::Postgres]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["run_sql", "backup"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        let metadata = request.credential.metadata.clone();
        let alias = request.credential.alias.clone();
        match request.action.as_str() {
            "run_sql" => {
                self.execute_run_sql(request.params, &metadata, &request.credential.data)
                    .await
            }
            "backup" => {
                self.execute_backup(request.params, &metadata, &alias, &request.credential.data)
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
            "run_sql" => {
                if let Some(obj) = params.as_object() {
                    for key in ["sql", "file"] {
                        if let Some(v) = obj.get(key) {
                            if !v.is_string() {
                                return Err(PluginError::InvalidParams(format!(
                                    "{} must be a string",
                                    key
                                )));
                            }
                        }
                    }
                    if obj.contains_key("sql") && obj.contains_key("file") {
                        return Err(PluginError::InvalidParams(
                            "cannot provide both 'sql' and 'file'; choose one".to_string(),
                        ));
                    }
                    if let Some(v) = obj.get("transaction") {
                        if !v.is_boolean() {
                            return Err(PluginError::InvalidParams(
                                "transaction must be a boolean".to_string(),
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
            "backup" => {
                if let Some(obj) = params.as_object() {
                    if let Some(v) = obj.get("output_path") {
                        if !v.is_string() {
                            return Err(PluginError::InvalidParams(
                                "output_path must be a string".to_string(),
                            ));
                        }
                    }
                    if let Some(v) = obj.get("format") {
                        let f = v.as_str().ok_or_else(|| {
                            PluginError::InvalidParams("format must be a string".to_string())
                        })?;
                        if !VALID_FORMATS.contains(&f) {
                            return Err(PluginError::InvalidParams(format!(
                                "invalid format '{}'; must be one of: {}",
                                f,
                                VALID_FORMATS.join(", ")
                            )));
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
        vec![
            super::types::McpToolDefinition {
                name: "run_sql".to_string(),
                action: "run_sql".to_string(),
                description: Some(
                    "Run SQL (string or file) against the Postgres database configured in the credential. Uses per-credential defaults from metadata; param overrides (sql/file) require run_sql.allow_override=true.".to_string(),
                ),
                input_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "credential":  { "type": "string", "description": "Credential alias or ID to run SQL against" },
                        "sql":         { "type": "string", "description": "Raw SQL to execute (requires run_sql.allow_override=true)" },
                        "file":        { "type": "string", "description": "Path to a local .sql file (requires run_sql.allow_override=true)" },
                        "transaction": { "type": "boolean", "description": "Wrap in a single transaction (default: true)" },
                        "timeout_secs":{ "type": "integer", "minimum": 1, "description": "Wall-clock timeout for the psql process" }
                    },
                    "required": ["credential"]
                })),
                parameter_mappings: HashMap::new(),
            },
            super::types::McpToolDefinition {
                name: "backup".to_string(),
                action: "backup".to_string(),
                description: Some(
                    "Run pg_dump and write a backup file to the local machine. Destination comes from credential metadata (backup.output_dir + backup.filename_template) unless backup.allow_override=true.".to_string(),
                ),
                input_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "credential":  { "type": "string", "description": "Credential alias or ID to back up" },
                        "output_path": { "type": "string", "description": "Override output file path (requires backup.allow_override=true)" },
                        "format":      { "type": "string", "enum": ["plain", "custom", "directory", "tar"], "description": "pg_dump format (requires backup.allow_override=true to change from metadata default)" },
                        "timeout_secs":{ "type": "integer", "minimum": 1, "description": "Wall-clock timeout for pg_dump" }
                    },
                    "required": ["credential"]
                })),
                parameter_mappings: HashMap::new(),
            },
        ]
    }

    fn description(&self) -> Option<&str> {
        Some("PostgreSQL SQL execution and backups via stored credentials; password never leaves Vultrino.")
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
}

// (removed the dead `RunSqlParams`/`BackupParams` "doc structs": never deserialized — the action impls
// parse loosely — so they were an unenforced parallel schema that could only drift from the real parsing.)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Credential, RequestContext, Secret};

    fn mk_cred(metadata: HashMap<String, String>) -> Credential {
        let mut cred = Credential::new(
            "test-pg".to_string(),
            CredentialData::Postgres {
                host: "localhost".to_string(),
                port: 5432,
                database: "testdb".to_string(),
                user: "testuser".to_string(),
                password: Secret::new("unused-in-unit-tests"),
                sslmode: "prefer".to_string(),
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
        let p = PostgresPlugin::new();
        assert_eq!(p.name(), "postgres");
        assert_eq!(p.supported_actions(), vec!["run_sql", "backup"]);
        assert_eq!(
            p.supported_credential_types(),
            vec![CredentialType::Postgres]
        );
    }

    #[test]
    fn psql_version_parsing_and_restrict_support() {
        let p = PostgresPlugin::parse_psql_version;
        assert_eq!(p("psql (PostgreSQL) 18.3 (Homebrew)\n"), Some((18, 3)));
        assert_eq!(
            p("psql (PostgreSQL) 16.10 (Ubuntu 16.10-1)"),
            Some((16, 10))
        );
        assert_eq!(p("psql (PostgreSQL) 18beta1"), None);
        assert_eq!(p("psql (PostgreSQL) 19devel"), None);
        assert_eq!(p("garbage"), None);
        assert_eq!(p(""), None);
        let ok = PostgresPlugin::psql_supports_restrict;
        for v in [
            (13, 22),
            (14, 19),
            (15, 14),
            (16, 10),
            (17, 6),
            (18, 0),
            (19, 2),
        ] {
            assert!(ok(v), "{v:?} has \\restrict");
        }
        for v in [
            (13, 21),
            (14, 18),
            (15, 13),
            (16, 9),
            (17, 5),
            (12, 22),
            (9, 6),
        ] {
            assert!(!ok(v), "{v:?} lacks \\restrict");
        }
    }

    #[test]
    fn restricted_script_puts_restrict_first_and_never_unrestricts() {
        let key = PostgresPlugin::new_restrict_key();
        assert_eq!(key.len(), 32);
        assert!(key.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(key, PostgresPlugin::new_restrict_key());
        let sql = "select 1;\n\\! id\n";
        let script = PostgresPlugin::restricted_script(&key, 250, sql);
        assert!(script.starts_with(&format!("\\restrict {key}\nSET statement_timeout = 250;\n")));
        assert!(script.ends_with(sql));
        assert!(!script.contains("\\unrestrict"));
        assert_eq!(
            PostgresPlugin::restricted_script(&key, 0, "x"),
            format!("\\restrict {key}\nx")
        );
    }

    #[test]
    fn test_format_flag_mapping() {
        assert_eq!(format_flag("plain"), "p");
        assert_eq!(format_flag("custom"), "c");
        assert_eq!(format_flag("directory"), "d");
        assert_eq!(format_flag("tar"), "t");
        // fallback behavior
        assert_eq!(format_flag("bogus"), "p");
    }

    #[test]
    fn test_filename_template_tokens() {
        let t = "2026-01-02T03:04:05Z";
        let now: chrono::DateTime<Utc> = t.parse().unwrap();
        let rendered = PostgresPlugin::render_filename_template(
            "{alias}-{date}-{time}-{timestamp}.sql",
            "prod-db",
            now,
        );
        assert!(rendered.contains("prod-db"));
        assert!(rendered.contains("2026-01-02"));
        assert!(rendered.contains("03-04-05"));
        assert!(rendered.ends_with(".sql"));
    }

    #[test]
    fn test_validate_run_sql_ok() {
        let p = PostgresPlugin::new();
        assert!(p.validate_params("run_sql", &serde_json::json!({})).is_ok());
        assert!(p
            .validate_params("run_sql", &serde_json::json!({"sql": "SELECT 1;"}))
            .is_ok());
        assert!(p
            .validate_params("run_sql", &serde_json::json!({"file": "/tmp/a.sql"}))
            .is_ok());
        assert!(p
            .validate_params(
                "run_sql",
                &serde_json::json!({"transaction": false, "timeout_secs": 30})
            )
            .is_ok());
    }

    #[test]
    fn test_validate_run_sql_rejects_both_sql_and_file() {
        let p = PostgresPlugin::new();
        let err = p
            .validate_params(
                "run_sql",
                &serde_json::json!({"sql": "SELECT 1;", "file": "/tmp/a.sql"}),
            )
            .unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn test_validate_run_sql_bad_types() {
        let p = PostgresPlugin::new();
        assert!(p
            .validate_params("run_sql", &serde_json::json!({"sql": 42}))
            .is_err());
        assert!(p
            .validate_params("run_sql", &serde_json::json!({"transaction": "yes"}))
            .is_err());
        assert!(p
            .validate_params("run_sql", &serde_json::json!({"timeout_secs": -1}))
            .is_err());
    }

    #[test]
    fn test_validate_backup_ok() {
        let p = PostgresPlugin::new();
        assert!(p.validate_params("backup", &serde_json::json!({})).is_ok());
        assert!(p
            .validate_params("backup", &serde_json::json!({"format": "custom"}))
            .is_ok());
    }

    #[test]
    fn test_validate_backup_rejects_bad_format() {
        let p = PostgresPlugin::new();
        let err = p
            .validate_params("backup", &serde_json::json!({"format": "bogus"}))
            .unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn test_validate_unknown_action() {
        let p = PostgresPlugin::new();
        assert!(p
            .validate_params("restore", &serde_json::json!({}))
            .is_err());
    }

    #[tokio::test]
    async fn test_run_sql_no_source_errors() {
        let p = PostgresPlugin::new();
        let req = mk_request("run_sql", serde_json::json!({}), HashMap::new());
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("run_sql.sql"));
    }

    #[tokio::test]
    async fn test_run_sql_override_locked_by_default() {
        let p = PostgresPlugin::new();
        let mut meta = HashMap::new();
        meta.insert("run_sql.sql".to_string(), "SELECT 1;".to_string());
        let req = mk_request(
            "run_sql",
            serde_json::json!({"sql": "DROP TABLE users;"}),
            meta,
        );
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("allow_override"));
    }

    #[tokio::test]
    async fn test_run_sql_missing_file_errors_clearly() {
        let p = PostgresPlugin::new();
        let mut meta = HashMap::new();
        meta.insert(
            "run_sql.file".to_string(),
            "/nonexistent/path/migrate.sql".to_string(),
        );
        let req = mk_request("run_sql", serde_json::json!({}), meta);
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("file"));
    }

    #[tokio::test]
    async fn test_backup_no_destination_errors() {
        let p = PostgresPlugin::new();
        let req = mk_request("backup", serde_json::json!({}), HashMap::new());
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("backup.output_dir"));
    }

    #[tokio::test]
    async fn test_backup_override_locked_by_default() {
        let p = PostgresPlugin::new();
        let mut meta = HashMap::new();
        meta.insert("backup.output_dir".to_string(), "/tmp".to_string());
        let req = mk_request(
            "backup",
            serde_json::json!({"output_path": "/tmp/evil/dump.sql"}),
            meta,
        );
        let err = p.execute(req).await.unwrap_err();
        assert!(err.to_string().contains("allow_override"));
    }

    #[test]
    fn test_mcp_tools_exposed() {
        let p = PostgresPlugin::new();
        let tools = p.mcp_tool_definitions();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"run_sql"));
        assert!(names.contains(&"backup"));
        assert!(tools.iter().all(|t| t.input_schema.is_some()));
    }

    #[test]
    fn test_base_psql_args_includes_connection_info() {
        let conn = PgConn {
            host: "db.example.com".to_string(),
            port: 5433,
            database: "app".to_string(),
            user: "deploy".to_string(),
            password: "secret".to_string(),
            sslmode: "require".to_string(),
        };
        let args = PostgresPlugin::base_psql_args(&conn);
        assert!(args.contains(&"-h".to_string()));
        assert!(args.contains(&"db.example.com".to_string()));
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"5433".to_string()));
        assert!(args.contains(&"-U".to_string()));
        assert!(args.contains(&"deploy".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"app".to_string()));
    }
}
