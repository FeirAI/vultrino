//! Child processes get a minimal environment, and caller SQL cannot run psql meta-commands.
//!
//! Real `VultrinoServer::execute_gated` with the real Postgres and SSH plugins and a real
//! `FileStorage`. The programs psql, pg_dump, sshpass and rsync are STUBS written into a
//! temp dir that is put first on PATH; they record environment variable NAMES (never values),
//! their argv and their stdin. Only dummy secrets appear here.
//!
//! Everything shares one process environment, so the tests take `LOCK` and restore PATH.
//! The tests that need a real psql print SKIPPED when psql or python3 is missing.

// LOCK serialises process-environment mutation across awaits on purpose.
#![allow(clippy::await_holding_lock)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use tempfile::tempdir;
use vultrino::auth::{NewUseToken, UseToken};
use vultrino::config::Config;
use vultrino::policy::Policy;
use vultrino::router::CredentialResolver;
use vultrino::server::{ExecAuth, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, ExecuteRequest, ExecutionOutcome, Secret};

static LOCK: Mutex<()> = Mutex::new(());

const MASTER: &str = "ZZMASTER-dummy-0123456789abcdef";
const PG_PW: &str = "pgcred-dummy-password-9876";

const INTERNAL_VARS: &[&str] = &[
    "VULTRINO_PASSWORD",
    "VULTRINO_PASSWORD_FILE",
    "VULTRINO_NEW_PASSWORD",
    "VULTRINO_IDENTITY_SECRET",
    "VULTRINO_POLICY_HASH_SECRET",
    "GOVDER_SHARED_SECRET",
    "AVERIN_TOKEN",
    "LERIA_SECRET",
    "FEIR_SECRET",
    "ORGPACK_SECRET",
];

/// Writes a stub program that records (to $STUB_DIR/<name>.rec) its argv and every env name,
/// copies stdin to $STUB_DIR/<name>.stdin, and answers `--version`/`-V` from
/// $STUB_DIR/psql.version when it is the psql stub.
fn write_stubs(dir: &Path) {
    let script = r#"#!/bin/sh
NAME="$(basename "$0")"
D="$(dirname "$0")"
case "$1" in
  --version) if [ -f "$D/$NAME.version" ]; then cat "$D/$NAME.version"; else echo "$NAME (stub) 0.0"; fi; exit 0;;
  -V) echo "$NAME (stub) 0.0"; exit 0;;
esac
{ echo "argv=$*"; env | cut -d= -f1 | sort | sed 's/^/envname=/'; } > "$D/$NAME.rec"
cat > "$D/$NAME.stdin" 2>/dev/null || true
exit 0
"#;
    for name in ["psql", "pg_dump", "sshpass", "rsync", "ssh"] {
        let p = dir.join(name);
        std::fs::write(&p, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

fn config() -> Config {
    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Deny;
    config.policies = vec![Policy::allow_all("base", "*")];
    config
}

async fn server() -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let pw = SecretString::from("generated-test-password-child-env");
    let storage: Arc<dyn StorageBackend> = Arc::new(FileStorage::new(&path, &pw).await.unwrap());
    let s = VultrinoServer::new(
        config(),
        storage.clone(),
        CredentialResolver::new(storage.clone()),
    );
    (s, storage)
}

async fn run(
    s: &VultrinoServer,
    st: &Arc<dyn StorageBackend>,
    cred: &str,
    action: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let (_p, tok) = UseToken::create(NewUseToken {
        name: "agent".into(),
        credential_scope: "*".into(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    let auth = ExecAuth::from_use_token(tok);
    st.store_use_token(auth.use_token.as_ref().unwrap())
        .await
        .unwrap();
    let req = ExecuteRequest {
        credential: cred.into(),
        action: action.into(),
        params,
    };
    match s.execute_gated(req, auth).await {
        Ok(ExecutionOutcome::Completed(r)) => Ok(serde_json::from_slice(&r.body)
            .unwrap_or(serde_json::json!({"raw": String::from_utf8_lossy(&r.body)}))),
        Ok(_) => Err("pending/other outcome".into()),
        Err(e) => Err(e.to_string()),
    }
}

fn pg_cred(alias: &str, port: u16, allow_override: bool) -> Credential {
    let mut c = Credential::new(
        alias.into(),
        CredentialData::Postgres {
            host: "127.0.0.1".into(),
            port,
            database: "d".into(),
            user: "u".into(),
            password: Secret::new(PG_PW),
            sslmode: "disable".into(),
        },
    );
    if allow_override {
        c = c.with_metadata("run_sql.allow_override", "true");
    }
    c
}

/// Sets the dummy internal secrets and puts `stubs` first on PATH. Returns the old PATH.
fn poison_env(stubs: &Path) -> String {
    let old = std::env::var("PATH").unwrap();
    for v in INTERNAL_VARS {
        std::env::set_var(v, MASTER);
    }
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/dummy-agent.sock");
    std::env::set_var("PGOPTIONS", "-c dummy=1");
    std::env::set_var("PATH", format!("{}:{}", stubs.display(), old));
    old
}

fn restore_env(old_path: &str) {
    for v in INTERNAL_VARS {
        std::env::remove_var(v);
    }
    std::env::remove_var("SSH_AUTH_SOCK");
    std::env::remove_var("PGOPTIONS");
    std::env::set_var("PATH", old_path);
}

fn recorded_names(stubs: &Path, prog: &str) -> Vec<String> {
    std::fs::read_to_string(stubs.join(format!("{prog}.rec")))
        .unwrap_or_else(|_| panic!("{prog} stub did not run"))
        .lines()
        .filter_map(|l| l.strip_prefix("envname=").map(String::from))
        .collect()
}

fn assert_clean(prog: &str, names: &[String]) {
    for n in names {
        for p in [
            "VULTRINO_",
            "GOVDER_",
            "AVERIN_",
            "LERIA_",
            "FEIR_",
            "ORGPACK_",
        ] {
            assert!(!n.starts_with(p), "{prog} child inherited {n}");
        }
        assert_ne!(n, "PGOPTIONS", "{prog} child inherited PGOPTIONS");
        assert_ne!(n, "SSH_AUTH_SOCK", "{prog} child inherited SSH_AUTH_SOCK");
    }
    assert!(
        names.iter().any(|n| n == "PATH"),
        "{prog} child has no PATH"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_ssh_children_get_minimal_environment() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stubs = tempdir().unwrap();
    write_stubs(stubs.path());
    let old = poison_env(stubs.path());

    let (s, st) = server().await;
    st.store(&pg_cred("pg", 5432, false).with_metadata("run_sql.sql", "select 1;"))
        .await
        .unwrap();
    run(&s, &st, "pg", "postgres.run_sql", serde_json::json!({}))
        .await
        .unwrap();
    let names = recorded_names(stubs.path(), "psql");
    assert_clean("psql", &names);
    for need in ["PGPASSWORD", "PGSSLMODE", "PGCONNECT_TIMEOUT", "HOME"] {
        assert!(names.iter().any(|n| n == need), "psql lacks {need}");
    }

    let out = tempdir().unwrap();
    st.store(
        &pg_cred("pgb", 5432, false)
            .with_metadata("backup.output_dir", out.path().to_str().unwrap()),
    )
    .await
    .unwrap();
    run(&s, &st, "pgb", "postgres.backup", serde_json::json!({}))
        .await
        .unwrap();
    let names = recorded_names(stubs.path(), "pg_dump");
    assert_clean("pg_dump", &names);
    assert!(names.iter().any(|n| n == "PGPASSWORD"));

    let ssh = Credential::new(
        "ssh".into(),
        CredentialData::SshPassword {
            host: "127.0.0.1".into(),
            port: 22,
            user: "u".into(),
            password: Secret::new("ssh-dummy-password-1234"),
        },
    )
    .with_metadata("run.commands", "[\"true\"]")
    .with_metadata("deploy.source_dir", "/tmp")
    .with_metadata("deploy.dest_dir", "/tmp/x");
    st.store(&ssh).await.unwrap();
    run(&s, &st, "ssh", "ssh.run", serde_json::json!({}))
        .await
        .unwrap();
    let names = recorded_names(stubs.path(), "sshpass");
    assert_clean("sshpass (ssh.run)", &names);
    for need in ["SSHPASS", "HOME"] {
        assert!(names.iter().any(|n| n == need), "sshpass lacks {need}");
    }
    let _ = std::fs::remove_file(stubs.path().join("sshpass.rec"));
    run(&s, &st, "ssh", "ssh.deploy", serde_json::json!({}))
        .await
        .unwrap();
    assert_clean(
        "sshpass (ssh.deploy)",
        &recorded_names(stubs.path(), "sshpass"),
    );

    restore_env(&old);
}

fn stdin_of(stubs: &Path) -> String {
    std::fs::read_to_string(stubs.join("psql.stdin")).unwrap_or_default()
}

const META_ATTEMPTS: &[&str] = &[
    "\\! id\n",
    "\\copy t to program 'id'\n",
    "\\o |cat\nselect 1;\n",
    "\\i /etc/passwd\n",
    "\\setenv X y\n",
    "select 1; \\! id\n",
    "select 1;\nselect 2;\n\\! id\n",
    "select $$a\n\\! id\n$$;\n",
];

#[tokio::test(flavor = "multi_thread")]
async fn caller_sql_is_sent_only_behind_a_restrict_line() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stubs = tempdir().unwrap();
    write_stubs(stubs.path());
    std::fs::write(
        stubs.path().join("psql.version"),
        "psql (PostgreSQL) 18.3 (stub)\n",
    )
    .unwrap();
    let old = poison_env(stubs.path());
    let (s, st) = server().await;
    st.store(&pg_cred("pg", 5432, true).with_metadata("run_sql.statement_timeout_ms", "5000"))
        .await
        .unwrap();

    let mut keys = Vec::new();
    for sql in META_ATTEMPTS {
        run(
            &s,
            &st,
            "pg",
            "postgres.run_sql",
            serde_json::json!({"sql": sql}),
        )
        .await
        .unwrap();
        let got = stdin_of(stubs.path());
        let (first, rest) = got.split_once('\n').unwrap();
        let key = first.strip_prefix("\\restrict ").expect("restrict first");
        assert!(key.len() >= 32 && key.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!got.contains("\\unrestrict"), "unrestrict was sent");
        assert!(
            rest.starts_with("SET statement_timeout = 5000;\n"),
            "timeout set inside the script: {rest:?}"
        );
        assert!(rest.ends_with(sql), "caller text follows the restrict line");
        assert!(
            !recorded_argv(stubs.path()).contains("-c"),
            "no -c: psql would ignore stdin"
        );
        keys.push(key.to_string());
    }
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), META_ATTEMPTS.len(), "a fresh key for each call");

    // A plain multi-statement script still goes through unchanged after the preamble.
    let script = "create table t(a int);\ninsert into t values (1);\nselect * from t;\n";
    run(
        &s,
        &st,
        "pg",
        "postgres.run_sql",
        serde_json::json!({"sql": script}),
    )
    .await
    .unwrap();
    assert!(stdin_of(stubs.path()).ends_with(script));

    // A caller-named file is read and sent through stdin, never passed as `-f`.
    let f = stubs.path().join("caller.sql");
    std::fs::write(&f, "\\! id\nselect 1;\n").unwrap();
    run(
        &s,
        &st,
        "pg",
        "postgres.run_sql",
        serde_json::json!({"file": f.to_str().unwrap()}),
    )
    .await
    .unwrap();
    assert!(stdin_of(stubs.path()).starts_with("\\restrict "));
    assert!(!recorded_argv(stubs.path()).contains("-f"));

    // Operator-authored SQL from metadata is unchanged: no restrict line, meta-commands kept.
    st.store(
        &pg_cred("pg-op", 5432, false).with_metadata("run_sql.sql", "\\set a 1\nselect :a;\n"),
    )
    .await
    .unwrap();
    run(&s, &st, "pg-op", "postgres.run_sql", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(stdin_of(stubs.path()), "\\set a 1\nselect :a;\n");
    restore_env(&old);
}

fn recorded_argv(stubs: &Path) -> String {
    std::fs::read_to_string(stubs.join("psql.rec"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("argv=").map(String::from))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn caller_sql_is_refused_when_psql_is_too_old_or_unrecognised() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stubs = tempdir().unwrap();
    write_stubs(stubs.path());
    let old = poison_env(stubs.path());
    let (s, st) = server().await;
    st.store(&pg_cred("pg", 5432, true).with_metadata("run_sql.sql", "select 1;"))
        .await
        .unwrap();
    for v in [
        "psql (PostgreSQL) 17.5\n",
        "psql (PostgreSQL) 16.9 (Debian 16.9-1)\n",
        "psql (PostgreSQL) 12.22\n",
        "psql (PostgreSQL) 18beta1\n",
        "something unexpected\n",
        "",
    ] {
        std::fs::write(stubs.path().join("psql.version"), v).unwrap();
        let _ = std::fs::remove_file(stubs.path().join("psql.rec"));
        let r = run(
            &s,
            &st,
            "pg",
            "postgres.run_sql",
            serde_json::json!({"sql": "\\! id\n"}),
        )
        .await;
        let e = r.expect_err(&format!("caller SQL must be refused for {v:?}"));
        assert!(e.contains("restrict"), "clear error: {e}");
        assert!(
            !stubs.path().join("psql.rec").exists(),
            "psql must not run the SQL for {v:?}"
        );
    }
    // Operator SQL from metadata still runs on an old psql.
    std::fs::write(
        stubs.path().join("psql.version"),
        "psql (PostgreSQL) 12.22\n",
    )
    .unwrap();
    run(&s, &st, "pg", "postgres.run_sql", serde_json::json!({}))
        .await
        .unwrap();
    // The new releases are accepted.
    for v in [
        "psql (PostgreSQL) 17.6\n",
        "psql (PostgreSQL) 16.10 (Ubuntu)\n",
        "psql (PostgreSQL) 15.14\n",
        "psql (PostgreSQL) 14.19\n",
        "psql (PostgreSQL) 13.22\n",
        "psql (PostgreSQL) 18.0\n",
        "psql (PostgreSQL) 19.1\n",
    ] {
        std::fs::write(stubs.path().join("psql.version"), v).unwrap();
        run(
            &s,
            &st,
            "pg",
            "postgres.run_sql",
            serde_json::json!({"sql": "select 1;"}),
        )
        .await
        .unwrap_or_else(|e| panic!("{v:?} should be accepted: {e}"));
    }
    restore_env(&old);
}

fn tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").ok()?;
    path.split(':')
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// End to end with a REAL psql against a minimal wire-protocol stub server (not Postgres).
#[tokio::test(flavor = "multi_thread")]
async fn real_psql_does_not_run_meta_commands_from_caller_sql() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let psql_dir = ["/opt/homebrew/opt/libpq/bin", "/usr/local/opt/libpq/bin"]
        .iter()
        .find(|d| Path::new(d).join("psql").is_file())
        .map(PathBuf::from)
        .or_else(|| tool("psql").and_then(|p| p.parent().map(PathBuf::from)));
    let (Some(psql_dir), Some(py)) = (psql_dir, tool("python3")) else {
        println!("SKIPPED: real psql or python3 not available");
        return;
    };
    let version = std::process::Command::new(psql_dir.join("psql"))
        .arg("--version")
        .output()
        .unwrap();
    let version = String::from_utf8_lossy(&version.stdout).to_string();
    let supported = version
        .split("(PostgreSQL)")
        .nth(1)
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.split('.').next()?.parse::<u32>().ok())
        .is_some_and(|m| m >= 18);
    if !supported {
        println!(
            "SKIPPED: local psql ({}) is not 18 or later",
            version.trim()
        );
        return;
    }
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_pg_server.py");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut server_proc = std::process::Command::new(py)
        .arg("-I")
        .arg(&fixture)
        .arg(port.to_string())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(800));

    let old = std::env::var("PATH").unwrap();
    std::env::set_var("PATH", format!("{}:{}", psql_dir.display(), old));
    std::env::set_var("VULTRINO_PASSWORD", MASTER);
    let (s, st) = server().await;
    st.store(&pg_cred("pg", port, true)).await.unwrap();

    let marker = tempdir().unwrap();
    for (i, sql) in ["select 1;\n", "select 1;\n"].iter().enumerate() {
        let r = run(
            &s,
            &st,
            "pg",
            "postgres.run_sql",
            serde_json::json!({"sql": sql}),
        )
        .await
        .unwrap();
        assert_eq!(r["exit_code"], 0, "plain SQL works (run {i}): {r}");
    }
    for (i, meta) in [
        "\\! touch {m}\n",
        "select 1; \\! touch {m}\n",
        "select 1;\nselect 2;\n\\! touch {m}\n",
        "\\copy (select 1) to program 'touch {m}'\n",
        "\\o |touch {m}\nselect 1;\n",
        "\\! printf %s \"$VULTRINO_PASSWORD\" > {m}\n",
    ]
    .iter()
    .enumerate()
    {
        let m = marker.path().join(format!("pwned-{i}"));
        let sql = meta.replace("{m}", m.to_str().unwrap());
        let r = run(
            &s,
            &st,
            "pg",
            "postgres.run_sql",
            serde_json::json!({"sql": sql}),
        )
        .await
        .unwrap();
        assert_ne!(r["exit_code"], 0, "meta-command must fail: {r}");
        assert!(!m.exists(), "meta-command {i} executed a shell command");
    }
    // Operator-authored metadata SQL still runs its meta-commands.
    let m = marker.path().join("operator");
    st.store(
        &pg_cred("pg-op", port, false)
            .with_metadata("run_sql.sql", format!("\\! touch {}\n", m.display())),
    )
    .await
    .unwrap();
    let r = run(&s, &st, "pg-op", "postgres.run_sql", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    assert!(m.exists(), "operator SQL keeps meta-commands");

    std::env::remove_var("VULTRINO_PASSWORD");
    std::env::set_var("PATH", old);
    let _ = server_proc.kill();
    let _ = server_proc.wait();
}
