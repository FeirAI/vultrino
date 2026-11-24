//! SSH plugin input validation, end to end through the real `execute_gated`.
//!
//! The programs sshpass, rsync and ssh are STUBS that only RECORD their argv, one argument per
//! line, to `$STUB_DIR/<name>.argv`; they never run anything they are given. Every refusal test
//! asserts that no stub recorded an invocation, i.e. no child process was started. Only dummy
//! values appear here.

// LOCK serialises process-environment mutation across awaits on purpose.
#![allow(clippy::await_holding_lock)]

use std::path::Path;
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

fn write_stubs(dir: &Path) {
    let script = r#"#!/bin/sh
NAME="$(basename "$0")"
D="$(dirname "$0")"
case "$1" in
  -V|--version) echo "$NAME (stub) 0.0"; exit 0;;
esac
for a in "$@"; do printf '%s\n' "$a"; done > "$D/$NAME.argv"
exit 0
"#;
    for name in ["sshpass", "rsync", "ssh"] {
        let p = dir.join(name);
        std::fs::write(&p, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

fn argv(stubs: &Path, prog: &str) -> Option<Vec<String>> {
    std::fs::read_to_string(stubs.join(format!("{prog}.argv")))
        .ok()
        .map(|s| s.lines().map(String::from).collect())
}

fn clear_records(stubs: &Path) {
    for n in ["sshpass", "rsync", "ssh"] {
        let _ = std::fs::remove_file(stubs.join(format!("{n}.argv")));
    }
}

fn no_process_started(stubs: &Path) -> bool {
    ["sshpass", "rsync", "ssh"]
        .iter()
        .all(|n| !stubs.join(format!("{n}.argv")).exists())
}

async fn server() -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let pw = SecretString::from("generated-test-password-ssh-validation");
    let storage: Arc<dyn StorageBackend> = Arc::new(FileStorage::new(&path, &pw).await.unwrap());
    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Deny;
    config.policies = vec![Policy::allow_all("base", "*")];
    let s = VultrinoServer::new(
        config,
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

fn cred(alias: &str, host: &str, port: u16, user: &str, meta: &[(&str, &str)]) -> Credential {
    let mut c = Credential::new(
        alias.into(),
        CredentialData::SshPassword {
            host: host.into(),
            port,
            user: user.into(),
            password: Secret::new("ssh-dummy-password-1234"),
        },
    )
    .with_metadata("deploy.allow_override", "true")
    .with_metadata("run.allow_override", "true");
    for (k, v) in meta {
        c = c.with_metadata(*k, *v);
    }
    c
}

const BASE: &[(&str, &str)] = &[
    ("deploy.source_dir", "/src/"),
    ("deploy.dest_dir", "/srv/app/"),
    ("run.commands", "[\"uptime\"]"),
];

struct Env {
    stubs: tempfile::TempDir,
    old_path: String,
}

impl Env {
    fn new() -> Self {
        let stubs = tempdir().unwrap();
        write_stubs(stubs.path());
        let old_path = std::env::var("PATH").unwrap();
        std::env::set_var("PATH", format!("{}:{}", stubs.path().display(), old_path));
        Env { stubs, old_path }
    }
    fn dir(&self) -> &Path {
        self.stubs.path()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        std::env::set_var("PATH", &self.old_path);
    }
}

async fn expect_refused(
    e: &Env,
    s: &VultrinoServer,
    st: &Arc<dyn StorageBackend>,
    c: Credential,
    action: &str,
    params: serde_json::Value,
    field: &str,
) {
    let alias = c.alias.clone();
    st.store(&c).await.unwrap();
    clear_records(e.dir());
    let err = run(s, st, &alias, action, params.clone())
        .await
        .expect_err(&format!("{field}: must be refused"));
    assert!(err.contains(field), "error should name {field}: {err}");
    assert!(
        !err.contains("ssh-dummy-password-1234"),
        "error leaked the secret"
    );
    assert!(
        no_process_started(e.dir()),
        "{field}: a child process was started for {params}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_deploy_and_run_record_exact_argv() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = Env::new();
    let (s, st) = server().await;

    let mut meta: Vec<(&str, &str)> = BASE.to_vec();
    meta.push(("deploy.excludes", "[\".git\",\"node_modules\"]"));
    meta.push(("ssh.strict_host_key_checking", "yes"));
    st.store(&cred("a", "deploy.example.com", 2222, "deploy", &meta))
        .await
        .unwrap();

    clear_records(e.dir());
    run(
        &s,
        &st,
        "a",
        "ssh.deploy",
        serde_json::json!({"dry_run": true}),
    )
    .await
    .unwrap();
    assert_eq!(
        argv(e.dir(), "sshpass").unwrap(),
        vec![
            "-e",
            "rsync",
            "-avz",
            "--exclude=.git",
            "--exclude=node_modules",
            "--dry-run",
            "-e",
            "ssh -p 2222 -o StrictHostKeyChecking=yes -o ConnectTimeout=30",
            "--",
            "/src/",
            "deploy@deploy.example.com:/srv/app/",
        ]
    );

    clear_records(e.dir());
    run(&s, &st, "a", "ssh.run", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(
        argv(e.dir(), "sshpass").unwrap(),
        vec![
            "-e",
            "ssh",
            "-p",
            "2222",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=30",
            "--",
            "deploy@deploy.example.com",
            "uptime",
        ]
    );

    // Caller flags and the default host-key value; IPv6 host is bracketed for rsync.
    st.store(&cred("v6", "2001:db8::1", 22, "u", BASE))
        .await
        .unwrap();
    clear_records(e.dir());
    run(
        &s,
        &st,
        "v6",
        "ssh.deploy",
        serde_json::json!({"flags": "-rt --delete --exclude=*.tmp", "dest_dir": "rel/dir"}),
    )
    .await
    .unwrap();
    assert_eq!(
        argv(e.dir(), "sshpass").unwrap(),
        vec![
            "-e",
            "rsync",
            "-rt",
            "--delete",
            "--exclude=*.tmp",
            "-e",
            "ssh -p 22 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30",
            "--",
            "/src/",
            "u@[2001:db8::1]:rel/dir",
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_metadata_is_refused_before_any_process() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = Env::new();
    let (s, st) = server().await;
    let empty = serde_json::json!({});
    let mut n = 0;
    let mut alias = || {
        n += 1;
        format!("m{n}")
    };

    // Host-key value, from metadata, for both actions.
    for bad in [
        "no -o ProxyCommand=x",
        "yes\nx",
        "'yes'",
        "Yes",
        "",
        "accept_new",
    ] {
        let mut m = BASE.to_vec();
        m.push(("ssh.strict_host_key_checking", bad));
        for action in ["ssh.deploy", "ssh.run"] {
            expect_refused(
                &e,
                &s,
                &st,
                cred(&alias(), "h.example", 22, "u", &m),
                action,
                empty.clone(),
                "ssh.strict_host_key_checking",
            )
            .await;
        }
    }

    // Credential fields.
    let long_host = format!("{}.com", "a".repeat(250));
    let long_user = "a".repeat(65);
    for action in ["ssh.deploy", "ssh.run"] {
        for h in [
            "-oProxyCommand=x",
            ".x",
            "a b",
            "a;b",
            "a'b",
            "a\tb",
            &long_host,
        ] {
            expect_refused(
                &e,
                &s,
                &st,
                cred(&alias(), h, 22, "u", BASE),
                action,
                empty.clone(),
                "host",
            )
            .await;
        }
        for u in ["-l", "a b", "a@b", "a;b", "a\nb", &long_user] {
            expect_refused(
                &e,
                &s,
                &st,
                cred(&alias(), "h.example", 22, u, BASE),
                action,
                empty.clone(),
                "user",
            )
            .await;
        }
        expect_refused(
            &e,
            &s,
            &st,
            cred(&alias(), "h.example", 0, "u", BASE),
            action,
            empty.clone(),
            "port",
        )
        .await;
    }

    // Deploy metadata: flags, dest_dir, source_dir, excludes.
    for f in [
        "-avz -e sh",
        "-a --rsh=x",
        "--rsh=ssh",
        "-avze",
        "--files-from=/x",
        "-a\t--delete-excluded",
        "--exclude=",
        "--exclude=-x",
        "--ARCHIVE",
    ] {
        let mut m = BASE.to_vec();
        m.push(("deploy.flags", f));
        expect_refused(
            &e,
            &s,
            &st,
            cred(&alias(), "h.example", 22, "u", &m),
            "ssh.deploy",
            empty.clone(),
            "rsync flag",
        )
        .await;
    }
    for d in ["", "-x", "a\nb", "::mod", "~-"] {
        let m: Vec<(&str, &str)> = BASE
            .iter()
            .filter(|(k, _)| *k != "deploy.dest_dir")
            .copied()
            .chain([("deploy.dest_dir", d)])
            .collect();
        expect_refused(
            &e,
            &s,
            &st,
            cred(&alias(), "h.example", 22, "u", &m),
            "ssh.deploy",
            empty.clone(),
            "dest_dir",
        )
        .await;
    }
    for d in ["", "-x", "a\nb", "host:path", "rsync://h/m"] {
        let m: Vec<(&str, &str)> = BASE
            .iter()
            .filter(|(k, _)| *k != "deploy.source_dir")
            .copied()
            .chain([("deploy.source_dir", d)])
            .collect();
        expect_refused(
            &e,
            &s,
            &st,
            cred(&alias(), "h.example", 22, "u", &m),
            "ssh.deploy",
            empty.clone(),
            "source_dir",
        )
        .await;
    }
    for ex in ["[\"-x\"]", "[\"\"]", "[\"a\\nb\"]"] {
        let mut m = BASE.to_vec();
        m.push(("deploy.excludes", ex));
        expect_refused(
            &e,
            &s,
            &st,
            cred(&alias(), "h.example", 22, "u", &m),
            "ssh.deploy",
            empty.clone(),
            "exclude",
        )
        .await;
    }

    // Run metadata: a command starting with '-' would be read by local ssh as an option.
    for cmds in ["[\"-oProxyCommand=x\"]", "[\"\"]"] {
        let m: Vec<(&str, &str)> = vec![("run.commands", cmds)];
        expect_refused(
            &e,
            &s,
            &st,
            cred(&alias(), "h.example", 22, "u", &m),
            "ssh.run",
            empty.clone(),
            "commands[0]",
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_caller_parameters_are_refused_before_any_process() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = Env::new();
    let (s, st) = server().await;
    let mut n = 0;
    let mut alias = || {
        n += 1;
        format!("p{n}")
    };
    let mut good = || cred(&alias(), "h.example", 22, "u", BASE);

    for (k, v, field) in [
        ("flags", "-avz -e sh", "rsync flag"),
        ("flags", "--rsh=ssh", "rsync flag"),
        ("flags", "-avze", "rsync flag"),
        ("flags", "--exclude=-x", "pattern"),
        ("dest_dir", "-oFoo", "dest_dir"),
        ("dest_dir", "a\nb", "dest_dir"),
        ("dest_dir", "::module", "dest_dir"),
        ("dest_dir", "", "dest_dir"),
        ("source_dir", "--delete", "source_dir"),
        ("source_dir", "evil:/x", "source_dir"),
        ("source_dir", "a\nb", "source_dir"),
        ("source_dir", "", "source_dir"),
    ] {
        expect_refused(
            &e,
            &s,
            &st,
            good(),
            "ssh.deploy",
            serde_json::json!({ k: v }),
            field,
        )
        .await;
    }
    expect_refused(
        &e,
        &s,
        &st,
        good(),
        "ssh.deploy",
        serde_json::json!({"excludes": ["-x"]}),
        "exclude",
    )
    .await;
    for c in ["-oProxyCommand=x", ""] {
        expect_refused(
            &e,
            &s,
            &st,
            good(),
            "ssh.run",
            serde_json::json!({"commands": ["uptime", c]}),
            "commands[1]",
        )
        .await;
    }
}
