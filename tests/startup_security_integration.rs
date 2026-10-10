//! Production-entrypoint negative controls for security-critical web config.

use std::process::Command;

fn minimal_config() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("vultrino.toml"), "").unwrap();
    dir
}

fn web_command(config: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vultrino"));
    command
        .arg("--config")
        .arg(config)
        .arg("web")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .env_remove("VULTRINO_WORKLOAD_ASSERTION_SECRET")
        .env_remove("VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE");
    command
}

#[test]
fn web_refuses_to_start_without_policy_hash_secret() {
    let dir = minimal_config();
    let config = dir.path().join("vultrino.toml");
    for policy_secret in [None, Some("   ")] {
        let mut command = web_command(&config);
        command.env_remove("VULTRINO_WORKLOAD_EXCHANGE_ENABLED");
        match policy_secret {
            Some(secret) => {
                command.env("VULTRINO_POLICY_HASH_SECRET", secret);
            }
            None => {
                command.env_remove("VULTRINO_POLICY_HASH_SECRET");
            }
        }
        let output = command.output().unwrap();

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("VULTRINO_POLICY_HASH_SECRET is required"),
            "unexpected startup error: {stderr}"
        );
    }
}

#[test]
fn enabled_exchange_refuses_to_start_without_valid_verifier() {
    let dir = minimal_config();
    let config = dir.path().join("vultrino.toml");
    let cases = [
        (None, None, "is not configured"),
        (Some("too-short"), None, "at least 32 bytes"),
        (
            None,
            Some(dir.path().join("missing-verifier")),
            "cannot be read",
        ),
    ];
    for (inline_secret, secret_file, expected_detail) in cases {
        let mut command = web_command(&config);
        command
            .env(
                "VULTRINO_POLICY_HASH_SECRET",
                "01234567890123456789012345678901",
            )
            .env("VULTRINO_WORKLOAD_EXCHANGE_ENABLED", "1");
        if let Some(secret) = inline_secret {
            command.env("VULTRINO_WORKLOAD_ASSERTION_SECRET", secret);
        }
        if let Some(path) = secret_file {
            command.env("VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE", path);
        }
        let output = command.output().unwrap();

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("requires a valid startup verifier")
                && stderr.contains(expected_detail),
            "unexpected startup error: {stderr}"
        );
    }
}

/// P3-FLOORS: `vultrino web` refuses to start when the vault holds a RateLimit
/// policy whose default action is not deny, and the error names the policy and
/// the fix; `vultrino policy deny-default <id>` then repairs it offline (the
/// default becomes deny, the rules are kept).
#[test]
fn web_refuses_to_start_with_a_stored_rate_limit_policy_that_does_not_default_deny() {
    use std::time::{Duration, Instant};
    use vultrino::policy::{Policy, PolicyAction, PolicyCondition};
    use vultrino::storage::{FileStorage, StorageBackend};

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.enc");
    let config = dir.path().join("vultrino.toml");
    std::fs::write(
        &config,
        format!(
            "[storage]\nbackend = \"file\"\n[storage.file]\npath = \"{}\"\n",
            vault.display()
        ),
    )
    .unwrap();
    let password = "startup-refusal-test-password";
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let storage = FileStorage::new(&vault, &secrecy::SecretString::from(password))
            .await
            .unwrap();
        let mut p = Policy::deny_all("legacy-rate", "cred-*").with_rule(
            PolicyCondition::And(vec![
                PolicyCondition::UrlMatch("https://api.example.com/v1/*".into()),
                PolicyCondition::RateLimit {
                    max: 5,
                    window_secs: 60,
                },
            ]),
            PolicyAction::Allow,
        );
        p.id = "legacy-rate-startup".to_string();
        p.default_action = PolicyAction::Allow;
        storage.store_policy(&p).await.unwrap();
    });

    let mut child = web_command(&config)
        .env("HOME", dir.path())
        .env("VULTRINO_PASSWORD", password)
        .env(
            "VULTRINO_POLICY_HASH_SECRET",
            "01234567890123456789012345678901",
        )
        .env("VULTRINO_ADMIN_USERNAME", "admin")
        .env("VULTRINO_ADMIN_PASSWORD", "startup-refusal-admin-password")
        .env_remove("VULTRINO_WORKLOAD_EXCHANGE_ENABLED")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("`vultrino web` started (still running after 60s) with a refused stored policy in the vault");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!status.success(), "startup must fail: {stderr}");
    assert!(
        stderr.contains("legacy-rate-startup")
            && stderr.contains("vultrino policy deny-default legacy-rate-startup"),
        "the startup error names the policy and the fix: {stderr}"
    );

    let fix = Command::new(env!("CARGO_BIN_EXE_vultrino"))
        .arg("--config")
        .arg(&config)
        .args(["policy", "deny-default", "legacy-rate-startup"])
        .env("HOME", dir.path())
        .env("VULTRINO_PASSWORD", password)
        .output()
        .unwrap();
    assert!(
        fix.status.success(),
        "deny-default failed: {}",
        String::from_utf8_lossy(&fix.stderr)
    );
    rt.block_on(async {
        let storage = FileStorage::new(&vault, &secrecy::SecretString::from(password))
            .await
            .unwrap();
        let p = storage
            .get_policy("legacy-rate-startup")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.default_action, PolicyAction::Deny);
        assert_eq!(p.rules.len(), 1, "the fix keeps the rules");
        assert!(p.stored_load_refusal().is_none());
    });
}

/// Wave-1 close-out: `vultrino serve --mcp` is the second start path that loads stored
/// policies, and it refuses a stored RateLimit policy with a non-deny default the same
/// way `vultrino web` does (a refused set never starts a process with a weaker set).
#[test]
fn serve_mcp_refuses_to_start_with_a_stored_rate_limit_policy_that_does_not_default_deny() {
    use vultrino::policy::{Policy, PolicyAction, PolicyCondition};
    use vultrino::storage::{FileStorage, StorageBackend};

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.enc");
    let config = dir.path().join("vultrino.toml");
    std::fs::write(
        &config,
        format!(
            "[storage]\nbackend = \"file\"\n[storage.file]\npath = \"{}\"\n",
            vault.display()
        ),
    )
    .unwrap();
    let password = "startup-refusal-mcp-test-password";
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let storage = FileStorage::new(&vault, &secrecy::SecretString::from(password))
            .await
            .unwrap();
        let mut p = Policy::deny_all("legacy-rate-mcp", "cred-*").with_rule(
            PolicyCondition::And(vec![
                PolicyCondition::UrlMatch("https://api.example.com/v1/*".into()),
                PolicyCondition::RateLimit {
                    max: 5,
                    window_secs: 60,
                },
            ]),
            PolicyAction::Allow,
        );
        p.id = "legacy-rate-mcp-id".to_string();
        p.default_action = PolicyAction::Allow;
        storage.store_policy(&p).await.unwrap();
    });

    // stdin is closed: a process that did start would read EOF and exit cleanly, so a
    // non-zero exit naming the policy can only be the startup refusal.
    let output = Command::new(env!("CARGO_BIN_EXE_vultrino"))
        .arg("--config")
        .arg(&config)
        .args(["serve", "--mcp"])
        .env("HOME", dir.path())
        .env("VULTRINO_PASSWORD", password)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "startup must fail: {stderr}");
    assert!(
        stderr.contains("legacy-rate-mcp-id")
            && stderr.contains("vultrino policy deny-default legacy-rate-mcp-id"),
        "the startup error names the policy and the fix: {stderr}"
    );
}
