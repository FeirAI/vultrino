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
