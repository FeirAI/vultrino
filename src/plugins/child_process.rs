//! The one place a child process is built.
//!
//! Every program the proxy starts (psql, pg_dump, sshpass, ssh, rsync, openssl, git, tar,
//! rustup, cargo) must be created through [`tokio_command`] or [`std_command`]. A bare
//! `Command::new` would hand the child the proxy's whole environment, and that environment
//! carries the vault master password (`VULTRINO_PASSWORD`, or the path in
//! `VULTRINO_PASSWORD_FILE`) and every other secret the proxy was started with (identity,
//! workload-assertion and policy-hash secrets, govder and averin secrets). A source-scanning
//! test (`tests/no_raw_child_process.rs`) fails if `Command::new` appears in `src/` anywhere
//! outside this file.
//!
//! The helper clears the inherited environment and copies back only an explicit allowlist,
//! chosen per [`ChildEnv`] profile. Nothing is inherited implicitly. A caller adds what its
//! program needs on top with `.env(..)` (for example `PGPASSWORD` for psql), exactly as before.
//!
//! # Allowlist
//!
//! Baseline, every profile: `PATH` (to find the program), `LANG`, `LC_*`, `TZ`, `TMPDIR`.
//!
//! | Profile | Adds | Why |
//! |---|---|---|
//! | [`ChildEnv::Minimal`] | nothing | openssl, tar: pure filters, no home directory needed |
//! | [`ChildEnv::Postgres`] | `HOME`, `PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`, `PGSSLCRL` | libpq reads `~/.postgresql/root.crt` for `sslmode=verify-*`; the four `PGSSL*` names are file paths an operator may have set for the proxy, not secrets. `PGPASSWORD`, `PGSSLMODE` and `PGCONNECT_TIMEOUT` are set by the plugin per call. `PGOPTIONS`, `PGSERVICE`, `PGPASSFILE` and the other `PG*` names are not passed. |
//! | [`ChildEnv::Ssh`] | `HOME` | ssh reads `~/.ssh/known_hosts` and `~/.ssh/config`. `SSHPASS` is set by the plugin. `SSH_AUTH_SOCK` is NOT passed: the plugin authenticates with the credential's password through sshpass and nothing in the code relies on an agent. |
//! | [`ChildEnv::Installer`] | `HOME`, `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `SSH_AUTH_SOCK`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (and lowercase forms), `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CARGO_HTTP_CAINFO`, `GIT_SSL_CAINFO` | git, tar, rustup and cargo need a toolchain location and, behind a Socket Firewall or corporate proxy, the proxy and CA variables. `SSH_AUTH_SOCK` stays because the installer accepts `git@host:...` sources, which authenticate through the operator's agent. `GIT_*` code-execution hooks such as `GIT_SSH_COMMAND` and `GIT_CONFIG_*` are not passed. |
//!
//! A name starting with `VULTRINO_`, `GOVDER_`, `AVERIN_`, `LERIA_`, `FEIR_` or `ORGPACK_` is
//! never passed, whatever the profile says (a second, independent check, in case an allowlist
//! entry is ever widened by mistake).

use std::ffi::{OsStr, OsString};

/// Which environment a child process gets. See the module documentation for the lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildEnv {
    Minimal,
    Postgres,
    Ssh,
    Installer,
}

const BASELINE: &[&str] = &["PATH", "LANG", "TZ", "TMPDIR"];

const POSTGRES_EXTRA: &[&str] = &["HOME", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGSSLCRL"];

const SSH_EXTRA: &[&str] = &["HOME"];

const INSTALLER_EXTRA: &[&str] = &[
    "HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SSH_AUTH_SOCK",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CARGO_HTTP_CAINFO",
    "GIT_SSL_CAINFO",
];

/// Variable-name prefixes that never reach a child, whatever the profile.
const NEVER_PREFIXES: &[&str] = &[
    "VULTRINO_",
    "GOVDER_",
    "AVERIN_",
    "LERIA_",
    "FEIR_",
    "ORGPACK_",
];

impl ChildEnv {
    fn extra(self) -> &'static [&'static str] {
        match self {
            ChildEnv::Minimal => &[],
            ChildEnv::Postgres => POSTGRES_EXTRA,
            ChildEnv::Ssh => SSH_EXTRA,
            ChildEnv::Installer => INSTALLER_EXTRA,
        }
    }

    fn allows(self, name: &str) -> bool {
        if NEVER_PREFIXES.iter().any(|p| name.starts_with(p)) {
            return false;
        }
        BASELINE.contains(&name) || name.starts_with("LC_") || self.extra().contains(&name)
    }
}

/// The allowlisted subset of `vars` for a profile. Pure, so the policy is testable without
/// touching the real environment.
pub(crate) fn filter_env<I>(profile: ChildEnv, vars: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter()
        .filter(|(k, _)| k.to_str().is_some_and(|k| profile.allows(k)))
        .collect()
}

/// A `tokio::process::Command` for `program` with a cleared environment plus the profile's
/// allowlist.
pub(crate) fn tokio_command(
    program: impl AsRef<OsStr>,
    profile: ChildEnv,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    cmd.env_clear();
    cmd.envs(filter_env(profile, std::env::vars_os()));
    cmd
}

/// A `std::process::Command` for `program` with a cleared environment plus the profile's
/// allowlist.
// Only the unit tests of google_sa build a blocking Command today; keep the helper for any
// future blocking spawn so it cannot be done raw.
#[allow(dead_code)]
pub(crate) fn std_command(program: impl AsRef<OsStr>, profile: ChildEnv) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    cmd.env_clear();
    cmd.envs(filter_env(profile, std::env::vars_os()));
    cmd
}

/// Serialises unit tests that change the process environment (PATH, planted secrets).
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_env() -> Vec<(OsString, OsString)> {
        [
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TZ",
            "TMPDIR",
            "VULTRINO_PASSWORD",
            "VULTRINO_PASSWORD_FILE",
            "VULTRINO_NEW_PASSWORD",
            "VULTRINO_IDENTITY_SECRET",
            "GOVDER_SECRET",
            "AVERIN_TOKEN",
            "LERIA_KEY",
            "FEIR_X",
            "ORGPACK_Y",
            "PGPASSWORD",
            "PGOPTIONS",
            "PGSSLROOTCERT",
            "SSH_AUTH_SOCK",
            "HTTPS_PROXY",
            "CARGO_HOME",
            "GIT_SSH_COMMAND",
            "AWS_SECRET_ACCESS_KEY",
            "SOMETHING_ELSE",
        ]
        .iter()
        .map(|n| (OsString::from(n), OsString::from("v")))
        .collect()
    }

    fn names(profile: ChildEnv) -> Vec<String> {
        let mut v: Vec<String> = filter_env(profile, fake_env())
            .into_iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn no_profile_passes_an_internal_secret_or_an_unlisted_name() {
        for p in [
            ChildEnv::Minimal,
            ChildEnv::Postgres,
            ChildEnv::Ssh,
            ChildEnv::Installer,
        ] {
            for n in names(p) {
                assert!(
                    !NEVER_PREFIXES.iter().any(|x| n.starts_with(x)),
                    "{p:?} leaks {n}"
                );
                for bad in [
                    "PGPASSWORD",
                    "PGOPTIONS",
                    "GIT_SSH_COMMAND",
                    "AWS_SECRET_ACCESS_KEY",
                    "SOMETHING_ELSE",
                ] {
                    assert_ne!(n, bad, "{p:?} passes {bad}");
                }
            }
        }
    }

    #[test]
    fn profiles_pass_exactly_what_they_document() {
        let base = ["LANG", "LC_ALL", "LC_CTYPE", "PATH", "TMPDIR", "TZ"];
        assert_eq!(names(ChildEnv::Minimal), base);
        let mut pg: Vec<&str> = base.to_vec();
        pg.extend(["HOME", "PGSSLROOTCERT"]);
        pg.sort();
        assert_eq!(names(ChildEnv::Postgres), pg);
        let mut ssh: Vec<&str> = base.to_vec();
        ssh.push("HOME");
        ssh.sort();
        assert_eq!(names(ChildEnv::Ssh), ssh);
        let n = names(ChildEnv::Installer);
        for want in ["HOME", "CARGO_HOME", "HTTPS_PROXY", "SSH_AUTH_SOCK", "PATH"] {
            assert!(n.iter().any(|x| x == want), "installer lacks {want}");
        }
        assert!(!names(ChildEnv::Ssh).contains(&"SSH_AUTH_SOCK".to_string()));
    }
}
