//! Web UI for Vultrino administration
//!
//! Provides a server-side rendered web interface for managing:
//! - Credentials
//! - Roles and API keys
//! - Audit logs and statistics
//!
//! Also provides a JSON API for CLI and external applications using API key auth.

mod api;
mod auth;
mod llm_proxy;
mod mcp_http;
mod routes;
mod server;
mod templates;
mod workload_exchange;

pub use auth::{AdminAuth, WebSession};
pub use server::{WebConfig, WebServer};

/// Opaque, validated security inputs for the production web server.
///
/// The workload verifier is deliberately carried from validation into
/// `AppState`; reconstructing it later would reopen a check/use window around
/// the environment or verifier file.
pub struct WebSecurityStartup {
    vultrino_config: crate::config::Config,
    pub(crate) workload_verifier: workload_exchange::WorkloadVerifier,
}

impl WebSecurityStartup {
    /// Borrow the validated configuration while assembling production state.
    pub fn config(&self) -> &crate::config::Config {
        &self.vultrino_config
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::config::Config,
        workload_exchange::WorkloadVerifier,
    ) {
        (self.vultrino_config, self.workload_verifier)
    }
}

/// Validate security-critical environment before the production web entrypoint
/// touches the vault, starts background workers, or binds a listener.
pub fn validate_security_startup(
    config: crate::config::Config,
) -> Result<WebSecurityStartup, String> {
    if config
        .policy_hash_secret
        .as_deref()
        .map(str::trim)
        .filter(|secret| !secret.is_empty())
        .is_none()
    {
        return Err(
            "VULTRINO_POLICY_HASH_SECRET is required for `vultrino web`; refusing to start with the policy-drift oracle disabled"
                .to_string(),
        );
    }

    let workload_verifier = workload_exchange::WorkloadVerifier::from_env();
    workload_verifier.startup_result().map_err(|message| {
        format!(
            "VULTRINO_WORKLOAD_EXCHANGE_ENABLED requires a valid startup verifier: {message}"
        )
    })?;

    Ok(WebSecurityStartup {
        vultrino_config: config,
        workload_verifier,
    })
}

#[cfg(test)]
mod security_startup_tests {
    use super::*;

    #[test]
    fn policy_hash_secret_is_a_web_startup_precondition() {
        let config = crate::config::Config::default();
        let error = match validate_security_startup(config) {
            Err(error) => error,
            Ok(_) => panic!("missing policy-hash secret unexpectedly passed validation"),
        };
        assert!(error.contains("VULTRINO_POLICY_HASH_SECRET is required"));
    }
}
