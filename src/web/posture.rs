//! Live posture report (`GET /api/v1/posture`).
//!
//! The deploy-time posture verifier asks the RUNNING process what it enforces instead of
//! trusting the files it was started from. This module builds the report; the route handler in
//! `api.rs` only adds the operator-key gate. The report carries booleans, counts, identifiers and
//! build provenance only: never a key, a secret, a policy rule or a credential.

use serde_json::{json, Value};

use crate::config::{Config, TenantMode};
use crate::policy::Policy;

/// Schema version of the report; the verifier refuses a version it does not know.
pub const POSTURE_SCHEMA: u32 = 1;

/// Build the posture report for this process.
///
/// `default_deny` is the policy engine's live default (set from `[enforcement] default_action`),
/// `policies` the policies the engine enforces right now (config plus stored).
pub(crate) fn build_posture(config: &Config, default_deny: bool, policies: &[Policy]) -> Value {
    // Same condition the server uses to build its Averin client.
    let averin_client_present = matches!(
        crate::averin::AverinClient::new(config.averin.clone()),
        Ok(Some(_))
    );
    let key = config.govder.as_ref().map(|g| g.approval_key_posture());
    let mut observe_tenants: Vec<&str> = config
        .tenants
        .iter()
        .filter(|(_, m)| **m == TenantMode::Observe)
        .map(|(t, _)| t.as_str())
        .collect();
    observe_tenants.sort_unstable();
    let mut fail_open_rate_limits: Vec<&str> = policies
        .iter()
        .filter(|p| p.rate_limit_default_not_deny())
        .map(|p| p.id.as_str())
        .collect();
    fail_open_rate_limits.sort_unstable();

    json!({
        "schema": POSTURE_SCHEMA,
        "plane": "vultrino",
        "build": {
            "version": env!("CARGO_PKG_VERSION"),
            "rustc": env!("VULTRINO_RUSTC_VERSION"),
            "git_sha": env!("VULTRINO_BUILD_SHA"),
            "git_dirty": env!("VULTRINO_BUILD_DIRTY") == "true",
        },
        "approvals": {
            "enabled": config.approval.enabled,
            "enforce_separation_of_duty": config.approval.enforce_separation_of_duty,
        },
        "approver_identity": {
            "govder_configured": key.is_some(),
            "key_configured": key.is_some_and(|k| k.key_configured),
            "key_distinct_from_govder_key": key.is_some_and(|k| k.key_distinct),
            "shared_key_escape": key.is_some_and(|k| k.shared_key_escape),
        },
        "engine": {
            "default_deny": default_deny,
            "tenants_in_observe_mode": observe_tenants,
            "unlisted_tenant_mode": match config.tenant_mode(None) {
                TenantMode::Enforce => "enforce",
                TenantMode::Observe => "observe",
            },
        },
        "identity": {
            "inbound_header_configured": config.identity.is_some(),
            "signature_key_configured": config
                .identity
                .as_ref()
                .is_some_and(|i| i.verification_key.is_some()),
        },
        "egress": {
            // The URL is never reported (it can carry proxy credentials).
            "upstream_proxy_configured": crate::plugins::upstream_proxy_configured(),
            "plugin_ambient_proxy_honoured": false,
            // The CA is trusted for every https target of the guarded client while the proxy
            // is set; the path is never reported.
            "upstream_proxy_ca_configured": crate::plugins::upstream_proxy_ca_configured(),
        },
        "averin": {
            "enabled": config.averin.enabled,
            "mode": match config.averin.mode {
                crate::averin::AverinMode::Observe => "observe",
                crate::averin::AverinMode::RequireEvidence => "require_evidence",
            },
            "d8_complete_evidence": config.averin.d8_complete_evidence,
            // VUL-38: the configured floor; it only takes effect with d8_complete_evidence on.
            "d8_evidence_floor": config.averin.d8_evidence_floor.as_str(),
            // Effective only with a live client, enabled and d8_complete_evidence on.
            "d8_evidence_floor_effective": if averin_client_present
                && config.averin.d8_complete_evidence
            {
                config.averin.d8_evidence_floor.as_str()
            } else {
                "human_floor"
            },
        },
        "policies": {
            "total": policies.len(),
            "rate_limit_default_not_deny": fail_open_rate_limits,
        },
        "vault": {
            "format_version": crate::storage::STORAGE_VERSION,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyAction, PolicyCondition, PolicyRule};

    fn rate_limited(id: &str, default_action: PolicyAction) -> Policy {
        Policy {
            id: id.to_string(),
            name: id.to_string(),
            credential_pattern: "*".to_string(),
            principal_pattern: None,
            rules: vec![PolicyRule {
                condition: PolicyCondition::RateLimit {
                    max: 5,
                    window_secs: 60,
                },
                action: PolicyAction::Allow,
            }],
            default_action,
            kill: false,
        }
    }

    #[test]
    fn report_flags_a_stored_rate_limit_policy_whose_default_is_not_deny() {
        let policies = vec![
            rate_limited("rl-open", PolicyAction::Allow),
            rate_limited("rl-closed", PolicyAction::Deny),
        ];
        let v = build_posture(&Config::default(), true, &policies);
        assert_eq!(
            v["policies"]["rate_limit_default_not_deny"],
            json!(["rl-open"])
        );
        assert_eq!(v["policies"]["total"], 2);
    }

    #[test]
    fn report_names_the_vul38_evidence_floor_mode() {
        let v = build_posture(&Config::default(), true, &[]);
        assert_eq!(v["averin"]["d8_evidence_floor"], "money_and_irreversible");
        // With two-phase evidence off the floor setting has no effect: every non-reversible
        // action keeps the committed-evidence floor, and the report says so.
        assert_eq!(v["averin"]["d8_evidence_floor_effective"], "human_floor");
        let cfg = Config::parse(
            "[averin]\nenabled = true\nbase_url = \"http://127.0.0.1:1\"\n\
             d8_complete_evidence = true\nd8_evidence_floor = \"human_floor\"\n",
        )
        .unwrap();
        let v = build_posture(&cfg, true, &[]);
        assert_eq!(v["averin"]["d8_evidence_floor"], "human_floor");
        assert_eq!(v["averin"]["d8_evidence_floor_effective"], "human_floor");
        let cfg = Config::parse(
            "[averin]\nenabled = true\nbase_url = \"http://127.0.0.1:1\"\n\
             resource_id = \"r\"\nd8_complete_evidence = true\n",
        )
        .unwrap();
        let v = build_posture(&cfg, true, &[]);
        assert_eq!(
            v["averin"]["d8_evidence_floor_effective"],
            "money_and_irreversible"
        );
        // No client can be built (resource_id empty, or averin disabled): there is no evidence
        // path, so the configured floor is not in force and the report says human_floor.
        for toml in [
            "[averin]\nenabled = true\nbase_url = \"http://127.0.0.1:1\"\n\
             d8_complete_evidence = true\n",
            "[averin]\nenabled = false\nbase_url = \"http://127.0.0.1:1\"\n\
             resource_id = \"r\"\nd8_complete_evidence = true\n",
        ] {
            let v = build_posture(&Config::parse(toml).unwrap(), true, &[]);
            assert_eq!(v["averin"]["d8_evidence_floor_effective"], "human_floor");
        }
    }

    #[test]
    fn report_reflects_the_live_engine_default_and_never_claims_deny_it_was_not_given() {
        let v = build_posture(&Config::default(), false, &[]);
        assert_eq!(v["engine"]["default_deny"], false);
        let v = build_posture(&Config::default(), true, &[]);
        assert_eq!(v["engine"]["default_deny"], true);
    }

    #[test]
    fn report_lists_observe_tenants_and_reports_unlisted_as_enforce() {
        let mut cfg = Config::default();
        cfg.tenants.insert("b".into(), TenantMode::Observe);
        cfg.tenants.insert("a".into(), TenantMode::Observe);
        cfg.tenants.insert("c".into(), TenantMode::Enforce);
        let v = build_posture(&cfg, true, &[]);
        assert_eq!(v["engine"]["tenants_in_observe_mode"], json!(["a", "b"]));
        assert_eq!(v["engine"]["unlisted_tenant_mode"], "enforce");
    }

    #[test]
    fn report_carries_the_sod_flag_and_the_vault_format_and_no_secret_material() {
        let v = build_posture(&Config::default(), true, &[]);
        assert_eq!(v["approvals"]["enforce_separation_of_duty"], false);
        let mut cfg = Config::default();
        cfg.approval.enforce_separation_of_duty = true;
        let v = build_posture(&cfg, true, &[]);
        assert_eq!(v["approvals"]["enforce_separation_of_duty"], true);
        assert_eq!(
            v["vault"]["format_version"],
            crate::storage::STORAGE_VERSION
        );
        assert_eq!(v["approver_identity"]["govder_configured"], false);
        assert_eq!(
            v["approver_identity"]["key_distinct_from_govder_key"],
            false
        );
        let text = v.to_string();
        assert!(!text.contains("secret"), "no secret-named field: {text}");
    }

    fn govder(shared: &str, approval: Option<&str>, escape: bool) -> crate::govder::GovderConfig {
        crate::govder::GovderConfig {
            base_url: "http://govder.invalid".to_string(),
            assertion_secret: shared.to_string(),
            approval_assertion_secret: approval.map(str::to_string),
            allow_shared_approval_key: escape,
            assertion_ttl: std::time::Duration::from_secs(90),
            http_timeout: std::time::Duration::from_secs(30),
        }
    }

    #[test]
    fn report_says_the_approver_key_is_distinct_only_when_it_differs_from_the_govder_key() {
        let cases = [
            // (shared F, approver M, escape, configured, distinct, escape)
            ("f-key", Some("m-key"), false, true, true, false),
            ("f-key", Some("f-key"), false, true, false, false),
            ("f-key ", Some("f-key"), false, true, false, false), // F padded: still F
            ("f-key", None, false, false, false, false),
            ("f-key", None, true, false, false, true),
        ];
        for (f, m, esc, configured, distinct, escape) in cases {
            let cfg = Config {
                govder: Some(govder(f, m, esc)),
                ..Config::default()
            };
            let v = build_posture(&cfg, true, &[]);
            let a = &v["approver_identity"];
            assert_eq!(a["govder_configured"], true);
            assert_eq!(a["key_configured"], configured, "{f}/{m:?}");
            assert_eq!(a["key_distinct_from_govder_key"], distinct, "{f}/{m:?}");
            assert_eq!(a["shared_key_escape"], escape, "{f}/{m:?}");
        }
    }
}
