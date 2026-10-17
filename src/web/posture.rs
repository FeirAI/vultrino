//! Live posture report (`GET /api/v1/posture`).
//!
//! The deploy-time posture verifier asks the RUNNING process what it enforces instead of
//! trusting the files it was started from. This module builds the report; the route handler in
//! `api.rs` only adds the operator-key gate. The report carries booleans, counts, identifiers and
//! build provenance only: never a key, a secret, a policy rule or a credential.

use serde_json::{json, Value};

use crate::config::{Config, TenantMode};
use crate::policy::Policy;
use crate::web::workload_exchange::WorkloadVerifier;

/// Schema version of the report; the verifier refuses a version it does not know.
pub const POSTURE_SCHEMA: u32 = 1;

/// Build the posture report for this process.
///
/// `default_deny` is the policy engine's live default (set from `[enforcement] default_action`),
/// `policies` the policies the engine enforces right now (config plus stored).
pub(crate) fn build_posture(
    config: &Config,
    default_deny: bool,
    policies: &[Policy],
    workload: &WorkloadVerifier,
) -> Value {
    let secret_fingerprints = secret_fingerprints(config, workload);
    // Same condition the server uses to build its Averin client.
    let averin_client_present = matches!(
        crate::averin::AverinClient::new(config.averin.clone()),
        Ok(Some(_))
    );
    let averin_key_sent = config.averin.enabled
        && config
            .averin
            .api_key
            .as_deref()
            .and_then(|k| crate::secret_fp::fingerprint(k, REL_AVERIN_API_KEY))
            .is_some();
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
            // FEI-40 relationship I: the seal client is on and a non-empty key is set, the same
            // condition as the averin-api-key fingerprint (the key is read but never sent while
            // the client is off). feir-os's verifier reads this beside the fingerprint.
            "api_key_configured": averin_key_sent,
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
        // FEI-40: keyed fingerprints of the shared secrets this process holds, per relationship
        // (see crate::secret_fp). The verifier compares them with the other planes' to find a
        // misaligned pair at deploy time. Never a secret value.
        "secret_fingerprints": secret_fingerprints,
    })
}

/// Relationship names of the secret-alignment matrix this plane takes part in. They are the same
/// strings in every plane and in feir-os `deploy/posture/evaluate.jq`, and part of the fingerprinted
/// message.
const REL_OUTBOX_POLL: &str = "vultrino-outbox-poll"; // A: vultrino signs its meter feed; leria verifies
const REL_APPROVAL_PUSH: &str = "vultrino-approval-push"; // E: the same outbox secret signs approval pushes; govder verifies
const REL_TENANT_ASSERTION: &str = "tenant-assertion"; // F: the edge/broker-signed tenant assertion (vultrino signs its calls to govder with it)
const REL_AVERIN_API_KEY: &str = "averin-api-key"; // I: the project bearer vultrino sends to averin (averin accepts a list)
const REL_WORKLOAD_ASSERTION: &str = "workload-assertion"; // L: the secret feir-runtime-edge signs workload assertions with; vultrino verifies (a list, for rotation)
const REL_APPROVER_KEY: &str = "approver-key"; // M: the key that verifies the broker's signed approver decisions

/// The fingerprints of the secrets this process was configured with, per relationship. A
/// relationship with no configured secret is omitted (an unset secret has no fingerprint).
fn secret_fingerprints(config: &Config, workload: &WorkloadVerifier) -> Value {
    use crate::secret_fp::fingerprint;
    let mut out = serde_json::Map::new();
    let mut add = |rel: &str, secret: Option<&str>| {
        if let Some(fp) = secret.and_then(|s| fingerprint(s, rel)) {
            out.insert(rel.to_string(), json!([fp]));
        }
    };
    let outbox = config.outbox.hmac_secret.as_deref();
    add(REL_OUTBOX_POLL, outbox);
    // The push relationship exists only while push delivery is on and has somewhere to go: an
    // outbox that only serves GET /api/v1/events signs the feed (above) but sends no approval push.
    let pushing = config.outbox.enabled
        && config
            .outbox
            .url
            .as_deref()
            .is_some_and(|u| !u.trim().is_empty());
    add(REL_APPROVAL_PUSH, outbox.filter(|_| pushing));
    // Reported only while the seal client is on: AVERIN_API_KEY is read but never sent otherwise.
    add(
        REL_AVERIN_API_KEY,
        config
            .averin
            .api_key
            .as_deref()
            .filter(|_| config.averin.enabled),
    );
    if let Some(g) = config.govder.as_ref() {
        add(REL_TENANT_ASSERTION, Some(g.assertion_secret.as_str()));
        add(REL_APPROVER_KEY, g.approval_verification_secret());
    }
    // L: one fingerprint per verifier secret the exchange accepts (the same comma-split, trimmed list
    // it verifies with, so a rotation overlap reports both). Reported only while the exchange is
    // configured and valid: a disabled or invalid exchange verifies nothing.
    let workload_fps = workload.fingerprints(REL_WORKLOAD_ASSERTION);
    if !workload_fps.is_empty() {
        out.insert(REL_WORKLOAD_ASSERTION.to_string(), json!(workload_fps));
    }
    Value::Object(out)
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
        let v = build_posture(
            &Config::default(),
            true,
            &policies,
            &WorkloadVerifier::Disabled,
        );
        assert_eq!(
            v["policies"]["rate_limit_default_not_deny"],
            json!(["rl-open"])
        );
        assert_eq!(v["policies"]["total"], 2);
    }

    #[test]
    fn report_names_the_vul38_evidence_floor_mode() {
        let v = build_posture(&Config::default(), true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(v["averin"]["d8_evidence_floor"], "money_and_irreversible");
        // With two-phase evidence off the floor setting has no effect: every non-reversible
        // action keeps the committed-evidence floor, and the report says so.
        assert_eq!(v["averin"]["d8_evidence_floor_effective"], "human_floor");
        let cfg = Config::parse(
            "[averin]\nenabled = true\nbase_url = \"http://127.0.0.1:1\"\n\
             resource_id = \"r\"\nd8_complete_evidence = true\nd8_evidence_floor = \"human_floor\"\n",
        )
        .unwrap();
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(v["averin"]["d8_evidence_floor"], "human_floor");
        assert_eq!(v["averin"]["d8_evidence_floor_effective"], "human_floor");
        let cfg = Config::parse(
            "[averin]\nenabled = true\nbase_url = \"http://127.0.0.1:1\"\n\
             resource_id = \"r\"\nd8_complete_evidence = true\n",
        )
        .unwrap();
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(
            v["averin"]["d8_evidence_floor_effective"],
            "money_and_irreversible"
        );
        // No client can be built: there is no evidence path, so the configured floor is not in
        // force and the report says human_floor. An enabled block with an empty resource_id no
        // longer loads (FEI-33), so that case is built in code; a disabled block still loads.
        let mut empty_resource = Config::parse(
            "[averin]\nenabled = true\nbase_url = \"http://127.0.0.1:1\"\n\
             resource_id = \"r\"\nd8_complete_evidence = true\n",
        )
        .unwrap();
        empty_resource.averin.resource_id = String::new();
        let disabled = Config::parse(
            "[averin]\nenabled = false\nbase_url = \"http://127.0.0.1:1\"\n\
             resource_id = \"r\"\nd8_complete_evidence = true\n",
        )
        .unwrap();
        for cfg in [empty_resource, disabled] {
            let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
            assert_eq!(v["averin"]["d8_evidence_floor_effective"], "human_floor");
        }
    }

    #[test]
    fn report_reflects_the_live_engine_default_and_never_claims_deny_it_was_not_given() {
        let v = build_posture(&Config::default(), false, &[], &WorkloadVerifier::Disabled);
        assert_eq!(v["engine"]["default_deny"], false);
        let v = build_posture(&Config::default(), true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(v["engine"]["default_deny"], true);
    }

    #[test]
    fn report_lists_observe_tenants_and_reports_unlisted_as_enforce() {
        let mut cfg = Config::default();
        cfg.tenants.insert("b".into(), TenantMode::Observe);
        cfg.tenants.insert("a".into(), TenantMode::Observe);
        cfg.tenants.insert("c".into(), TenantMode::Enforce);
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(v["engine"]["tenants_in_observe_mode"], json!(["a", "b"]));
        assert_eq!(v["engine"]["unlisted_tenant_mode"], "enforce");
    }

    #[test]
    fn report_carries_the_sod_flag_and_the_vault_format_and_no_secret_material() {
        let v = build_posture(&Config::default(), true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(v["approvals"]["enforce_separation_of_duty"], false);
        let mut cfg = Config::default();
        cfg.approval.enforce_separation_of_duty = true;
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
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
        // The one field whose name says "secret" is the fingerprint map (FEI-40): keyed fingerprints,
        // never a value (the test below checks that with real secrets configured).
        let text = v.to_string().replace("secret_fingerprints", "");
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
            let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
            let a = &v["approver_identity"];
            assert_eq!(a["govder_configured"], true);
            assert_eq!(a["key_configured"], configured, "{f}/{m:?}");
            assert_eq!(a["key_distinct_from_govder_key"], distinct, "{f}/{m:?}");
            assert_eq!(a["shared_key_escape"], escape, "{f}/{m:?}");
        }
    }

    // ---- FEI-40: secret-alignment fingerprints --------------------------------------------------

    fn govder_cfg(m: Option<&str>) -> crate::govder::GovderConfig {
        crate::govder::GovderConfig {
            base_url: "http://govder.invalid".into(),
            assertion_secret: "assertion-F".into(),
            approval_assertion_secret: m.map(str::to_string),
            allow_shared_approval_key: false,
            assertion_ttl: std::time::Duration::from_secs(90),
            http_timeout: std::time::Duration::from_secs(1),
        }
    }

    /// The report carries one keyed fingerprint per relationship, from the values this process is
    /// configured with: the outbox secret for both its feed and its approval pushes (one secret, two
    /// relationships, so two different fingerprints), the tenant assertion secret it signs calls to
    /// govder with, and the approver key. No secret value appears in the report.
    #[test]
    fn report_carries_a_fingerprint_per_relationship_and_no_secret() {
        use crate::secret_fp::fingerprint;
        let mut cfg = Config::default();
        cfg.outbox.hmac_secret = Some("outbox-secret-A".into());
        cfg.outbox.enabled = true;
        cfg.outbox.url = Some("http://govder.invalid/webhooks/vultrino-approvals".into());
        cfg.govder = Some(govder_cfg(Some("approver-key-M")));
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        let fp = &v["secret_fingerprints"];
        assert_eq!(
            fp["vultrino-outbox-poll"],
            json!([fingerprint("outbox-secret-A", "vultrino-outbox-poll").unwrap()])
        );
        assert_eq!(
            fp["vultrino-approval-push"],
            json!([fingerprint("outbox-secret-A", "vultrino-approval-push").unwrap()])
        );
        assert_ne!(fp["vultrino-outbox-poll"], fp["vultrino-approval-push"]);
        assert_eq!(
            fp["tenant-assertion"],
            json!([fingerprint("assertion-F", "tenant-assertion").unwrap()])
        );
        assert_eq!(
            fp["approver-key"],
            json!([fingerprint("approver-key-M", "approver-key").unwrap()])
        );
        let text = v.to_string();
        for secret in ["outbox-secret-A", "assertion-F", "approver-key-M"] {
            assert!(!text.contains(secret), "the report carries {secret}");
        }
    }

    /// With push delivery off (or no URL), the outbox still signs the feed leria polls but sends no
    /// approval push, so only the feed relationship is reported.
    #[test]
    fn report_omits_the_push_relationship_when_the_outbox_does_not_push() {
        let mut cfg = Config::default();
        cfg.outbox.hmac_secret = Some("outbox-secret-A".into());
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert!(v["secret_fingerprints"]
            .get("vultrino-outbox-poll")
            .is_some());
        assert!(v["secret_fingerprints"]
            .get("vultrino-approval-push")
            .is_none());
        cfg.outbox.enabled = true; // enabled but no URL: still nowhere to push
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert!(v["secret_fingerprints"]
            .get("vultrino-approval-push")
            .is_none());
        cfg.outbox.url = Some("  ".into());
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert!(v["secret_fingerprints"]
            .get("vultrino-approval-push")
            .is_none());
    }

    /// FEI-40 relationship I: vultrino reports the averin key it sends, only while the seal client
    /// is enabled, and never the key.
    #[test]
    fn report_carries_the_averin_key_fingerprint_only_while_the_seal_client_is_on() {
        use crate::secret_fp::fingerprint;
        let mut cfg = Config::default();
        cfg.averin.api_key = Some("averin-project-bearer".into());
        cfg.averin.enabled = false;
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert!(v["secret_fingerprints"].get("averin-api-key").is_none());
        cfg.averin.enabled = true;
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(
            v["secret_fingerprints"]["averin-api-key"],
            json!([fingerprint("averin-project-bearer", "averin-api-key").unwrap()])
        );
        assert!(!v.to_string().contains("averin-project-bearer"));
        cfg.averin.api_key = None;
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert!(v["secret_fingerprints"].get("averin-api-key").is_none());
    }

    /// The posture `averin` object carries `api_key_configured` (feir-os averin_use_checks reads it
    /// for a keyed averin): true only with the seal client on and a non-empty key, the same
    /// condition as the fingerprint, and the key itself never appears.
    #[test]
    fn report_carries_averin_api_key_configured_with_the_fingerprint_condition() {
        let mut cfg = Config::default();
        let flag = |c: &Config| {
            build_posture(c, true, &[], &WorkloadVerifier::Disabled)["averin"]["api_key_configured"]
                .clone()
        };
        // Present as a boolean in every state, not omitted.
        assert_eq!(flag(&cfg), json!(false));
        cfg.averin.api_key = Some("averin-project-bearer".into());
        cfg.averin.enabled = false;
        assert_eq!(flag(&cfg), json!(false));
        cfg.averin.enabled = true;
        assert_eq!(flag(&cfg), json!(true));
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert!(!v.to_string().contains("averin-project-bearer"));
        cfg.averin.api_key = Some(String::new());
        assert_eq!(flag(&cfg), json!(false));
        cfg.averin.api_key = None;
        assert_eq!(flag(&cfg), json!(false));
    }

    /// An unset secret has no fingerprint (the relationship is absent), and an approver key that is
    /// not usable (equal to the shared key, so verified approvals are disabled) is not reported as
    /// held.
    #[test]
    fn report_omits_unset_secrets_and_an_unusable_approver_key() {
        let v = build_posture(&Config::default(), true, &[], &WorkloadVerifier::Disabled);
        assert_eq!(v["secret_fingerprints"], json!({}));
        let cfg = Config {
            govder: Some(govder_cfg(Some("assertion-F"))), // M equal to F: disabled
            ..Config::default()
        };
        let v = build_posture(&cfg, true, &[], &WorkloadVerifier::Disabled);
        assert!(v["secret_fingerprints"].get("approver-key").is_none());
        assert!(v["secret_fingerprints"].get("tenant-assertion").is_some());
    }

    /// FEI-40 relationship L: vultrino reports one fingerprint per verifier secret the workload
    /// exchange accepts (the comma-split, trimmed list it verifies with, so a rotation overlap
    /// reports both), only while the exchange is configured, and never a secret.
    #[test]
    fn report_carries_a_workload_assertion_fingerprint_per_verifier_secret() {
        use crate::secret_fp::fingerprint;
        use crate::web::workload_exchange::parse_verifier_secrets;
        let a = "workload-secret-0123456789abcdef0123";
        let b = "rotated-secret-0123456789abcdef01234";
        let rel = "workload-assertion";
        let listed = parse_verifier_secrets(&format!(" {a} , {b} ,")).unwrap();
        let verifier = WorkloadVerifier::Configured(std::sync::Arc::new(listed));
        let v = build_posture(&Config::default(), true, &[], &verifier);
        assert_eq!(
            v["secret_fingerprints"][rel],
            json!([fingerprint(a, rel).unwrap(), fingerprint(b, rel).unwrap()])
        );
        let text = v.to_string();
        assert!(!text.contains(a) && !text.contains(b));
        // Disabled, or enabled but invalid: the exchange verifies nothing, so nothing is reported.
        let v = build_posture(&Config::default(), true, &[], &WorkloadVerifier::Disabled);
        assert!(v["secret_fingerprints"].get(rel).is_none());
        let invalid = WorkloadVerifier::Invalid("workload assertion verifier is not configured");
        let v = build_posture(&Config::default(), true, &[], &invalid);
        assert!(v["secret_fingerprints"].get(rel).is_none());
    }
}
