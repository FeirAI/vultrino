//! VUL-05 red-first: the permit must refuse a payload that differs from the
//! request it was minted for. Written against the origin/main API.

use super::*;
use crate::formal_kernel::{digest_bytes, ExecutionBinding, ExecutionPermit, PermitError};

fn payload(params: serde_json::Value) -> ActionPayload {
    ActionPayload {
        credential: crate::Credential::new(
            "cred-a".to_string(),
            crate::CredentialData::ApiKey {
                key: crate::Secret::new("secret-key"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        ),
        plugin_name: "mock".to_string(),
        action_name: "echo".to_string(),
        params,
        context: RequestContext::new(),
        use_token_id: None,
        evidence_subject_id: None,
        approved_execution: false,
        evidence_action: "mock.echo".to_string(),
        evidence_required: false,
    }
}

#[test]
fn permit_binding_negative_params_changed_after_mint() {
    let minted = serde_json::json!({"url": "https://api.example.com/a"});
    let dispatched = serde_json::json!({"url": "https://other.example.net/b"});
    let p = payload(dispatched);
    // Mint exactly as prepare_execution does on origin/main.
    let binding = ExecutionBinding::new(
        format!("direct:{}", p.context.request_id),
        0,
        "",
        "",
        "cred-a",
        "mock.echo",
        digest_bytes(&serde_json::to_vec(&minted).unwrap()),
        digest_bytes(b"effective-direct/no-approval"),
    );
    let permit = ExecutionPermit::direct(binding.clone(), true, false).unwrap();
    let result = permit.authorize(&binding, p);
    assert!(
        matches!(result, Err(PermitError::BindingMismatch)),
        "a permit minted for one params value authorized a payload with different params"
    );
}

#[test]
fn admission_deny_cannot_reach_direct_mint() {
    // A real policy evaluation that denies (fail-closed engine, no policy).
    let engine = crate::policy::PolicyEngine::new();
    let decision = engine.evaluate_full(&crate::policy::EvalInput {
        credential_alias: "cred-a",
        url: None,
        method: None,
        action: Some("mock.echo"),
        principal: None,
        spend: None,
    });
    assert!(matches!(decision, crate::policy::PolicyDecision::Deny(_)));
    // Mint exactly as prepare_execution does on origin/main: the kernel never
    // sees the decision, so nothing stops a direct permit after a Deny.
    let binding = ExecutionBinding::new(
        "direct:r",
        0,
        "",
        "",
        "cred-a",
        "mock.echo",
        digest_bytes(b"{}"),
        digest_bytes(b"effective-direct/no-approval"),
    );
    assert!(
        ExecutionPermit::direct(binding, true, false).is_err(),
        "a direct permit was minted after the policy denied the request"
    );
}
