//! VUL-05: the execution permit is minted only from a real policy evaluation
//! (direct) or a re-derived grant plus the resume evaluation (approved), and
//! `authorize` recomputes the binding from the payload it is handed.
//!
//! These tests drive the production policy engine, the approval module's grant
//! derivation and the production `ActionPayload` recomputation. They do not go
//! through `prepare_execution` or `resume_approved`; the server tests and
//! `tests/approval_token_integration.rs` cover those paths end to end.

use super::*;
use crate::formal_kernel::{admit, AdmissionKind, ExecutionPermit, PermitError};
use crate::policy::{
    AdmissionQuery, Policy, PolicyAction, PolicyCondition, PolicyEngine, PolicyRule, Principal,
};

const CREDENTIAL: &str = "cred-a";

fn refusal(
    result: Result<crate::formal_kernel::Authorized<ActionPayload>, PermitError>,
) -> PermitError {
    match result {
        Ok(_) => panic!("the permit authorized the payload"),
        Err(error) => error,
    }
}

fn params_a() -> serde_json::Value {
    serde_json::json!({"method": "POST", "url": "https://api.example.com/a"})
}

fn params_b() -> serde_json::Value {
    serde_json::json!({"method": "POST", "url": "https://other.example.net/b"})
}

fn principal() -> Principal {
    Principal {
        id: "k1".to_string(),
        agent_label: None,
        owner: None,
        workload_id: None,
    }
}

fn credential(alias: &str) -> crate::Credential {
    crate::Credential::new(
        alias.to_string(),
        crate::CredentialData::ApiKey {
            key: crate::Secret::new("secret-key"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
}

/// A direct payload exactly as `prepare_execution` builds it for principal
/// `k1` in `tenant-a`.
fn direct_payload(params: serde_json::Value) -> ActionPayload {
    let mut context = RequestContext::new();
    context.api_key_id = Some("k1".to_string());
    context.tenant = Some("tenant-a".to_string());
    ActionPayload {
        credential: credential(CREDENTIAL),
        plugin_name: "mock".to_string(),
        action_name: "echo".to_string(),
        params,
        context,
        use_token_id: None,
        evidence_subject_id: None,
        approved_execution: false,
        evidence_action: "mock.echo".to_string(),
        evidence_required: false,
    }
}

fn allow_engine() -> PolicyEngine {
    let engine = PolicyEngine::new();
    engine.set_default_deny(false);
    engine
}

fn evaluate(
    engine: &PolicyEngine,
    params: &serde_json::Value,
    observe_tenant: bool,
) -> crate::policy::Evaluation {
    let principal = principal();
    engine.evaluate_for_admission(
        &AdmissionQuery {
            credential_alias: CREDENTIAL,
            action: "mock.echo",
            params,
            principal: Some(&principal),
            spend: None,
        },
        observe_tenant,
    )
}

/// Mint a direct permit for `request_id` the way `prepare_execution` does.
fn direct_permit(
    engine: &PolicyEngine,
    params: &serde_json::Value,
    request_id: &str,
) -> ExecutionPermit {
    let witness = admit(evaluate(engine, params, false), false).expect("Allow admits");
    ExecutionPermit::direct(witness, request_id, "tenant-a", "mock.echo")
}

#[test]
fn permit_binding_negative_params_changed_after_mint() {
    let engine = allow_engine();
    // Control: the exact payload is authorized.
    let exact = direct_payload(params_a());
    let permit = direct_permit(&engine, &params_a(), &exact.context.request_id);
    assert!(permit.authorize(exact).is_ok());

    // The permit was minted for params A; the payload now carries params B.
    let changed = direct_payload(params_b());
    let permit = direct_permit(&engine, &params_a(), &changed.context.request_id);
    assert_eq!(
        refusal(permit.authorize(changed)),
        PermitError::BindingMismatch,
        "a permit minted for one params value authorized a payload with different params"
    );
}

#[test]
fn permit_binding_negative_every_payload_field() {
    let engine = allow_engine();
    type Change = (&'static str, fn(&mut ActionPayload));
    let changes: [Change; 9] = [
        ("credential alias", |p| p.credential = credential("cred-b")),
        ("plugin", |p| p.plugin_name = "http".to_string()),
        ("action", |p| p.action_name = "request".to_string()),
        ("params", |p| p.params = params_b()),
        ("tenant", |p| {
            p.context.tenant = Some("tenant-b".to_string())
        }),
        ("principal", |p| {
            p.context.api_key_id = Some("k2".to_string())
        }),
        ("claims approved execution", |p| p.approved_execution = true),
        ("carries an approval id", |p| {
            p.context.approval_id = Some("appr_x".to_string())
        }),
        ("carries an approval epoch", |p| {
            p.context.approval_execution_epoch = Some(0)
        }),
    ];
    for (field, change) in changes {
        let mut payload = direct_payload(params_a());
        let permit = direct_permit(&engine, &params_a(), &payload.context.request_id);
        change(&mut payload);
        let error = refusal(permit.authorize(payload));
        assert!(
            matches!(
                error,
                PermitError::BindingMismatch | PermitError::Unbindable
            ),
            "a payload whose {field} changed after mint was authorized ({error:?})"
        );
    }
    // A permit minted for another request id does not authorize this payload.
    let payload = direct_payload(params_a());
    let permit = direct_permit(&engine, &params_a(), "another-request");
    assert_eq!(
        refusal(permit.authorize(payload)),
        PermitError::BindingMismatch
    );
}

#[test]
fn admission_deny_cannot_reach_direct_mint() {
    // A real evaluation that denies: the engine fails closed with no policy.
    let engine = PolicyEngine::new();
    for approval_required in [false, true] {
        let evaluation = evaluate(&engine, &params_a(), false);
        assert!(matches!(
            evaluation.decision(),
            crate::policy::PolicyDecision::Deny(_)
        ));
        assert!(!evaluation.observe_downgrade());
        assert_eq!(
            admit(evaluation, approval_required).unwrap_err(),
            PermitError::PolicyDenied,
            "an enforced Deny produced a direct witness or an approval route"
        );
    }
}

#[test]
fn admission_observe_mode_is_an_explicit_witness_kind() {
    // Observe tenant, ordinary Deny: admitted, but only as ObservedDeny.
    let engine = PolicyEngine::new();
    let evaluation = evaluate(&engine, &params_a(), true);
    assert!(evaluation.observe_downgrade());
    let payload = direct_payload(params_a());
    let permit = ExecutionPermit::direct(
        admit(evaluation, false).expect("observe mode admits an ordinary Deny"),
        &payload.context.request_id,
        "tenant-a",
        "mock.echo",
    );
    assert_eq!(permit.admission_kind(), Some(AdmissionKind::ObservedDeny));
    assert!(permit.authorize(payload).is_ok());

    // Observe never applies when approval is required: the request goes to a human.
    assert_eq!(
        admit(evaluate(&engine, &params_a(), true), true).unwrap_err(),
        PermitError::ApprovalRequired
    );

    // Observe never downgrades a kill switch or a resource guard.
    let rule = |condition| PolicyRule {
        condition,
        action: PolicyAction::Allow,
    };
    let kill = PolicyEngine::new();
    kill.add_policy(Policy {
        id: "halt".to_string(),
        name: "halt".to_string(),
        credential_pattern: "*".to_string(),
        principal_pattern: None,
        rules: vec![],
        default_action: PolicyAction::Deny,
        kill: true,
    });
    let guarded = PolicyEngine::new();
    guarded.add_policy(Policy {
        id: "rate".to_string(),
        name: "rate".to_string(),
        credential_pattern: "*".to_string(),
        principal_pattern: None,
        rules: vec![rule(PolicyCondition::And(vec![
            PolicyCondition::UrlMatch("https://nowhere.example/*".to_string()),
            PolicyCondition::RateLimit {
                max: 1,
                window_secs: 60,
            },
        ]))],
        default_action: PolicyAction::Deny,
        kill: false,
    });
    for (label, engine) in [("kill switch", kill), ("resource guard", guarded)] {
        let evaluation = evaluate(&engine, &params_a(), true);
        assert!(
            !evaluation.observe_downgrade(),
            "{label}: observe mode downgraded a Deny it must keep"
        );
        assert_eq!(
            admit(evaluation, false).unwrap_err(),
            PermitError::PolicyDenied,
            "{label}"
        );
    }
}

#[test]
fn admission_allow_is_explicit_and_prompt_goes_to_approval() {
    let engine = allow_engine();
    let witness = admit(evaluate(&engine, &params_a(), false), false).unwrap();
    let permit = ExecutionPermit::direct(witness, "r", "tenant-a", "mock.echo");
    assert_eq!(permit.admission_kind(), Some(AdmissionKind::Allow));
    // Allow plus a server-side approval requirement goes to approval.
    assert_eq!(
        admit(evaluate(&engine, &params_a(), false), true).unwrap_err(),
        PermitError::ApprovalRequired
    );

    let prompt = PolicyEngine::new();
    prompt.add_policy(Policy {
        id: "ask".to_string(),
        name: "ask".to_string(),
        credential_pattern: "*".to_string(),
        principal_pattern: None,
        rules: vec![],
        default_action: PolicyAction::Prompt,
        kill: false,
    });
    assert_eq!(
        admit(evaluate(&prompt, &params_a(), false), false).unwrap_err(),
        PermitError::ApprovalRequired,
        "a Prompt reached the direct mint without approval"
    );
}

// ---------------------------------------------------------------------------
// Approved permits
// ---------------------------------------------------------------------------

fn approved_request() -> crate::approval::ApprovalRequest {
    use crate::approval::{
        ApprovalRequest, CriticalityClass, Decision, NewApproval, RequesterInfo,
    };
    let (mut approval, _token) = ApprovalRequest::open(NewApproval {
        credential: CREDENTIAL.to_string(),
        action: "mock.echo".to_string(),
        params: params_a(),
        requester: RequesterInfo {
            principal_kind: "api_key".to_string(),
            principal_id: Some("k1".to_string()),
            principal_name: Some("agent".to_string()),
            role: Some("executor".to_string()),
            owner: None,
        },
        use_token_id: None,
        principal_id: Some("k1".to_string()),
        agent_label: None,
        tenant: Some("tenant-a".to_string()),
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: CriticalityClass::Medium,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    });
    approval
        .approve(Decision::new("admin panel", "alice@corp"))
        .unwrap();
    approval
}

/// The payload `resume_approved` builds from the approval record.
fn approved_payload(
    approval: &crate::approval::ApprovalRequest,
    params: serde_json::Value,
) -> ActionPayload {
    let mut context = RequestContext::new();
    context.api_key_id = approval.principal_id.clone();
    context.bind_approved_execution(
        approval.id.clone(),
        approval.execution_epoch,
        approval.tenant.clone(),
    );
    ActionPayload {
        credential: credential(&approval.credential),
        plugin_name: "mock".to_string(),
        action_name: "echo".to_string(),
        params,
        context,
        use_token_id: None,
        evidence_subject_id: Some(format!("approval:{}:0", approval.id)),
        approved_execution: true,
        evidence_action: "mock.echo".to_string(),
        evidence_required: false,
    }
}

fn resume_evaluation(
    engine: &PolicyEngine,
    params: &serde_json::Value,
) -> crate::policy::Evaluation {
    let principal = principal();
    engine.evaluate_readonly_for_admission(&AdmissionQuery {
        credential_alias: CREDENTIAL,
        action: "mock.echo",
        params,
        principal: Some(&principal),
        spend: None,
    })
}

fn approved_permit(
    approval: &crate::approval::ApprovalRequest,
    engine: &PolicyEngine,
    judged: &serde_json::Value,
) -> Result<ExecutionPermit, PermitError> {
    ExecutionPermit::approved(
        approval
            .grant_witness()
            .expect("an approved request re-derives"),
        resume_evaluation(engine, judged),
        chrono::Utc::now().timestamp(),
    )
}

#[test]
fn approved_permit_binding_negative_params_changed_after_mint() {
    let approval = approved_request();
    let engine = allow_engine();
    // Control: the payload built from the record is authorized.
    let permit = approved_permit(&approval, &engine, &params_a()).unwrap();
    assert_eq!(permit.admission_kind(), None);
    assert!(permit
        .authorize(approved_payload(&approval, params_a()))
        .is_ok());

    let permit = approved_permit(&approval, &engine, &params_a()).unwrap();
    assert_eq!(
        refusal(permit.authorize(approved_payload(&approval, params_b()))),
        PermitError::BindingMismatch,
        "an approved permit authorized params the approver did not approve"
    );

    // An approved permit never authorizes a payload that claims direct execution.
    let permit = approved_permit(&approval, &engine, &params_a()).unwrap();
    let mut direct = approved_payload(&approval, params_a());
    direct.approved_execution = false;
    assert!(permit.authorize(direct).is_err());
}

#[test]
fn approved_permit_refuses_resume_deny_and_a_different_judgement() {
    let approval = approved_request();
    // A Deny at resume refuses, even though the grant is valid.
    assert_eq!(
        approved_permit(&approval, &PolicyEngine::new(), &params_a()).unwrap_err(),
        PermitError::PolicyDenied
    );
    // The resume evaluation judged other params than the grant binds.
    assert_eq!(
        approved_permit(&approval, &allow_engine(), &params_b()).unwrap_err(),
        PermitError::BindingMismatch
    );
    // A Prompt at resume is satisfied by the grant.
    let prompt = PolicyEngine::new();
    prompt.add_policy(Policy {
        id: "ask".to_string(),
        name: "ask".to_string(),
        credential_pattern: "*".to_string(),
        principal_pattern: None,
        rules: vec![],
        default_action: PolicyAction::Prompt,
        kill: false,
    });
    assert!(approved_permit(&approval, &prompt, &params_a()).is_ok());
}
