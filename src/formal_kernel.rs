//! Pure enforcement kernel mirrored by `formal/lean/Vultrino`.
//!
//! This module contains no I/O, async, locks, globals, or unsafe code. It is the
//! small Rust surface intended for translation/refinement checking. The Tokio
//! adapter is responsible only for deriving these values from authenticated
//! state and linearizing the durable claim.
//!
//! VUL-05: a permit is minted only from evidence another module produced (an
//! [`AdmissionWitness`] built from a [`crate::policy::Evaluation`], or a
//! [`crate::approval::Granted`]), and [`ExecutionPermit::authorize`] recomputes
//! the binding from the payload it is handed instead of receiving one.

use sha2::{Digest, Sha256};

/// Every execution-relevant field an approval or direct decision authorizes.
/// Equality is the refinement obligation at the side-effect boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBinding {
    pub approval_id: String,
    pub epoch: u64,
    pub tenant: String,
    pub principal: String,
    pub credential: String,
    pub action: String,
    pub params_digest: String,
    pub rule_digest: String,
}

impl ExecutionBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        approval_id: impl Into<String>,
        epoch: u64,
        tenant: impl Into<String>,
        principal: impl Into<String>,
        credential: impl Into<String>,
        action: impl Into<String>,
        params_digest: impl Into<String>,
        rule_digest: impl Into<String>,
    ) -> Self {
        Self {
            approval_id: approval_id.into(),
            epoch,
            tenant: tenant.into(),
            principal: principal.into(),
            credential: credential.into(),
            action: action.into(),
            params_digest: params_digest.into(),
            rule_digest: rule_digest.into(),
        }
    }

    /// Whether a payload's recomputed binding carries exactly this binding.
    /// The rule digest is authority evidence checked when the permit is
    /// minted, not a property of the payload, so it is not compared here.
    fn binds(&self, dispatched: &DispatchedBinding) -> bool {
        self.approval_id == dispatched.approval_id
            && self.epoch == dispatched.epoch
            && self.tenant == dispatched.tenant
            && self.principal == dispatched.principal
            && self.credential == dispatched.credential
            && self.action == dispatched.action
            && self.params_digest == dispatched.params_digest
    }
}

/// Exact SHA-256 digest of the bytes the adapter presents to the kernel.
/// Canonicalization is deliberately outside this function and must be shared by
/// the producer/consumer adapter; collision resistance remains a TCB assumption.
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Digest of the serde_json bytes of an action's params. The policy
/// evaluation, the approval binding and the dispatched payload all use this one
/// function, so the same params value always gives the same digest. `None`
/// when the value cannot be serialized, which every caller refuses.
pub(crate) fn digest_params(params: &serde_json::Value) -> Option<String> {
    serde_json::to_vec(params)
        .ok()
        .map(|bytes| digest_bytes(&bytes))
}

/// Advance the durable one-shot fence without wraparound.
pub(crate) fn next_epoch(current: u64) -> Option<u64> {
    current.checked_add(1)
}

/// The kinds of policy decision the admission gate distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    Deny,
    Prompt,
}

/// Why a direct permit exists. There is no kind for an enforced Deny or for a
/// Prompt, so a witness can only name one of these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionKind {
    /// The effective policy allowed the request.
    Allow,
    /// The policy denied the request, but V11 observe mode lets it run: the
    /// tenant is observe-only and the denial came from neither a kill switch
    /// nor a SpendCap or RateLimit guard. The server emits the denial as an
    /// event; the permit keeps this kind (and a distinct rule digest), so an
    /// observed denial is never recorded as an Allow.
    ObservedDeny,
}

/// `digest_bytes(b"effective-direct/allow")`, spelled out so the kernel (and
/// Kani) does not hash at mint time. A unit test pins it to the function.
const DIRECT_ALLOW_RULE_DIGEST: &str =
    "sha256:d2c08dcdbdeee9ba014f122cbddc6c68c7264db9360594cf1f8b0d64852ec12a";
/// `digest_bytes(b"effective-direct/observed-deny")`, pinned the same way.
const DIRECT_OBSERVED_DENY_RULE_DIGEST: &str =
    "sha256:f09492db3e9370dcf6c024c71fd2747afc1b34a9710432f6585ebc68b53fb4ca";

impl AdmissionKind {
    fn rule_digest(self) -> &'static str {
        match self {
            AdmissionKind::Allow => DIRECT_ALLOW_RULE_DIGEST,
            AdmissionKind::ObservedDeny => DIRECT_OBSERVED_DENY_RULE_DIGEST,
        }
    }
}

/// What one policy evaluation judged: the credential alias, the principal id
/// (empty when there is none) and the digest of the params whose URL and
/// method it judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JudgedSubject {
    credential: String,
    principal: String,
    params_digest: String,
}

impl JudgedSubject {
    pub(crate) fn new(
        credential: impl Into<String>,
        principal: impl Into<String>,
        params_digest: impl Into<String>,
    ) -> Self {
        Self {
            credential: credential.into(),
            principal: principal.into(),
            params_digest: params_digest.into(),
        }
    }

    /// Whether `binding` names exactly the request this evaluation judged.
    fn judged(&self, binding: &ExecutionBinding) -> bool {
        self.credential == binding.credential
            && self.principal == binding.principal
            && self.params_digest == binding.params_digest
    }
}

/// The pure admission table. It decides between a direct permit, human
/// approval and refusal for one evaluated request:
///
/// - Allow runs directly unless approval is required;
/// - Deny refuses, unless observe mode downgrades it, and then it behaves as
///   Allow but keeps the `ObservedDeny` kind;
/// - Prompt always requires approval.
pub(crate) fn admission_gate(
    verdict: Verdict,
    observe_downgrade: bool,
    approval_required: bool,
) -> Result<AdmissionKind, PermitError> {
    let kind = match verdict {
        Verdict::Allow => AdmissionKind::Allow,
        Verdict::Deny if observe_downgrade => AdmissionKind::ObservedDeny,
        Verdict::Deny => return Err(PermitError::PolicyDenied),
        Verdict::Prompt => return Err(PermitError::ApprovalRequired),
    };
    if approval_required {
        return Err(PermitError::ApprovalRequired);
    }
    Ok(kind)
}

/// Evidence that one policy evaluation admitted one request for direct
/// execution. The fields are private; outside this module [`admit`] is the
/// only way to obtain one. It is neither `Clone`, `Copy`, `Default`, nor
/// deserializable.
#[derive(Debug)]
#[must_use = "an AdmissionWitness is the only input that mints a direct permit"]
pub(crate) struct AdmissionWitness {
    kind: AdmissionKind,
    subject: JudgedSubject,
}

/// Run the admission gate on a real policy evaluation. `Ok` is the only way to
/// obtain an [`AdmissionWitness`]; `Err(ApprovalRequired)` sends the request to
/// human approval; any other error refuses it.
pub(crate) fn admit(
    evaluation: crate::policy::Evaluation,
    approval_required: bool,
) -> Result<AdmissionWitness, PermitError> {
    let verdict = evaluation.verdict();
    let observe_downgrade = evaluation.observe_downgrade();
    witness_from(
        verdict,
        observe_downgrade,
        approval_required,
        evaluation.into_subject(),
    )
}

fn witness_from(
    verdict: Verdict,
    observe_downgrade: bool,
    approval_required: bool,
    subject: Option<JudgedSubject>,
) -> Result<AdmissionWitness, PermitError> {
    let kind = admission_gate(verdict, observe_downgrade, approval_required)?;
    let subject = subject.ok_or(PermitError::Unbindable)?;
    Ok(AdmissionWitness { kind, subject })
}

/// The pure resume gate for an approved request: a policy Deny at resume
/// refuses (observe mode never applies at resume), a Prompt is satisfied by the
/// grant, and the grant is valid from its issue time up to, not including, its
/// expiry.
pub(crate) fn approved_gate(
    verdict: Verdict,
    now_unix_seconds: i64,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
) -> Result<(), PermitError> {
    if verdict == Verdict::Deny {
        return Err(PermitError::PolicyDenied);
    }
    if now_unix_seconds < issued_at_unix_seconds {
        return Err(PermitError::GrantNotYetIssued);
    }
    if now_unix_seconds >= expires_at_unix_seconds {
        return Err(PermitError::GrantExpired);
    }
    Ok(())
}

/// Why an execution permit exists. Private so possession, not inspection, is
/// the authority consumed at dispatch.
#[derive(Debug)]
enum PermitBasis {
    Direct(AdmissionKind),
    #[allow(dead_code)] // carried as the consumed proof object, never a decision input
    Approved(Box<crate::approval::Granted>),
}

impl PermitBasis {
    fn is_approved(&self) -> bool {
        matches!(self, PermitBasis::Approved(_))
    }
}

/// The only authority accepted by a side-effecting plugin dispatch.
///
/// It has no public constructor and is neither `Clone`, `Copy`, `Default`, nor
/// deserializable. A direct permit consumes an [`AdmissionWitness`]; an
/// approved permit consumes the persisted grant witness.
#[derive(Debug)]
#[must_use = "dropping an ExecutionPermit discards the authority to execute"]
pub(crate) struct ExecutionPermit {
    binding: ExecutionBinding,
    basis: PermitBasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermitError {
    PolicyDenied,
    ApprovalRequired,
    BindingMismatch,
    /// The params could not be serialized, so no binding could be computed.
    Unbindable,
    GrantNotYetIssued,
    GrantExpired,
}

/// The binding fields a payload determines, recomputed from the values the
/// payload will dispatch, plus whether it claims approved execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchedBinding {
    pub approved: bool,
    pub approval_id: String,
    pub epoch: u64,
    pub tenant: String,
    pub principal: String,
    pub credential: String,
    pub action: String,
    pub params_digest: String,
}

/// A payload that can recompute its own binding. `None` means it cannot be
/// bound (for example an approved payload with no approval id), which refuses.
pub(crate) trait Dispatch {
    fn dispatched_binding(&self) -> Option<DispatchedBinding>;
}

impl ExecutionPermit {
    /// Mint direct authority. The credential, principal and params digest come
    /// from what the policy evaluation judged (carried by the witness), the
    /// rule digest from the witness kind. The server supplies only the request
    /// id, the tenant and the canonical action, and [`Self::authorize`] then
    /// recomputes all of them from the payload.
    pub(crate) fn direct(
        witness: AdmissionWitness,
        request_id: &str,
        tenant: &str,
        action: &str,
    ) -> Self {
        let AdmissionWitness { kind, subject } = witness;
        let JudgedSubject {
            credential,
            principal,
            params_digest,
        } = subject;
        let mut approval_id = String::from("direct:");
        approval_id.push_str(request_id);
        Self {
            binding: ExecutionBinding::new(
                approval_id,
                0,
                tenant,
                principal,
                credential,
                action,
                params_digest,
                kind.rule_digest(),
            ),
            basis: PermitBasis::Direct(kind),
        }
    }

    /// Mint authority for an approved request by consuming the grant the
    /// approval module re-derived from the persisted record under the durable
    /// claim lock, and the read-only policy evaluation made at resume. The
    /// binding is the grant's; the resume evaluation must have judged the same
    /// credential, principal and params.
    pub(crate) fn approved(
        grant: crate::approval::Granted,
        resume: crate::policy::Evaluation,
        now_unix_seconds: i64,
    ) -> Result<Self, PermitError> {
        approved_gate(
            resume.verdict(),
            now_unix_seconds,
            grant.issued_at_unix_seconds(),
            grant.expires_at_unix_seconds(),
        )?;
        match resume.subject() {
            Some(subject) if subject.judged(grant.binding()) => {}
            Some(_) => return Err(PermitError::BindingMismatch),
            None => return Err(PermitError::Unbindable),
        }
        Ok(Self {
            binding: grant.binding().clone(),
            basis: PermitBasis::Approved(Box::new(grant)),
        })
    }

    /// The admission kind of a direct permit; `None` for an approved one.
    pub(crate) fn admission_kind(&self) -> Option<AdmissionKind> {
        match self.basis {
            PermitBasis::Direct(kind) => Some(kind),
            PermitBasis::Approved(_) => None,
        }
    }

    /// Bind the permit to the exact dispatch payload. The binding is
    /// recomputed from the payload (approval id or request id, epoch, tenant,
    /// principal, credential alias, canonical action and the params digest)
    /// and must equal the permit's; a direct permit cannot authorize a payload
    /// that claims approved execution, nor the reverse. The returned wrapper
    /// has no public constructor and no mutable access, preventing field
    /// substitution after authorization.
    pub(crate) fn authorize<T: Dispatch>(self, payload: T) -> Result<Authorized<T>, PermitError> {
        let dispatched = payload
            .dispatched_binding()
            .ok_or(PermitError::Unbindable)?;
        if dispatched.approved != self.basis.is_approved() || !self.binding.binds(&dispatched) {
            return Err(PermitError::BindingMismatch);
        }
        Ok(Authorized {
            payload,
            _permit: self,
        })
    }
}

/// A payload paired with and protected by one non-cloneable permit.
#[derive(Debug)]
pub(crate) struct Authorized<T> {
    payload: T,
    _permit: ExecutionPermit,
}

impl<T> Authorized<T> {
    pub(crate) fn payload(&self) -> &T {
        &self.payload
    }

    /// Consumes the permit and payload together at the side-effect seam.
    pub(crate) fn into_payload(self) -> T {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> JudgedSubject {
        JudgedSubject::new("credential-a", "agent-a", digest_bytes(b"{}"))
    }

    fn dispatched_for(permit: &ExecutionPermit) -> DispatchedBinding {
        DispatchedBinding {
            approved: permit.basis.is_approved(),
            approval_id: permit.binding.approval_id.clone(),
            epoch: permit.binding.epoch,
            tenant: permit.binding.tenant.clone(),
            principal: permit.binding.principal.clone(),
            credential: permit.binding.credential.clone(),
            action: permit.binding.action.clone(),
            params_digest: permit.binding.params_digest.clone(),
        }
    }

    struct Fixed(DispatchedBinding);

    fn refusal<T>(result: Result<Authorized<T>, PermitError>) -> PermitError {
        match result {
            Ok(_) => panic!("the permit authorized the payload"),
            Err(error) => error,
        }
    }

    impl Dispatch for Fixed {
        fn dispatched_binding(&self) -> Option<DispatchedBinding> {
            Some(self.0.clone())
        }
    }

    fn direct_permit() -> ExecutionPermit {
        let witness = witness_from(Verdict::Allow, false, false, Some(subject())).unwrap();
        ExecutionPermit::direct(witness, "req-1", "tenant-a", "payments.refund")
    }

    #[test]
    fn admission_gate_exhaustive() {
        use PermitError::*;
        use Verdict::*;
        // Independent table: every input, every outcome, written out.
        let table = [
            (Allow, false, false, Ok(AdmissionKind::Allow)),
            (Allow, false, true, Err(ApprovalRequired)),
            (Allow, true, false, Ok(AdmissionKind::Allow)),
            (Allow, true, true, Err(ApprovalRequired)),
            (Deny, false, false, Err(PolicyDenied)),
            (Deny, false, true, Err(PolicyDenied)),
            (Deny, true, false, Ok(AdmissionKind::ObservedDeny)),
            (Deny, true, true, Err(ApprovalRequired)),
            (Prompt, false, false, Err(ApprovalRequired)),
            (Prompt, false, true, Err(ApprovalRequired)),
            (Prompt, true, false, Err(ApprovalRequired)),
            (Prompt, true, true, Err(ApprovalRequired)),
        ];
        for (verdict, observe, approval, want) in table {
            assert_eq!(
                admission_gate(verdict, observe, approval),
                want,
                "{verdict:?} observe={observe} approval_required={approval}"
            );
            let witness = witness_from(verdict, observe, approval, Some(subject()));
            assert_eq!(witness.as_ref().ok().map(|w| w.kind), want.ok());
            assert_eq!(witness.err(), want.err());
            // No subject, no witness, whatever the gate says.
            assert!(witness_from(verdict, observe, approval, None).is_err());
        }
    }

    #[test]
    fn direct_rule_digests_are_the_digests_they_name() {
        assert_eq!(
            DIRECT_ALLOW_RULE_DIGEST,
            digest_bytes(b"effective-direct/allow")
        );
        assert_eq!(
            DIRECT_OBSERVED_DENY_RULE_DIGEST,
            digest_bytes(b"effective-direct/observed-deny")
        );
    }

    #[test]
    fn direct_permit_carries_the_judged_subject_and_kind() {
        for (observe, kind, rule) in [
            (false, AdmissionKind::Allow, &b"effective-direct/allow"[..]),
            (
                true,
                AdmissionKind::ObservedDeny,
                &b"effective-direct/observed-deny"[..],
            ),
        ] {
            let verdict = if observe {
                Verdict::Deny
            } else {
                Verdict::Allow
            };
            let witness = witness_from(verdict, observe, false, Some(subject())).unwrap();
            let permit = ExecutionPermit::direct(witness, "req-1", "tenant-a", "http.request");
            assert_eq!(permit.admission_kind(), Some(kind));
            assert_eq!(
                permit.binding,
                ExecutionBinding::new(
                    "direct:req-1",
                    0,
                    "tenant-a",
                    "agent-a",
                    "credential-a",
                    "http.request",
                    digest_bytes(b"{}"),
                    digest_bytes(rule),
                )
            );
        }
    }

    #[test]
    fn authorize_refuses_every_single_field_substitution() {
        let exact = dispatched_for(&direct_permit());
        assert!(direct_permit().authorize(Fixed(exact.clone())).is_ok());
        type Substitution = (&'static str, fn(&mut DispatchedBinding));
        let substitutions: [Substitution; 8] = [
            ("approved", |d| d.approved = true),
            ("approval_id", |d| d.approval_id = "direct:req-2".into()),
            ("epoch", |d| d.epoch = 1),
            ("tenant", |d| d.tenant = "tenant-b".into()),
            ("principal", |d| d.principal = "agent-b".into()),
            ("credential", |d| d.credential = "credential-b".into()),
            ("action", |d| d.action = "payments.charge".into()),
            ("params_digest", |d| {
                d.params_digest = digest_bytes(br#"{"amount":1}"#)
            }),
        ];
        for (field, substitute) in substitutions {
            let mut changed = exact.clone();
            substitute(&mut changed);
            assert_eq!(
                refusal(direct_permit().authorize(Fixed(changed))),
                PermitError::BindingMismatch,
                "a payload with a different {field} was authorized"
            );
        }
    }

    #[test]
    fn authorize_refuses_an_unbindable_payload() {
        struct Unbound;
        impl Dispatch for Unbound {
            fn dispatched_binding(&self) -> Option<DispatchedBinding> {
                None
            }
        }
        assert_eq!(
            refusal(direct_permit().authorize(Unbound)),
            PermitError::Unbindable
        );
    }

    #[test]
    fn approved_gate_exhaustive_at_the_window_edges() {
        for verdict in [Verdict::Allow, Verdict::Deny, Verdict::Prompt] {
            for now in [9_i64, 10, 11, 19, 20, 21] {
                let want = if verdict == Verdict::Deny {
                    Err(PermitError::PolicyDenied)
                } else if now < 10 {
                    Err(PermitError::GrantNotYetIssued)
                } else if now >= 20 {
                    Err(PermitError::GrantExpired)
                } else {
                    Ok(())
                };
                assert_eq!(
                    approved_gate(verdict, now, 10, 20),
                    want,
                    "{verdict:?} now={now}"
                );
            }
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn any_verdict() -> Verdict {
        match kani::any::<u8>() % 3 {
            0 => Verdict::Allow,
            1 => Verdict::Deny,
            _ => Verdict::Prompt,
        }
    }

    fn pick(choice: bool) -> String {
        String::from(if choice { "a" } else { "b" })
    }

    /// The witness exists exactly when the verdict is Allow, or Deny under an
    /// observe downgrade, approval is not required, and the evaluation could
    /// bind its params. A direct permit built from it carries the judged
    /// subject and a kind that names which of the two admitted it.
    #[kani::proof]
    fn admission_gate_truth_table_is_exact() {
        let verdict = any_verdict();
        let observe: bool = kani::any();
        let approval_required: bool = kani::any();
        let bindable: bool = kani::any();
        let subject = if bindable {
            Some(JudgedSubject::new("c", "p", "d"))
        } else {
            None
        };
        let result = witness_from(verdict, observe, approval_required, subject);
        let allow = verdict == Verdict::Allow;
        let observed_deny = verdict == Verdict::Deny && observe;
        let admitted = (allow || observed_deny) && !approval_required && bindable;
        kani::cover!(admitted && allow, "admitted by Allow");
        kani::cover!(admitted && observed_deny, "admitted by an observed Deny");
        kani::cover!(
            !admitted && verdict == Verdict::Deny && !observe,
            "enforced Deny"
        );
        kani::cover!(
            !admitted && verdict == Verdict::Prompt,
            "Prompt goes to approval"
        );
        kani::cover!(!admitted && allow && approval_required, "approval required");
        kani::cover!(
            !admitted && allow && !approval_required && !bindable,
            "unbindable"
        );
        assert_eq!(result.is_ok(), admitted);
        match result {
            Ok(witness) => {
                let kind = witness.kind;
                assert!(
                    (kind == AdmissionKind::Allow && allow)
                        || (kind == AdmissionKind::ObservedDeny && observed_deny)
                );
                let permit = ExecutionPermit::direct(witness, "r", "t", "x");
                assert_eq!(permit.admission_kind(), Some(kind));
                assert_eq!(permit.binding.epoch, 0);
            }
            Err(PermitError::PolicyDenied) => {
                assert!(verdict == Verdict::Deny && !observe)
            }
            Err(PermitError::ApprovalRequired) => {
                assert!(verdict == Verdict::Prompt || approval_required)
            }
            Err(PermitError::Unbindable) => assert!(!bindable),
            Err(_) => panic!("the admission gate returned an error it never produces"),
        }

        // A direct permit copies the judged subject and the witness kind into
        // its binding. Built from a fixed witness so that no branch above
        // makes the string lengths symbolic.
        let kind = if kani::any() {
            AdmissionKind::Allow
        } else {
            AdmissionKind::ObservedDeny
        };
        let witness = AdmissionWitness {
            kind,
            subject: JudgedSubject::new("c", "p", "d"),
        };
        let permit = ExecutionPermit::direct(witness, "r", "t", "x");
        kani::cover!(kind == AdmissionKind::ObservedDeny, "observed-deny permit");
        assert!(permit.binding.approval_id == "direct:r");
        assert!(permit.binding.tenant == "t");
        assert!(permit.binding.principal == "p");
        assert!(permit.binding.credential == "c");
        assert!(permit.binding.action == "x");
        assert!(permit.binding.params_digest == "d");
        assert!(
            (kind == AdmissionKind::Allow
                && permit.binding.rule_digest == DIRECT_ALLOW_RULE_DIGEST)
                || (kind == AdmissionKind::ObservedDeny
                    && permit.binding.rule_digest == DIRECT_OBSERVED_DENY_RULE_DIGEST)
        );
    }

    /// authorize succeeds exactly when every dispatch-determined field the
    /// payload recomputes equals the permit's, and the payload does not claim
    /// approved execution for a direct permit. Each field is drawn from two
    /// values independently on both sides; the rule digest varies freely and
    /// must not matter.
    #[kani::proof]
    fn authorize_accepts_exactly_the_recomputed_binding() {
        let p: [bool; 6] = kani::any();
        let q: [bool; 6] = kani::any();
        let permit_epoch: u64 = kani::any();
        let payload_epoch: u64 = kani::any();
        let claims_approved: bool = kani::any();
        let permit = ExecutionPermit {
            binding: ExecutionBinding::new(
                pick(p[0]),
                permit_epoch,
                pick(p[1]),
                pick(p[2]),
                pick(p[3]),
                pick(p[4]),
                pick(p[5]),
                pick(kani::any()),
            ),
            basis: PermitBasis::Direct(AdmissionKind::Allow),
        };
        struct Payload(DispatchedBinding);
        impl Dispatch for Payload {
            fn dispatched_binding(&self) -> Option<DispatchedBinding> {
                Some(self.0.clone())
            }
        }
        let payload = Payload(DispatchedBinding {
            approved: claims_approved,
            approval_id: pick(q[0]),
            epoch: payload_epoch,
            tenant: pick(q[1]),
            principal: pick(q[2]),
            credential: pick(q[3]),
            action: pick(q[4]),
            params_digest: pick(q[5]),
        });
        let same = p == q && permit_epoch == payload_epoch && !claims_approved;
        let only_params_differ =
            p[..5] == q[..5] && p[5] != q[5] && permit_epoch == payload_epoch && !claims_approved;
        kani::cover!(same, "exact payload");
        kani::cover!(only_params_differ, "only the params digest differs");
        kani::cover!(
            p == q && permit_epoch == payload_epoch && claims_approved,
            "payload claims approved execution"
        );
        kani::cover!(
            p == q && permit_epoch != payload_epoch,
            "only the epoch differs"
        );
        let result = permit.authorize(payload);
        assert_eq!(result.is_ok(), same);
        if let Err(error) = result {
            assert_eq!(error, PermitError::BindingMismatch);
        }
    }

    /// The approved gate refuses a resume-time Deny and is valid exactly on
    /// [issued, expires) for every i64 clock value.
    #[kani::proof]
    fn approved_gate_enforces_deny_and_window() {
        let verdict = any_verdict();
        let now: i64 = kani::any();
        let issued: i64 = kani::any();
        let expires: i64 = kani::any();
        let result = approved_gate(verdict, now, issued, expires);
        let ok = verdict != Verdict::Deny && issued <= now && now < expires;
        kani::cover!(
            ok && verdict == Verdict::Prompt,
            "Prompt satisfied by the grant"
        );
        kani::cover!(verdict == Verdict::Deny, "resume Deny");
        kani::cover!(verdict != Verdict::Deny && now < issued, "not yet issued");
        kani::cover!(
            verdict != Verdict::Deny && now >= expires && now >= issued,
            "expired"
        );
        assert_eq!(result.is_ok(), ok);
    }

    #[kani::proof]
    fn execution_epoch_never_wraps() {
        let current: u64 = kani::any();
        match next_epoch(current) {
            Some(next) => {
                kani::cover!(true, "epoch advances");
                assert!(next > current)
            }
            None => {
                kani::cover!(true, "epoch saturates at u64::MAX");
                assert_eq!(current, u64::MAX)
            }
        }
    }
}
