import Vultrino.Types

namespace Vultrino.Approval.Authority

/-!
The narrow cross-plane identity boundary for JSON approval decisions.

The cryptographic primitive and HTTP parser remain refinement/TCB obligations;
this model states what a successfully verified assertion is permitted to mean.
Every field that can change approval authority is part of one exact binding.
-/

abbrev Subject := String
abbrev ApproverClass := String
abbrev BodyDigest := String

/-- The authority-bearing request tuple covered by the broker assertion MAC. -/
structure DecisionBinding where
  tenant : TenantId
  approvalId : ApprovalId
  approve : Bool
  subject : Subject
  approverClass : ApproverClass
  method : String
  path : String
  query : String
  host : String
  bodyDigest : BodyDigest
deriving DecidableEq, Repr

/-- Evidence retained by the verifier after checking MAC shape and TTL bounds. -/
structure AssertionEvidence where
  binding : DecisionBinding
  expiresAt : Instant
deriving DecidableEq, Repr

/-- The assertion is usable only for one exact received tuple and bounded time. -/
def AssertionEvidence.validFor
    (evidence : AssertionEvidence)
    (received : DecisionBinding)
    (now maxTtl : Instant) : Prop :=
  evidence.binding = received ∧
  now ≤ evidence.expiresAt ∧
  evidence.expiresAt - now ≤ maxTtl

/-- Provenance carried into the approval state transition. Bare bearer-key
claims are deliberately distinct from request-bound broker evidence. -/
inductive IdentityEvidence where
  | aggregatorClaim (apiKey subject : String)
  | verifiedBroker
      (evidence : AssertionEvidence)
      (received : DecisionBinding)
      (now maxTtl : Instant)
      (valid : evidence.validFor received now maxTtl)

/-- A verified broker decision has exactly the tenant, approval, outcome,
subject, class, route, host, and body digest that were MAC-bound. -/
theorem verified_broker_identity_is_exact
    {evidence : AssertionEvidence}
    {received : DecisionBinding}
    {now maxTtl : Instant}
    (valid : evidence.validFor received now maxTtl) :
    evidence.binding.tenant = received.tenant ∧
    evidence.binding.approvalId = received.approvalId ∧
    evidence.binding.approve = received.approve ∧
    evidence.binding.subject = received.subject ∧
    evidence.binding.approverClass = received.approverClass ∧
    evidence.binding.method = received.method ∧
    evidence.binding.path = received.path ∧
    evidence.binding.query = received.query ∧
    evidence.binding.host = received.host ∧
    evidence.binding.bodyDigest = received.bodyDigest := by
  have exactBinding : evidence.binding = received := valid.1
  cases exactBinding
  simp

/-- Changing any authority-bearing field makes the old evidence invalid for the
new request. This is the abstract post-signing-tamper rejection theorem. -/
theorem changed_binding_rejected
    {evidence : AssertionEvidence}
    {original changed : DecisionBinding}
    {now maxTtl : Instant}
    (valid : evidence.validFor original now maxTtl)
    (changedBinding : changed ≠ original) :
    ¬ evidence.validFor changed now maxTtl := by
  intro changedValid
  exact changedBinding (changedValid.1.symm.trans valid.1)

/-- A bearer-key claim carries no theorem that two subject strings behind the
same key are independently authenticated. Code must keep such identities in the
`agg:<key>:` namespace and apply the one-positive-slot-per-key guard. -/
def independentlyAuthenticated : IdentityEvidence → Prop
  | .aggregatorClaim _ _ => False
  | .verifiedBroker _ _ _ _ _ => True

theorem aggregator_claim_is_not_independent (apiKey subject : String) :
    ¬ independentlyAuthenticated (.aggregatorClaim apiKey subject) := by
  simp [independentlyAuthenticated]

theorem verified_broker_claim_is_independent
    {evidence : AssertionEvidence}
    {received : DecisionBinding}
    {now maxTtl : Instant}
    (valid : evidence.validFor received now maxTtl) :
    independentlyAuthenticated
      (.verifiedBroker evidence received now maxTtl valid) := by
  simp [independentlyAuthenticated]

end Vultrino.Approval.Authority
