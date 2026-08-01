namespace Vultrino.Approval

/-- Trusted result of resolving the request against the stored capability
catalog. `undeclared` preserves local legacy plugin calls; `unavailable` cannot
prove that the action is reversible and therefore refuses. -/
inductive IrreversibilityResolution where
  | reversible
  | humanFloor
  | undeclared
  | ambiguousCanonical
  | unavailable
deriving DecidableEq, Repr

def IrreversibilityResolution.automaticallyRequiresApproval :
    IrreversibilityResolution → Bool
  | .humanFloor | .ambiguousCanonical => true
  | .reversible | .undeclared | .unavailable => false

inductive CriticalGateDecision where
  | direct
  | pendingApproval
  | refuse
deriving DecidableEq, Repr

/-- Criticality's contribution to the production execution gate. Other policy,
scope, recipe, and permit checks can only narrow `pendingApproval` or `direct`. -/
def decideCriticalGate
    (strictCatalog : Bool)
    (approvalsEnabled : Bool)
    (resolution : IrreversibilityResolution) : CriticalGateDecision :=
  match resolution with
  | .unavailable => .refuse
  | .undeclared => if strictCatalog then .refuse else .direct
  | .humanFloor | .ambiguousCanonical =>
      if approvalsEnabled then .pendingApproval else .refuse
  | .reversible => .direct

/-- V-A26 safety half: a declared irreversible/partially-reversible action can
never receive direct execution authority, regardless of approval posture. -/
theorem declared_human_floor_never_direct
    (strictCatalog approvalsEnabled : Bool) :
    decideCriticalGate strictCatalog approvalsEnabled .humanFloor ≠ .direct := by
  cases approvalsEnabled <;> simp [decideCriticalGate]

/-- A catalog outage is also never direct authority: classification cannot be
established, so execution refuses regardless of approval posture. -/
theorem unavailable_catalog_never_direct
    (strictCatalog approvalsEnabled : Bool) :
    decideCriticalGate strictCatalog approvalsEnabled .unavailable ≠ .direct := by
  simp [decideCriticalGate]

/-- A governed canonical verb shared by business labels has erased the exact
declaration and recipe key. It can enter approval or refuse, never direct. -/
theorem ambiguous_canonical_never_direct
    (strictCatalog approvalsEnabled : Bool) :
    decideCriticalGate strictCatalog approvalsEnabled .ambiguousCanonical ≠ .direct := by
  cases approvalsEnabled <;> simp [decideCriticalGate]

/-- V-A26b: production strictness turns a missing exact declaration into
refusal. Disabling approvals is irrelevant because no approval is opened. -/
theorem strict_catalog_undeclared_never_direct
    (approvalsEnabled : Bool) :
    decideCriticalGate true approvalsEnabled .undeclared ≠ .direct := by
  simp [decideCriticalGate]

/-- If criticality permits a direct path, the trusted snapshot did not classify
the action as human-floor and the catalog was not unavailable. -/
theorem direct_excludes_human_floor_and_unavailable
    {strictCatalog approvalsEnabled : Bool}
    {resolution : IrreversibilityResolution}
    (direct : decideCriticalGate strictCatalog approvalsEnabled resolution = .direct) :
    resolution ≠ .humanFloor ∧
      resolution ≠ .ambiguousCanonical ∧
      resolution ≠ .unavailable := by
  cases strictCatalog <;> cases approvalsEnabled <;> cases resolution <;>
    simp [decideCriticalGate] at direct ⊢

/-- In the production strict posture, direct criticality authority is possible
only after an exact, trusted reversible declaration. -/
theorem strict_catalog_direct_implies_reversible
    {approvalsEnabled : Bool} {resolution : IrreversibilityResolution}
    (direct : decideCriticalGate true approvalsEnabled resolution = .direct) :
    resolution = .reversible := by
  cases approvalsEnabled <;> cases resolution <;>
    simp [decideCriticalGate] at direct ⊢

/-- An approval may resume only when a fresh exact credential+action catalog
resolution matches the authority class frozen at approval-open. An unavailable
catalog is never continuity evidence. -/
def approvalCatalogStillAuthorizes
    (opened current : IrreversibilityResolution) : Bool :=
  current != .unavailable && opened == current

/-- A catalog replacement that changes the authority class invalidates the old
approval. This includes reversible-to-human-floor escalation. -/
theorem changed_catalog_authority_refuses_resume
    {opened current : IrreversibilityResolution}
    (changed : opened ≠ current) :
    approvalCatalogStillAuthorizes opened current = false := by
  simp [approvalCatalogStillAuthorizes, changed]

/-- A successful approval resume proves continuity of the exact request's
catalog authority from approval-open to permit issuance. -/
theorem approval_resume_implies_same_catalog_authority
    {opened current : IrreversibilityResolution}
    (authorized : approvalCatalogStillAuthorizes opened current = true) :
    opened = current := by
  simp [approvalCatalogStillAuthorizes] at authorized
  exact authorized.2

/-- Catalog unavailability at resume is fail-closed regardless of the stamped
open-time authority. -/
theorem unavailable_catalog_refuses_approval_resume
    (opened : IrreversibilityResolution) :
    approvalCatalogStillAuthorizes opened .unavailable = false := by
  simp [approvalCatalogStillAuthorizes]

end Vultrino.Approval
