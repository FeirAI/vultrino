namespace Vultrino.Approval

/-- Trusted result of resolving the request against the stored capability
catalog. `undeclared` preserves local legacy plugin calls; `unavailable` cannot
prove that the action is reversible and therefore fails to the approval path. -/
inductive IrreversibilityResolution where
  | reversible
  | humanFloor
  | undeclared
  | unavailable
deriving DecidableEq, Repr

def IrreversibilityResolution.automaticallyRequiresApproval :
    IrreversibilityResolution → Bool
  | .humanFloor | .unavailable => true
  | .reversible | .undeclared => false

inductive CriticalGateDecision where
  | direct
  | pendingApproval
  | refuse
deriving DecidableEq, Repr

/-- Criticality's contribution to the production execution gate. Other policy,
scope, recipe, and permit checks can only narrow `pendingApproval` or `direct`. -/
def decideCriticalGate
    (approvalsEnabled : Bool)
    (resolution : IrreversibilityResolution) : CriticalGateDecision :=
  if resolution.automaticallyRequiresApproval then
    if approvalsEnabled then .pendingApproval else .refuse
  else
    .direct

/-- V-A26 safety half: a declared irreversible/partially-reversible action can
never receive direct execution authority, regardless of approval posture. -/
theorem declared_human_floor_never_direct
    (approvalsEnabled : Bool) :
    decideCriticalGate approvalsEnabled .humanFloor ≠ .direct := by
  cases approvalsEnabled <;> simp [decideCriticalGate,
    IrreversibilityResolution.automaticallyRequiresApproval]

/-- A catalog outage is also never direct authority: it either enters the
approval path or refuses when approvals are disabled. -/
theorem unavailable_catalog_never_direct
    (approvalsEnabled : Bool) :
    decideCriticalGate approvalsEnabled .unavailable ≠ .direct := by
  cases approvalsEnabled <;> simp [decideCriticalGate,
    IrreversibilityResolution.automaticallyRequiresApproval]

/-- If criticality permits a direct path, the trusted snapshot did not classify
the action as human-floor and the catalog was not unavailable. -/
theorem direct_excludes_human_floor_and_unavailable
    {approvalsEnabled : Bool} {resolution : IrreversibilityResolution}
    (direct : decideCriticalGate approvalsEnabled resolution = .direct) :
    resolution ≠ .humanFloor ∧ resolution ≠ .unavailable := by
  cases approvalsEnabled <;> cases resolution <;>
    simp [decideCriticalGate,
      IrreversibilityResolution.automaticallyRequiresApproval] at direct ⊢

end Vultrino.Approval
