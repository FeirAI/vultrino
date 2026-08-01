namespace Vultrino.Approval.ActionAuthority

/-!
The V-A7 action-namespace partition at approval open.

A business label may resolve to a canonical plugin verb shared by several
labels. If a caller presents only the canonical verb, the label (and therefore
the authoritative Govder gate key) has been erased. The runtime may accept an
exact rule filed under that canonical key; otherwise it refuses rather than
falling back to a weaker numeric approval.
-/

inductive RuleLookup where
  | authoritativeRule
  | confirmedAbsent
  | inconclusive
deriving DecidableEq, Repr

inductive ApprovalOpenAuthority where
  | authoritativeRule
  | numericFallback
  | refuse
deriving DecidableEq, Repr

def decideAuthority
    (presentedAsLabel canonicalHasLabels : Bool)
    (lookup : RuleLookup) : ApprovalOpenAuthority :=
  match lookup with
  | .authoritativeRule => .authoritativeRule
  | .confirmedAbsent | .inconclusive =>
      if !presentedAsLabel && canonicalHasLabels then
        .refuse
      else
        .numericFallback

/-- V-A7: erasing a configured business label cannot turn an absent exact rule
into a numeric-approval grant. -/
theorem canonical_alias_without_rule_is_refused :
    decideAuthority false true .confirmedAbsent = .refuse := by
  rfl

/-- An inconclusive canonical lookup has the same fail-closed result. -/
theorem canonical_alias_inconclusive_is_refused :
    decideAuthority false true .inconclusive = .refuse := by
  rfl

/-- A rule explicitly filed under the canonical key remains authoritative; the
ambiguity guard does not convert a real rule into an availability failure. -/
theorem exact_canonical_rule_remains_authoritative :
    decideAuthority false true .authoritativeRule = .authoritativeRule := by
  rfl

end Vultrino.Approval.ActionAuthority
