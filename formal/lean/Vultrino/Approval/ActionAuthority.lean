namespace Vultrino.Approval.ActionAuthority

/-!
The V-A7 action-namespace partition and V-A9 recipe-authority continuity
conditions at approval open/resume.

A business label may resolve to a canonical plugin verb shared by several
labels. If a caller presents only the canonical verb, the label (and therefore
the authoritative Govder gate key) has been erased. The runtime may accept an
exact rule filed under that canonical key; otherwise it refuses rather than
falling back to a weaker numeric approval.

Production strict mode additionally treats an inconclusive Govder answer as a
refusal for every action, and a resumed approval must see the same normalized
recipe/risk authority snapshot that it satisfied at open.
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

/-!
The normalized rule authority frozen on an approval. The recipe and risk tier
are abstract semantic values here; the Rust refinement compares the parsed
structures directly, without relying on a hash.
-/
structure NormalizedRuleAuthority where
  recipe : Nat
  riskTier : Nat
  irreversible : Bool
deriving DecidableEq, Repr

inductive RecipeAuthoritySnapshot where
  | rule (authority : NormalizedRuleAuthority)
  | confirmedAbsent
  | inconclusive
deriving DecidableEq, Repr

/-- Whether this recipe-authority answer may open an approval. Compatibility
posture permits the historical reversible-action fallback; production strict
posture requires either an exact rule or authoritative confirmation of absence. -/
def recipeAuthorityAllowsOpen
    (strict : Bool) (snapshot : RecipeAuthoritySnapshot) : Bool :=
  match snapshot with
  | .inconclusive => !strict
  | .rule _ | .confirmedAbsent => true

/-- Resume authorization is the conjunction of (1) an answer that is permitted
under the current posture and (2) exact equality with the authority snapshot
frozen at approval-open. -/
def approvalRecipeStillAuthorizes
    (strict : Bool)
    (opened current : RecipeAuthoritySnapshot) : Bool :=
  recipeAuthorityAllowsOpen strict current && opened == current

/-- V-A9: production strict mode cannot infer a weaker numeric recipe from an
inconclusive lookup, even for a capability classified as reversible. -/
theorem strict_inconclusive_recipe_refuses_open :
    recipeAuthorityAllowsOpen true .inconclusive = false := by
  rfl

/-- Any recipe/risk authority change invalidates the approval that satisfied
the earlier snapshot. -/
theorem changed_recipe_authority_refuses_resume
    {strict : Bool} {opened current : RecipeAuthoritySnapshot}
    (changed : opened ≠ current) :
    approvalRecipeStillAuthorizes strict opened current = false := by
  simp [approvalRecipeStillAuthorizes, changed]

/-- A successful resume proves exact recipe-authority continuity from open to
the permit-minting check. -/
theorem recipe_resume_implies_same_authority
    {strict : Bool} {opened current : RecipeAuthoritySnapshot}
    (authorized : approvalRecipeStillAuthorizes strict opened current = true) :
    opened = current := by
  simp [approvalRecipeStillAuthorizes] at authorized
  exact authorized.2

/-- In production strict posture, a successful resume also proves that the
current authority was conclusive. -/
theorem strict_recipe_resume_implies_conclusive_authority
    {opened current : RecipeAuthoritySnapshot}
    (authorized : approvalRecipeStillAuthorizes true opened current = true) :
    current ≠ .inconclusive := by
  cases current <;> simp [approvalRecipeStillAuthorizes,
    recipeAuthorityAllowsOpen] at authorized ⊢

/-!
An approval also freezes the concrete persisted credential revision that its
alias resolved to.  `recordId`, `revision`, and `kind` abstract Rust's id,
created/updated timestamps, and credential type; `tenant` is retained
separately because it has its own authorization predicate.  The model contains
no credential bytes or secret-derived digest.
-/
structure CredentialAuthoritySnapshot where
  recordId : Nat
  revision : Nat
  kind : Nat
  tenant : Option Nat
deriving DecidableEq, Repr

/-- A global principal may act on every tenant; a tenant principal may act on
its own tenant or on an explicitly shared credential. -/
def tenantMayAct (acting resource : Option Nat) : Bool :=
  match acting, resource with
  | none, _ => true
  | some _, none => true
  | some a, some r => a == r

/-- Resume requires a present open-time snapshot, a present current record,
exact revision equality, and current tenant authorization.  Missing legacy
authority is refusal in every posture. -/
def approvalCredentialStillAuthorizes
    (acting : Option Nat)
    (opened current : Option CredentialAuthoritySnapshot) : Bool :=
  match opened, current with
  | some old, some now => old == now && tenantMayAct acting now.tenant
  | _, _ => false

/-- A legacy approval with no credential authority cannot execute against any
current record. -/
theorem missing_credential_authority_refuses_resume
    {acting : Option Nat} {current : Option CredentialAuthoritySnapshot} :
    approvalCredentialStillAuthorizes acting none current = false := by
  cases current <;> rfl

/-- Delete/recreate, type change, revision change, or tenant change invalidates
the old approval before permit issuance. -/
theorem changed_credential_authority_refuses_resume
    {acting : Option Nat} {opened current : CredentialAuthoritySnapshot}
    (changed : opened ≠ current) :
    approvalCredentialStillAuthorizes acting (some opened) (some current) = false := by
  simp [approvalCredentialStillAuthorizes, changed]

/-- Successful resume proves exact concrete credential continuity. -/
theorem credential_resume_implies_same_authority
    {acting : Option Nat}
    {opened current : Option CredentialAuthoritySnapshot}
    (authorized : approvalCredentialStillAuthorizes acting opened current = true) :
    opened = current := by
  cases opened with
  | none => simp [approvalCredentialStillAuthorizes] at authorized
  | some old =>
      cases current with
      | none => simp [approvalCredentialStillAuthorizes] at authorized
      | some now =>
          simp [approvalCredentialStillAuthorizes] at authorized
          exact congrArg some authorized.1

/-- Successful resume independently proves that the opener remains authorized
for the current credential tenant. -/
theorem credential_resume_preserves_tenant_authority
    {acting : Option Nat}
    {opened current : Option CredentialAuthoritySnapshot}
    (authorized : approvalCredentialStillAuthorizes acting opened current = true) :
    ∃ authority, current = some authority ∧ tenantMayAct acting authority.tenant = true := by
  cases opened with
  | none => simp [approvalCredentialStillAuthorizes] at authorized
  | some old =>
      cases current with
      | none => simp [approvalCredentialStillAuthorizes] at authorized
      | some now =>
          simp [approvalCredentialStillAuthorizes] at authorized
          exact ⟨now, rfl, authorized.2⟩

end Vultrino.Approval.ActionAuthority
