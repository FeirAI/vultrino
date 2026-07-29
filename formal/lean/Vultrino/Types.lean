import Std

namespace Vultrino

/-! Opaque wire identities. Equality is deliberately exact and case-sensitive. -/

abbrev ApprovalId := String
abbrev Epoch := Nat
abbrev TenantId := String
abbrev PrincipalId := String
abbrev CredentialAlias := String
abbrev ActionName := String
abbrev Digest := String
abbrev Instant := Nat

/--
Everything an approval authorizes. Equality of this value is the exact-binding
obligation; adding a load-bearing execution field requires adding it here and in
the Rust refinement type.
-/
structure RequestBinding where
  approvalId : ApprovalId
  epoch : Epoch
  tenant : TenantId
  principal : PrincipalId
  credential : CredentialAlias
  action : ActionName
  paramsDigest : Digest
  ruleDigest : Digest
deriving DecidableEq, Repr

/-- The decision facts presented to the execution kernel. -/
structure Request where
  binding : RequestBinding
  policyAllows : Bool
  requiresApproval : Bool
deriving DecidableEq, Repr

end Vultrino
