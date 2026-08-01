namespace Vultrino.Configuration

/-- Startup snapshot of the workload-exchange verifier. `invalid` means the
feature was enabled but its file/env value was absent, blank, unreadable, or had
an entry shorter than 32 bytes. -/
inductive WorkloadVerifier where
  | disabled
  | configured
  | invalid
deriving DecidableEq, Repr

def WorkloadVerifier.enabled : WorkloadVerifier → Bool
  | .disabled => false
  | .configured | .invalid => true

def WorkloadVerifier.valid : WorkloadVerifier → Bool
  | .configured => true
  | .disabled | .invalid => false

structure WebSecurityInputs where
  strictCatalog : Bool
  policyHashConfigured : Bool
  workloadVerifier : WorkloadVerifier
deriving DecidableEq, Repr

inductive StartupDecision where
  | start
  | refuse
deriving DecidableEq, Repr

/-- The production `vultrino web` startup decision, before vault or listener. -/
def decideWebStartup (inputs : WebSecurityInputs) : StartupDecision :=
  if inputs.strictCatalog = false then
    .refuse
  else if inputs.policyHashConfigured = false then
    .refuse
  else if inputs.workloadVerifier = .invalid then
    .refuse
  else
    .start

theorem web_start_implies_policy_hash_configured
    {inputs : WebSecurityInputs}
    (started : decideWebStartup inputs = .start) :
    inputs.policyHashConfigured = true := by
  cases strict : inputs.strictCatalog <;>
    cases policy : inputs.policyHashConfigured <;>
    simp [decideWebStartup, strict, policy] at started ⊢

/-- The network execution surface never starts in standalone compatibility
posture: every direct execution requires an exact reversible declaration. -/
theorem web_start_implies_strict_catalog
    {inputs : WebSecurityInputs}
    (started : decideWebStartup inputs = .start) :
    inputs.strictCatalog = true := by
  cases strict : inputs.strictCatalog <;>
    simp [decideWebStartup, strict] at started ⊢

theorem enabled_exchange_start_implies_valid_verifier
    {inputs : WebSecurityInputs}
    (started : decideWebStartup inputs = .start)
    (enabled : inputs.workloadVerifier.enabled = true) :
    inputs.workloadVerifier.valid = true := by
  cases strict : inputs.strictCatalog <;>
    cases verifier : inputs.workloadVerifier with
    | disabled => simp [WorkloadVerifier.enabled, verifier] at enabled
    | configured => rfl
    | invalid => simp [decideWebStartup, strict, verifier] at started

theorem invalid_security_config_refuses_before_listen
    {inputs : WebSecurityInputs}
    (invalid : inputs.strictCatalog = false ∨
      inputs.policyHashConfigured = false ∨
      inputs.workloadVerifier = .invalid) :
    decideWebStartup inputs = .refuse := by
  rcases invalid with nonStrict | missingPolicy | invalidVerifier
  · simp [decideWebStartup, nonStrict]
  · cases strict : inputs.strictCatalog <;>
      simp [decideWebStartup, strict, missingPolicy]
  · cases strict : inputs.strictCatalog <;>
      cases policy : inputs.policyHashConfigured <;>
      simp [decideWebStartup, strict, policy, invalidVerifier]

end Vultrino.Configuration
