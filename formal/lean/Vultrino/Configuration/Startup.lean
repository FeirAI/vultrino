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
  policyHashConfigured : Bool
  workloadVerifier : WorkloadVerifier
deriving DecidableEq, Repr

inductive StartupDecision where
  | start
  | refuse
deriving DecidableEq, Repr

/-- The production `vultrino web` startup decision, before vault or listener. -/
def decideWebStartup (inputs : WebSecurityInputs) : StartupDecision :=
  if inputs.policyHashConfigured = false then
    .refuse
  else if inputs.workloadVerifier = .invalid then
    .refuse
  else
    .start

theorem web_start_implies_policy_hash_configured
    {inputs : WebSecurityInputs}
    (started : decideWebStartup inputs = .start) :
    inputs.policyHashConfigured = true := by
  cases policy : inputs.policyHashConfigured <;>
    simp [decideWebStartup, policy] at started ⊢

theorem enabled_exchange_start_implies_valid_verifier
    {inputs : WebSecurityInputs}
    (started : decideWebStartup inputs = .start)
    (enabled : inputs.workloadVerifier.enabled = true) :
    inputs.workloadVerifier.valid = true := by
  cases verifier : inputs.workloadVerifier with
  | disabled => simp [WorkloadVerifier.enabled, verifier] at enabled
  | configured => rfl
  | invalid => simp [decideWebStartup, verifier] at started

theorem invalid_security_config_refuses_before_listen
    {inputs : WebSecurityInputs}
    (invalid : inputs.policyHashConfigured = false ∨
      inputs.workloadVerifier = .invalid) :
    decideWebStartup inputs = .refuse := by
  rcases invalid with missingPolicy | invalidVerifier
  · simp [decideWebStartup, missingPolicy]
  · cases policy : inputs.policyHashConfigured <;>
      simp [decideWebStartup, policy, invalidVerifier]

end Vultrino.Configuration
