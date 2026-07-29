import Vultrino.Approval.Model

namespace Vultrino.Approval

/--
The only authority accepted by the modeled side-effect boundary. Both variants
carry their justification as proof fields; an approval-required request cannot
be represented by `direct`.
-/
inductive ExecutionPermit (request : Request) (now : Instant) : Type where
  | direct
      (policyAllows : request.policyAllows = true)
      (approvalNotRequired : request.requiresApproval = false)
  | approved
      (evidence : Evidence)
      (valid : Evidence.validFor evidence request now)

/-- The proposition promised to callers of the execution kernel. -/
def properlyAuthorized (request : Request) (now : Instant) : Prop :=
  request.policyAllows = true ∧
  (request.requiresApproval = false ∨
    ∃ evidence : Evidence, Evidence.validFor evidence request now)

/-- Possession of an execution permit entails proper authorization. -/
theorem ExecutionPermit.sound
    {request : Request} {now : Instant}
    (permit : ExecutionPermit request now) :
    properlyAuthorized request now := by
  cases permit with
  | direct policyAllows approvalNotRequired =>
      exact ⟨policyAllows, Or.inl approvalNotRequired⟩
  | approved evidence valid =>
      exact ⟨valid.1, Or.inr ⟨evidence, valid⟩⟩

/-- A side effect recorded by the modeled execution boundary. -/
structure Execution where
  request : Request
  now : Instant
  permit : ExecutionPermit request now

def Execution.proper (execution : Execution) : Prop :=
  properlyAuthorized execution.request execution.now

theorem Execution.proper_of_permit (execution : Execution) : execution.proper :=
  ExecutionPermit.sound execution.permit

/-- The state visible to the approval execution kernel. -/
structure State where
  executions : List Execution := []
  consumedApprovalBindings : List RequestBinding := []

def Execution.approvalBinding (execution : Execution) : Option RequestBinding :=
  match execution.permit with
  | .direct _ _ => none
  | .approved evidence _ => some evidence.binding

def State.canExecute (state : State) (execution : Execution) : Prop :=
  match execution.approvalBinding with
  | none => True
  | some binding => binding ∉ state.consumedApprovalBindings

def State.afterExecute (state : State) (execution : Execution) : State :=
  { executions := execution :: state.executions
    consumedApprovalBindings :=
      match execution.approvalBinding with
      | none => state.consumedApprovalBindings
      | some binding => binding :: state.consumedApprovalBindings }

/--
The only transition that appends a side effect requires an `ExecutionPermit`.
Administrative/no-op transitions can change no execution fact.
-/
inductive Step : State → State → Prop where
  | execute (state : State) (execution : Execution)
      (canExecute : state.canExecute execution) :
      Step state (state.afterExecute execution)
  | administrative (state : State) : Step state state

inductive Reachable : State → Prop where
  | initial : Reachable { executions := [], consumedApprovalBindings := [] }
  | next {before after : State} : Reachable before → Step before after → Reachable after

/--
Main approval theorem: every action in every reachable trace is properly
authorized. When approval is required, the existential evidence is exact-bound,
recipe-satisfying, fresh, and unconsumed by definition of `Evidence.validFor`.
-/
theorem reachable_execution_is_proper
    {state : State} (reachable : Reachable state) :
    ∀ execution ∈ state.executions, execution.proper := by
  induction reachable with
  | initial => simp
  | next reachable step inductionHypothesis =>
      cases step with
      | execute execution canExecute =>
          intro candidate member
          simp only [State.afterExecute, List.mem_cons] at member
          cases member with
          | inl isHead =>
              subst candidate
              exact Execution.proper_of_permit execution
          | inr inTail =>
              exact inductionHypothesis candidate inTail
      | administrative =>
          exact inductionHypothesis

/-- Every approved execution consumes a distinct exact request binding. -/
theorem reachable_approval_consumption_is_one_shot
    {state : State} (reachable : Reachable state) :
    state.consumedApprovalBindings.Nodup := by
  induction reachable with
  | initial => simp
  | next reachable step inductionHypothesis =>
      cases step with
      | administrative => exact inductionHypothesis
      | execute execution canExecute =>
          cases execution with
          | mk request now permit =>
              cases permit with
              | direct policyAllows approvalNotRequired =>
                  simpa [State.afterExecute, Execution.approvalBinding]
                    using inductionHypothesis
              | approved evidence valid =>
                  have fresh := canExecute
                  simp only [State.canExecute, Execution.approvalBinding] at fresh
                  simpa [State.afterExecute, Execution.approvalBinding]
                    using List.nodup_cons.mpr ⟨fresh, inductionHypothesis⟩

/-- A denied policy decision can never inhabit an execution permit. -/
theorem denied_request_has_no_permit
    {request : Request} {now : Instant}
    (denied : request.policyAllows = false) :
    ExecutionPermit request now → False := by
  intro permit
  have allowed := (ExecutionPermit.sound permit).1
  simp [denied] at allowed

/-- An approval-required permit necessarily carries valid persisted evidence. -/
theorem approval_required_permit_carries_valid_evidence
    {request : Request} {now : Instant}
    (required : request.requiresApproval = true)
    (permit : ExecutionPermit request now) :
    ∃ evidence : Evidence, Evidence.validFor evidence request now := by
  cases permit with
  | direct policyAllows approvalNotRequired =>
      simp [required] at approvalNotRequired
  | approved evidence valid =>
      exact ⟨evidence, valid⟩

end Vultrino.Approval
