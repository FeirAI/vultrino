namespace Vultrino.Action.MethodAuthority

/-!
The enforcing half of V-A13 for named internal-HTTP capabilities. A valid
registration has exactly one operator method source: a fixed plugin parameter,
a singleton declared method, or both agreeing. The agent-facing call has no
authority to supply a method.
-/

inductive OperatorMethodSource where
  | pinned (method : String)
  | declared (method : String)
  | agreeing (method : String)
deriving DecidableEq, Repr

def OperatorMethodSource.method : OperatorMethodSource → String
  | .pinned method | .declared method | .agreeing method => method

/-- `none` represents the required agent request shape. Any caller-supplied
method is rejected before a plugin request can be constructed. -/
def composeMethod
    (source : OperatorMethodSource)
    (callerMethod : Option String) : Option String :=
  match callerMethod with
  | none => some source.method
  | some _ => none

/-- Every successfully composed method is exactly the operator's method and the
caller supplied no competing verb. -/
theorem successful_method_is_operator_method
    {source : OperatorMethodSource}
    {callerMethod : Option String}
    {executedMethod : String}
    (success : composeMethod source callerMethod = some executedMethod) :
    callerMethod = none ∧ executedMethod = source.method := by
  cases callerMethod with
  | none =>
      simp [composeMethod] at success
      exact ⟨rfl, success.symm⟩
  | some method =>
      simp [composeMethod] at success

/-- A caller-supplied method can never produce an executable plugin method. -/
theorem caller_method_is_rejected
    (source : OperatorMethodSource)
    (callerMethod : String) :
    composeMethod source (some callerMethod) = none := by
  rfl

end Vultrino.Action.MethodAuthority
