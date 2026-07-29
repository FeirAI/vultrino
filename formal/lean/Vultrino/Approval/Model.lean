import Vultrino.Types

namespace Vultrino.Approval

/-- One conjunctive recipe from the authoritative rule. -/
structure Recipe where
  senior : Nat
  teammate : Nat
  agentReviewer : Nat
deriving DecidableEq, Repr

def maxRecipeTermCount : Nat := 64

/-- The parser/validator contract mirrored by the formal model. -/
def Recipe.wellFormed (recipe : Recipe) : Prop :=
  0 < recipe.senior + recipe.teammate + recipe.agentReviewer ∧
  recipe.senior + recipe.teammate + recipe.agentReviewer ≤ maxRecipeTermCount

/-- An authoritative rule is a disjunction of whole recipes. -/
structure Rule where
  recipes : List Recipe
  /-- Digest authenticated by the policy plane; hash soundness is a TCB assumption. -/
  digest : Digest
deriving DecidableEq, Repr

def Rule.wellFormed (rule : Rule) : Prop :=
  rule.recipes ≠ [] ∧ ∀ recipe ∈ rule.recipes, recipe.wellFormed

/--
The normalized sign-off set after identity and authority validation. The four
Boolean guards deliberately remain in the model: counts alone are insufficient
if an unnamed, duplicate, unresolved, or same-controller principal can enter
the set.
-/
structure SignoffSet where
  positive : Nat
  senior : Nat
  teammate : Nat
  agentReviewer : Nat
  allNamed : Bool
  allDistinct : Bool
  allAuthoritiesResolved : Bool
  controllerSeparationHolds : Bool
deriving DecidableEq, Repr

/-- The two approval modes implemented by Vultrino. -/
inductive Requirement where
  | numeric (need : Nat)
  | recipe (rule : Rule)
deriving DecidableEq, Repr

def Requirement.wellFormed : Requirement → Prop
  | .numeric need => 0 < need
  | .recipe rule => rule.wellFormed

/--
Senior reviewers may fill otherwise-unfilled teammate slots, but one senior may
not fill both slots. Agent-reviewer slots are a separate authority domain.
-/
def Recipe.satisfied (recipe : Recipe) (signoffs : SignoffSet) : Prop :=
  signoffs.allNamed = true ∧
  signoffs.allDistinct = true ∧
  signoffs.allAuthoritiesResolved = true ∧
  signoffs.controllerSeparationHolds = true ∧
  recipe.senior ≤ signoffs.senior ∧
  recipe.teammate ≤ signoffs.teammate + (signoffs.senior - recipe.senior) ∧
  recipe.agentReviewer ≤ signoffs.agentReviewer

/-- At least one complete authoritative recipe holds. Slots never mix recipes. -/
def Rule.satisfied (rule : Rule) (signoffs : SignoffSet) : Prop :=
  ∃ recipe, recipe ∈ rule.recipes ∧ recipe.satisfied signoffs

/-- Numeric M-of-N and recipe approval share the same named/distinct evidence floor. -/
def Requirement.satisfied : Requirement → SignoffSet → Prop
  | .numeric need, signoffs =>
      signoffs.allNamed = true ∧
      signoffs.allDistinct = true ∧
      signoffs.controllerSeparationHolds = true ∧
      need ≤ signoffs.positive
  | .recipe rule, signoffs => rule.satisfied signoffs

/-- Persisted evidence from which an approval permit is re-derived. -/
structure Evidence where
  binding : RequestBinding
  requirement : Requirement
  requirementDigest : Digest
  signoffs : SignoffSet
  issuedAt : Instant
  expiresAt : Instant
  consumed : Bool
deriving DecidableEq, Repr

/--
The full approval predicate at the point of execution. It binds the grant to the
exact request and epoch, requires one whole recipe, and requires a fresh,
single-use grant.
-/
def Evidence.validFor (evidence : Evidence) (request : Request) (now : Instant) : Prop :=
  request.policyAllows = true ∧
  request.requiresApproval = true ∧
  evidence.binding = request.binding ∧
  evidence.requirementDigest = evidence.binding.ruleDigest ∧
  evidence.requirement.wellFormed ∧
  evidence.requirement.satisfied evidence.signoffs ∧
  evidence.consumed = false ∧
  evidence.issuedAt ≤ now ∧
  now < evidence.expiresAt

end Vultrino.Approval
