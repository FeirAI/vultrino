import Vultrino.Types

namespace Vultrino.Credentials

abbrev SecretValue := String
abbrev SecretForm := List Char

/-- The complete sink taxonomy at the credential boundary. -/
inductive Sink where
  | encryptedVault
  | trustedInjector
  | authorizedUpstream
  | agentResponse
  | mcpResponse
  | httpResponse
  | log
  | error
  | audit
  | metrics
  | untrustedPlugin
deriving DecidableEq, Repr

def Sink.trusted : Sink → Prop
  | .encryptedVault | .trustedInjector | .authorizedUpstream => True
  | _ => False

/-- Exact byte-form containment used by the finite egress guarantee. -/
def containsForm (form : SecretForm) (bytes : String) : Prop :=
  form <:+: bytes.toList

/--
Public bytes are admitted only with evidence that none of the declared raw or
derived secret forms occurs. If the declaration includes an empty form, this
type is intentionally uninhabitable: the safe response is to withhold output.
-/
structure PublicPayload (secretForms : List SecretForm) where
  bytes : String
  excludesDeclaredSecrets :
    ∀ form, form ∈ secretForms → ¬ containsForm form bytes

inductive Payload (secretForms : List SecretForm) where
  | rawCredential (value : SecretValue)
  | sanitized (value : PublicPayload secretForms)

structure Flow (secretForms : List SecretForm) where
  sink : Sink
  payload : Payload secretForms

def Flow.confined (flow : Flow secretForms) : Prop :=
  match flow.payload with
  | .rawCredential _ => flow.sink.trusted
  | .sanitized _ => True

/--
The small capability vocabulary exposed by the modeled credential kernel.
There is deliberately no operation that pairs raw credentials with a public or
plugin sink.
-/
inductive Operation (secretForms : List SecretForm) where
  | persistEncrypted (value : SecretValue)
  | injectAtTrustedBoundary (value : SecretValue)
  | sendToAuthorizedUpstream (value : SecretValue)
  | respondToAgent (value : PublicPayload secretForms)
  | respondToMcp (value : PublicPayload secretForms)
  | respondToHttp (value : PublicPayload secretForms)
  | writeLog (value : PublicPayload secretForms)
  | returnError (value : PublicPayload secretForms)
  | writeAudit (value : PublicPayload secretForms)
  | writeMetrics (value : PublicPayload secretForms)
  | callUntrustedPlugin (value : PublicPayload secretForms)

def route : Operation secretForms → Flow secretForms
  | .persistEncrypted value => ⟨.encryptedVault, .rawCredential value⟩
  | .injectAtTrustedBoundary value => ⟨.trustedInjector, .rawCredential value⟩
  | .sendToAuthorizedUpstream value => ⟨.authorizedUpstream, .rawCredential value⟩
  | .respondToAgent value => ⟨.agentResponse, .sanitized value⟩
  | .respondToMcp value => ⟨.mcpResponse, .sanitized value⟩
  | .respondToHttp value => ⟨.httpResponse, .sanitized value⟩
  | .writeLog value => ⟨.log, .sanitized value⟩
  | .returnError value => ⟨.error, .sanitized value⟩
  | .writeAudit value => ⟨.audit, .sanitized value⟩
  | .writeMetrics value => ⟨.metrics, .sanitized value⟩
  | .callUntrustedPlugin value => ⟨.untrustedPlugin, .sanitized value⟩

/-- Every operation in the capability vocabulary preserves confinement. -/
theorem route_confined (operation : Operation secretForms) :
    (route operation).confined := by
  cases operation <;> simp [route, Flow.confined, Sink.trusted]

structure State (secretForms : List SecretForm) where
  flows : List (Flow secretForms) := []

inductive Step (secretForms : List SecretForm) :
    State secretForms → State secretForms → Prop where
  | apply (state : State secretForms) (operation : Operation secretForms) :
      Step secretForms state { flows := route operation :: state.flows }
  | administrative (state : State secretForms) : Step secretForms state state

inductive Reachable (secretForms : List SecretForm) : State secretForms → Prop where
  | initial : Reachable secretForms { flows := [] }
  | next {before after : State secretForms} :
      Reachable secretForms before →
      Step secretForms before after →
      Reachable secretForms after

/-- Main credential theorem: no reachable raw credential flow has a low sink. -/
theorem reachable_credentials_are_confined
    {secretForms : List SecretForm} {state : State secretForms}
    (reachable : Reachable secretForms state) :
    ∀ flow ∈ state.flows, flow.confined := by
  induction reachable with
  | initial => simp
  | next reachable step inductionHypothesis =>
      cases step with
      | apply operation =>
          intro candidate member
          simp only [List.mem_cons] at member
          cases member with
          | inl isHead =>
              subst candidate
              exact route_confined operation
          | inr inTail =>
              exact inductionHypothesis candidate inTail
      | administrative =>
          exact inductionHypothesis

/-- Public-payload evidence exposes the exact finite guarantee to consumers. -/
theorem public_payload_excludes_every_declared_form
    {secretForms : List SecretForm}
    (payload : PublicPayload secretForms) :
    ∀ form, form ∈ secretForms → ¬ containsForm form payload.bytes :=
  payload.excludesDeclaredSecrets

/-!
Streaming requires a stronger boundary than checking each transport chunk in
isolation: the suffix of one chunk and prefix of the next can jointly form a
secret. `StreamState.bytes` is therefore the complete released byte sequence,
and `admitChunk` checks the concatenation before constructing the next state.
The Rust adapter implements this specification with an equivalent bounded-tail
check because every declared form has a finite maximum length.
-/

def excludesAll (secretForms : List SecretForm) (bytes : List Char) : Prop :=
  ∀ form, form ∈ secretForms → ¬ form <:+: bytes

/-- The exact suffix retained by the Rust streaming output gate. -/
def retainedTail (released : List Char) (maxFormLength : Nat) : List Char :=
  released.drop (released.length - (maxFormLength - 1))

theorem retained_tail_covers_every_possible_crossing_start
    {part released : List Char} {maxFormLength : Nat}
    (partSuffix : part <:+ released)
    (partShort : part.length < maxFormLength) :
    part <:+ retainedTail released maxFormLength := by
  apply List.suffix_of_suffix_length_le partSuffix
    (List.drop_suffix (released.length - (maxFormLength - 1)) released)
  rw [List.length_drop, Nat.sub_sub_eq_min]
  have partFitsReleased := partSuffix.length_le
  exact Nat.le_min.mpr ⟨partFitsReleased, Nat.le_sub_one_of_lt partShort⟩

/-- Checking only the retained suffix plus a candidate is equivalent to checking
the complete released stream for newly introduced occurrences. This discharges
the bounded-tail optimization used by `StreamScrubber::admit_output`. -/
theorem suffix_gate_preserves_stream_confinement
    {secretForms : List SecretForm}
    {released candidate : List Char}
    {maxFormLength : Nat}
    (bounded : ∀ form, form ∈ secretForms → form.length ≤ maxFormLength)
    (releasedSafe : excludesAll secretForms released)
    (boundarySafe :
      excludesAll secretForms (retainedTail released maxFormLength ++ candidate)) :
    excludesAll secretForms (released ++ candidate) := by
  intro form member contained
  rw [List.infix_append_iff_ne_nil] at contained
  rcases contained with inReleased | inCandidate | crossing
  · exact releasedSafe form member inReleased
  · exact boundarySafe form member (List.infix_append_of_infix_right inCandidate)
  · rcases crossing with
      ⟨left, right, leftNonempty, rightNonempty, formParts, leftSuffix, rightPrefix⟩
    have rightPositive : 0 < right.length := List.ne_nil_iff_length_pos.mp rightNonempty
    have formBound := bounded form member
    have leftShort : left.length < maxFormLength := by
      apply Nat.lt_of_lt_of_le _ formBound
      rw [formParts, List.length_append]
      exact Nat.lt_add_of_pos_right rightPositive
    have leftTail :=
      retained_tail_covers_every_possible_crossing_start leftSuffix leftShort
    apply boundarySafe form member
    rw [List.infix_append_iff_ne_nil]
    exact Or.inr (Or.inr
      ⟨left, right, leftNonempty, rightNonempty, formParts, leftTail, rightPrefix⟩)

structure DeclaredForms where
  values : List SecretForm
  nonempty : ∀ form, form ∈ values → form ≠ []

structure StreamState (secretForms : DeclaredForms) where
  bytes : List Char
  excludesDeclaredSecrets : excludesAll secretForms.values bytes

def emptyStream (secretForms : DeclaredForms) : StreamState secretForms where
  bytes := []
  excludesDeclaredSecrets := by
    intro form member contained
    exact secretForms.nonempty form member (List.infix_nil.mp contained)

/-- The proof-carrying streaming output gate. Unsafe candidates have no state. -/
noncomputable def admitChunk
    (state : StreamState secretForms)
    (candidate : List Char) : Option (StreamState secretForms) := by
  classical
  exact if safe : excludesAll secretForms.values (state.bytes ++ candidate) then
    some {
      bytes := state.bytes ++ candidate
      excludesDeclaredSecrets := safe
    }
  else
    none

/-- Every candidate accepted by the gate extends the exact released stream and
preserves absence of every declared secret across the chunk boundary. -/
theorem admitted_chunk_extends_stream_safely
    {state after : StreamState secretForms}
    {candidate : List Char}
    (admitted : admitChunk state candidate = some after) :
    after.bytes = state.bytes ++ candidate ∧
      excludesAll secretForms.values after.bytes := by
  classical
  unfold admitChunk at admitted
  split at admitted
  next safe =>
    simp only [Option.some.injEq] at admitted
    subst after
    exact ⟨rfl, safe⟩
  next notSafe => simp at admitted

/-- A candidate known to violate the whole-stream postcondition is refused. -/
theorem unsafe_chunk_is_rejected
    {state : StreamState secretForms}
    {candidate : List Char}
    (notSafe : ¬ excludesAll secretForms.values (state.bytes ++ candidate)) :
    admitChunk state candidate = none := by
  classical
  simp [admitChunk, notSafe]

inductive StreamReachable (secretForms : DeclaredForms) :
    StreamState secretForms → Prop where
  | initial : StreamReachable secretForms (emptyStream secretForms)
  | next {before after : StreamState secretForms} {candidate : List Char} :
      StreamReachable secretForms before →
      admitChunk before candidate = some after →
      StreamReachable secretForms after

/-- Universal stream theorem: arbitrary accepted chunking cannot reconstruct a
declared secret in the concatenated low-sink byte stream. -/
theorem reachable_public_stream_excludes_every_declared_form
    {state : StreamState secretForms}
    (_reachable : StreamReachable secretForms state) :
    excludesAll secretForms.values state.bytes :=
  state.excludesDeclaredSecrets

end Vultrino.Credentials
