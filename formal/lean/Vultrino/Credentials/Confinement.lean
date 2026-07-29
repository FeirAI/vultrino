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

end Vultrino.Credentials
