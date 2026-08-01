# Vultrino formal kernel

This directory is the machine-checked semantic model for Vultrino's two
critical enforcement boundaries. It uses the exact toolchain pinned in
`lean-toolchain` and has no third-party Lean dependencies.

Run:

```sh
cd formal/lean
lake build --wfail
bash check-nanoda.sh
```

## What is proved

`Approval.reachable_execution_is_proper` proves, by induction over every
reachable execution trace, that a recorded side effect is policy-allowed. If
the request requires approval, execution additionally carries persisted
evidence that is:

- bound to the exact approval id, execution epoch, tenant, principal,
  credential alias, action, parameter digest, and authoritative-rule digest;
- satisfied by one complete recipe rather than slots mixed across recipes;
- based only on named, distinct, authority-resolved sign-offs with the required
  controller separation; and
- unable to satisfy any recipe containing a disabled agent-reviewer term, so
  Govder-only D4(c)/(d)/(e) reviewer checks cannot be bypassed at this consumer; and
- restricted to a non-empty human-only recipe domain that
  `supported_recipe_satisfies_every_floor` proves remains valid for every current
  risk/autonomy/irreversibility floor; and
- issued no later than execution, unexpired, and unconsumed. The separate
  `reachable_approval_consumption_is_one_shot` theorem proves that consumed
  exact-request bindings never repeat in any reachable trace.

`Approval.Authority.verified_broker_identity_is_exact` proves that a broker
identity accepted through the stronger JSON-decision path has the exact tenant,
approval id, outcome, subject, approver class, method, path, query, host, and
body digest covered by its evidence. `changed_binding_rejected` proves that the
same evidence cannot validate any changed tuple. The model deliberately gives
plain bearer-key identity claims no independent-authentication witness, matching
the Rust rule that unsigned `agg:<key>:` identities can contribute at most one
positive recipe slot per key.

`Approval.ActionAuthority.canonical_alias_without_rule_is_refused` and its
inconclusive twin prove the V-A7 namespace partition: when a caller erases a
configured business label by presenting its shared canonical plugin verb, a
missing exact canonical rule cannot open the weaker numeric-approval path. An
exact rule filed under the canonical key remains authoritative.

`Action.MethodAuthority.successful_method_is_operator_method` proves that every
successfully composed named internal-HTTP capability request uses its unique
operator method source, while `caller_method_is_rejected` proves an agent-supplied
method never yields an executable plugin request.

`Configuration.web_start_implies_policy_hash_configured` proves that a started
production web process cannot have the policy-drift oracle disabled.
`enabled_exchange_start_implies_valid_verifier` proves that a started process
with workload exchange enabled has a configured, valid verifier snapshot; the
invalid state is a startup refusal before vault access or listener bind.

`Credentials.reachable_credentials_are_confined` proves, by induction over
every reachable credential-flow trace, that raw credential material reaches
only the encrypted vault, the private injector, or the specifically authorized
upstream. Agent, MCP, HTTP, log, error, audit, metrics, and untrusted-plugin
sinks accept only a `PublicPayload` carrying evidence that every declared
secret byte-form is absent.
`Credentials.reachable_public_stream_excludes_every_declared_form` separately
proves that this postcondition is preserved over the concatenation of arbitrary
accepted streaming chunks; checking chunks independently is intentionally not
enough because a forbidden form can cross a transport boundary.
`suffix_gate_preserves_stream_confinement` proves the bounded implementation
rule: retaining the last `max_form_len - 1` released bytes is sufficient to catch
every newly completed occurrence when that suffix is checked with the next
candidate.

The trace theorems are universal over traces; they are not bounded test sweeps.
The second command exports the complete environment and rechecks it with the
independently implemented nanoda kernel. Its exporter and checker revisions are
full-commit pinned, and `sorryAx` is deliberately not permitted.

## Rust refinement status

These remain model theorems, not a complete semantic refinement proof of the
async Rust server. The implementation now contains, however, a deliberately
small safe-Rust enforcement kernel and machine-enforced choke points matching
the model:

- `ExecutionBinding` contains the same eight fields as `RequestBinding`;
- a private, non-cloneable `ExecutionPermit` is minted only from a direct allow
  or a persisted exact-binding `Granted` witness and is consumed to produce the
  `Authorized<ActionPayload>` accepted by the only two dispatch variants;
- approval claims derive the epoch-bound grant while holding the vault lock and
  refuse epoch overflow;
- the approval JSON handler verifies any present broker assertion over the raw
  received bytes and actual route/Host before decoding authority-bearing fields;
  bad, expired, cross-tenant, over-five-minute, or request-mismatched assertions
  fail closed, while unsigned callers remain in the guarded `agg:<key>:` namespace;
- the production recipe evaluator hard-rejects every agent-reviewer term, matching
  `agent_reviewer_recipe_is_unsatisfiable` in the Lean model and the shared
  exhaustive Govder/Vultrino recipe vectors;
- action-label presentations query Govder under that exact label before the
  canonical verb; a canonical presentation whose verb is targeted by configured
  labels may use an exact canonical rule, but otherwise fails closed before the
  numeric-approval fallback;
- internal-HTTP capability registration requires one unambiguous method source;
  named tool calls reject a caller `method` before resolving and finally
  overwriting the plugin request with the operator method;
- the production web entrypoint validates the policy-hash secret and any enabled
  workload verifier before touching the vault, spawning workers, or binding; the
  verifier list is then held in `AppState` rather than reread per request;
- WASM ABI v2 serializes only an alias/type credential handle. ABI v1 modules,
  including the archived PGP fixture, fail installation and loading;
- plaintext `Secret` serialization requires a crate-private, dynamically scoped
  vault capability; refreshed credentials are neither public fields nor
  serializable response fields;
- buffered responses require a private `PublicResponse` confinement result and
  use a content-free fallback when no non-empty fixed diagnostic can satisfy the
  postcondition; short secrets force whole-response withholding; streamed
  headers, redaction output, and terminal frames receive a final declared-form
  check across output-chunk boundaries; and post-dispatch connector diagnostics
  are either proven free of every declared credential form or discarded; and
- the library security core forbids unsafe Rust.

The separate fixed-window limiter seam is extracted to the pure
`fixed_window_transition` used by production. A Rust test regenerates
`formal/vectors/rate_limiter_traces.json` through that function and compares it
byte-for-byte; the refinement checker pins SHA-256
`ab102718048eb7fd40d045daf1e5b1c0ab355361e0b5a7352e4cd7ed0f8b86ec`.
Govder consumes the identical fixture when checking its proved overshoot
formula. Invalid zero dimensions deny before creating counter state.

`formal/check-refinement.sh` is a structural drift gate over those exact Rust
objects and seams. Nine Kani harnesses check the direct-permit truth table,
prove execution-epoch increment cannot wrap, and discharge the planned P1–P7
recipe properties against the private production predicates (including explicit
unwind assertions). Property, unit, integration, race, and fault tests exercise
the adapter. These are meaningful implementation evidence; they are not a
substitute for a full Rust operational-semantics proof.

## What is not yet proved

The proof also makes these assumptions explicit:

- the trusted built-in connector and the specifically authorized upstream are
  allowed to receive the credential. An upstream can encode it into status,
  timing, length, or response bytes; information-theoretic noninterference is
  impossible without suppressing all upstream-controlled observations;
- `secretForms` is the complete finite set promised by the implementation. The
  theorem covers exactly those forms, not arbitrary encryption, compression,
  hashing, or other transformations;
- cryptographic primitives, the OS/process boundary, allocator behavior,
  zeroization, and hardware side channels are in the trusted computing base;
- the policy-hash secret remains stable across restarts and the workload verifier
  matches the trusted signer. Startup proves presence/shape and freezes one
  process snapshot; cross-process key ownership/alignment remains an operator
  obligation;
- a `verified:` approval identity means the holder of the configured shared
  broker/Govder assertion key signed the exact request. Correct authentication of
  the human ticket and immutable subject/group resolution inside that signer is a
  composition premise; the Lean theorem does not prove the IdP or HMAC primitive;
- digest equality is exact in the model, but SHA-256 collision resistance and
  the producer's authentication of the rule digest are cryptographic/composition
  assumptions rather than theorems about the hash implementation;
- the async adapter linearizes claim/consume/finalize correctly. The pure Rust
  kernel, structural gate, and race tests constrain this seam, but do not prove
  Tokio/storage behavior refines the Lean transition relation;
- that the Rust `StreamScrubber` refines the proved suffix-gate transition. The
  implementation retains the exact `max_form_len - 1` bound and rechecks that
  suffix plus every candidate; the structural gate and adversarial/property tests
  constrain this adapter seam, while short or whole-body-policy cases fall back
  to the buffered confinement constructor. This is not a full Rust
  operational-semantics proof.

No production claim should use an assumption-free “credentials can never
leak.” The precise claim being implemented and checked is: raw credential
material does not reach an agent-visible, MCP, HTTP-response, log, error, metric,
audit, or untrusted-WASM sink through the modeled execution paths, under the
enumerated trusted-connector, authorized-upstream, platform, cryptographic, and
declared-transform assumptions.

## Refinement plan

| Lean object | Required Rust object / seam |
|---|---|
| `RequestBinding` | private `ExecutionBinding` containing the same eight fields |
| `ExecutionPermit` | non-cloneable, private-constructor `ExecutionPermit` consumed at the side-effect call |
| `Evidence.validFor` | one pure function run under the storage claim lock |
| `Authority.AssertionEvidence.validFor` | inbound HMAC verifier over raw body plus actual tenant/method/path/query/Host, bounded to five minutes |
| `ActionAuthority.decideAuthority` | label-first exact Govder lookup plus canonical-label ambiguity refusal before numeric fallback |
| `Action.MethodAuthority.composeMethod` | registration-time method-source validation plus caller-method rejection and final operator pin in `build_internal_http_params` |
| `Configuration.decideWebStartup` | first operation in production `run_web_server` plus startup-snapshotted `WorkloadVerifier` in `AppState` |
| `Approval.Step.execute` | the single buffered/streaming dispatch seam |
| `Credentials.Operation` | built-ins are trusted declassification points; untrusted WASM receives only a handle |
| `PublicPayload` / `StreamState` | fail-closed buffered result and compositional streaming output gate checking every declared form |
| `Credentials.Step.apply` | the only module allowed to expose raw secret bytes |

Aeneas evaluation is now isolated to the pure, safe Rust kernel. Tokio lock
linearization remains a separate proof/test obligation because the concurrent
adapter is outside that kernel.
