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
- issued no later than execution, unexpired, and unconsumed. The separate
  `reachable_approval_consumption_is_one_shot` theorem proves that consumed
  exact-request bindings never repeat in any reachable trace.

`Credentials.reachable_credentials_are_confined` proves, by induction over
every reachable credential-flow trace, that raw credential material reaches
only the encrypted vault, the private injector, or the specifically authorized
upstream. Agent, MCP, HTTP, log, error, audit, metrics, and untrusted-plugin
sinks accept only a `PublicPayload` carrying evidence that every declared
secret byte-form is absent.

Both theorems are universal over traces; they are not bounded test sweeps.
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
- WASM ABI v2 serializes only an alias/type credential handle. ABI v1 modules,
  including the archived PGP fixture, fail installation and loading;
- plaintext `Secret` serialization requires a crate-private, dynamically scoped
  vault capability; refreshed credentials are neither public fields nor
  serializable response fields;
- buffered responses require a private `PublicResponse` confinement result,
  short secrets force whole-response withholding, streaming errors are generic,
  and post-dispatch connector diagnostics are either proven free of every
  declared credential form or discarded; and
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
- digest equality is exact in the model, but SHA-256 collision resistance and
  the producer's authentication of the rule digest are cryptographic/composition
  assumptions rather than theorems about the hash implementation;
- the async adapter linearizes claim/consume/finalize correctly. The pure Rust
  kernel, structural gate, and race tests constrain this seam, but do not prove
  Tokio/storage behavior refines the Lean transition relation;
- the incremental streaming scrubber implements the abstract public-payload
  predicate for all unbounded byte streams. It is supported by adversarial and
  property tests, while short or whole-body-policy cases fall back to the
  buffered confinement constructor.

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
| `Approval.Step.execute` | the single buffered/streaming dispatch seam |
| `Credentials.Operation` | built-ins are trusted declassification points; untrusted WASM receives only a handle |
| `PublicPayload` | fail-closed egress result whose constructor checks every declared form |
| `Credentials.Step.apply` | the only module allowed to expose raw secret bytes |

Aeneas evaluation is now isolated to the pure, safe Rust kernel. Tokio lock
linearization remains a separate proof/test obligation because the concurrent
adapter is outside that kernel.
