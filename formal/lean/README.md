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

## What is not yet proved

These are model theorems, not yet a refinement proof of the async Rust server.
The current Rust implementation does not satisfy the credential model:
`PluginRequest` owns a full `Credential`, and the WASM runtime serializes
`credential.data` into guest JSON. Until that boundary is changed to a
non-secret handle plus narrow trusted host capabilities, the honest system
claim is weaker than the Lean theorem.

The proof also makes these assumptions explicit:

- the authorized upstream is trusted with the credential. An upstream that can
  see a secret can encode it into status, timing, length, or response bytes;
  information-theoretic noninterference is impossible without suppressing all
  upstream-controlled observations;
- `secretForms` is the complete finite set promised by the implementation. The
  theorem covers exactly those forms, not arbitrary encryption, compression,
  hashing, or other transformations;
- cryptographic primitives, the OS/process boundary, allocator behavior,
  zeroization, and hardware side channels are in the trusted computing base;
- digest equality is exact in the model, but SHA-256 collision resistance and
  the producer's authentication of the rule digest are cryptographic/composition
  assumptions rather than theorems about the hash implementation;
- the async adapter linearizes claim/consume/finalize correctly. A pure Rust
  transition kernel and race tests must connect that implementation seam to the
  Lean state transition.

No production claim should say “credentials can never leak” until the Rust
refinement obligations above are discharged. The precise eventual claim is:
raw credential material never reaches a low sink, under the enumerated trusted
upstream, platform, cryptographic, and declared-transform assumptions.

## Refinement plan

| Lean object | Required Rust object / seam |
|---|---|
| `RequestBinding` | private `ExecutionBinding` containing the same eight fields |
| `ExecutionPermit` | non-cloneable, private-constructor `ExecutionPermit` consumed at the side-effect call |
| `Evidence.validFor` | one pure function run under the storage claim lock |
| `Approval.Step.execute` | the single buffered/streaming dispatch seam |
| `Credentials.Operation` | a sealed capability API; plugins receive handles, never `CredentialData` |
| `PublicPayload` | fail-closed egress result whose constructor checks every declared form |
| `Credentials.Step.apply` | the only module allowed to expose raw secret bytes |

Aeneas is intentionally deferred until this pure, safe Rust kernel exists. Its
documented translator does not cover concurrency or unsafe Rust, so Tokio lock
linearization remains a separate proof/test obligation.
