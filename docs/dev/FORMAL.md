# Formal and test evidence register

`formal/claims.json` is the register of security claims that Vultrino backs with
a proof, a model-checking harness or a pinned test. It exists to keep those claims
bounded and to stop them drifting: each claim names the exact source it covers,
the command that checks it, a mutation that command must catch, and what the claim
does **not** establish.

This page describes the register. The proofs themselves are described in
[`formal/lean/README.md`](../../formal/lean/README.md) and
[LIMITATIONS.md](LIMITATIONS.md). The tooling is vendored, unchanged, from the
shared formal kit into `scripts/formal/` (see its `README.md` for the full schema
and limits).

## What the register checks

`python3 scripts/formal/check_claims.py` fails when:

- the file does not match the schema, or a claim id repeats;
- a listed artifact path does not exist, or a gate is not a CI job id;
- `ci-required` does not need exactly the unconditional jobs (the scheduled
  `formal-nightly` job has an `if:` and is deliberately outside it);
- the sha256 of a covered function no longer matches (the drift lock);
- a mutant id has no patch file;
- a phrase from `overclaim_denylist` appears in `README.md` or `docs/**/*.md`.

`python3 scripts/formal/check_mutants.py --tier fast|full` applies each mutant
patch to a scratch copy of HEAD, runs the claim's detector, and requires the
detector to fail. A mutant the detector does not catch (`SURVIVED`) means the gate
does not bite.

## CI

| Job | When | What |
|---|---|---|
| `formal-fast` | every push and pull request, required by `ci-required` | kit unit tests, `check_claims.py`, fast-tier mutants |
| `formal-nightly` | schedule and manual dispatch only | all mutants, including Kani and Lean ones; JSON report kept as an artifact for 90 days |

Fast-tier detectors run a fixed list of exact test names (`--exact`) with
`--no-default-features`, so they do not build wasmtime. Kani and Lean mutants are full tier because they need those
toolchains.

Only a CI run counts as evidence for a claim. Local runs are informative only.

## Adding a claim

1. Write the proof or test and make sure a CI job runs it.
2. Add the claim to `formal/claims.json` with `"sha256": ""` in each cover. Cover
   the functions the claim depends on, including callees that carry the property.
3. Write a mutant: change the covered code so the claim should be false, then
   `git diff -- <covered file> > formal/mutants/<id>.patch` and
   `git checkout -- <covered file>`. Name the file in both commands.
4. `python3 scripts/formal/check_claims.py --relock --symbol <path>:<symbol>`
   fills the empty hashes.
5. Commit, then `python3 scripts/formal/check_mutants.py --only <id>` must print
   `killed` (it tests HEAD, not the working tree).
6. Say in `does_not_establish` what remains unproven.

## Relock policy

A hash mismatch means a covered function changed after the claim was written.
Re-read the claim, decide whether it still holds, downgrade or remove it if not,
and only then relock, for the changed symbols only (`--relock --symbol ...`).
Never relock as a blanket step to turn CI green. The PR text must say which
symbols were relocked and why. A drift lock says the text is unchanged, not that
the claim is still true: a callee can change without changing the hash.

## Evidence of record

A claim is evidence only through a CI run. `evidence_run` may record the run id a
human last confirmed; nothing fetches it.

## Current claims

Every claim is bounded; read the last column before citing one.

| Claim | Method | What it checks | Does NOT establish |
|---|---|---|---|
| `permit-kernel-tests` | test | `ExecutionPermit::direct` refuses denial and approval-required; `authorize` refuses a binding with a different action | not `approved`, not that every dispatch site uses a permit; only the action field is substituted; two example tests |
| `kani-permit-kernel` | kani | `direct` truth table over both boolean inputs (one fixed binding) and `next_epoch` no-wrap over every `u64` | vacuity gate lives in `run-kani.sh`; pure functions only; nothing under `wasm-plugins` |
| `recipe-unit-tests` | test | agent-reviewer terms unsatisfiable, over-cap counts unsatisfiable, one key cannot fabricate slots | other recipe shapes, sign-off collection, agreement with govder |
| `kani-recipe-safety` | kani | symbolic three-term recipes plus fixed malformed shapes: no satisfaction with zero approvers, no underfill, malformed never satisfied, cap prevents overflow | recipes beyond 3 terms or the harness bounds; separation of duties |
| `kani-recipe-greedy` | kani | greedy assignment equals exhaustive search at bound 5, monotone, slot contribution agrees | counts beyond bound 5; reference written in the same module |
| `ssrf-special-purpose` | test | special-purpose IPv4/IPv6 table edges blocked, neighbours reachable, embedded IPv4 decoded | exhaustive address space; hand-copied registry rows; constants are not drift-locked; DNS rebinding |
| `policy-refresh-ordering` | test | a stale refresh cannot overwrite a newer admin reload (async load lock plus ticket compare), and a refresh that took its ticket first still applies another process's kill policy, in two scripted interleavings | all schedules; cross-process visibility is bounded-staleness; ticket compare alone is not tested |
| `rate-limiter-vectors` | test (golden trace) | limiter transition reproduces the committed trace fixture; invalid limiter denies | the fixture is generated by the code it checks; no cross-repo agreement on main |
| `sb02-minted-scrub` | test | credentials minted during an action are scrubbed or the response withheld, buffered and streamed | other encodings and types; server dispatch code is not drift-locked; plugin error-path residual |
| `sb04-approval-key` | test | verified approver decisions need a dedicated key distinct from the shared govder key | route-level 403 is outside the detector; key strength and distribution |
| `refinement-structural` | test | source-shape checks only: binding field list equals the Lean field list, seams and strings present | semantic refinement; it greps strings and counts call sites |
| `lean-approval-execution` | lean | model-level: reachable executions are authorized and the consumed-binding list has no duplicates | the Rust code; the model is hand-written; nanoda check is not in the detector |
| `recipe-shared-vectors` | differential-vectors | `recipe_satisfied` matches the committed vector file shared byte for byte with govder | agreement only on the committed vectors and sweep domain; the govder half runs only in govder CI |
| `recipe-sweeps-exhaustive` | exhaustive | `recipe_satisfied` equals an independent matching oracle on three committed sweeps; the oracle discriminates | the sweep domains only; the oracle is test code |
| `recipe-greedy-optimal-real-cap` | exhaustive | senior-first greedy equals split search on 9,628,905 points at the real cap of 64 | one senior and one teammate term, no agent-reviewer slots; availability above 65 is argued, not enumerated |
| `approval-lifecycle-table` | exhaustive | `transition` matches a legality oracle on 720 states including guard order; unnamed principals fill no slot | only those 720 states; no recipe-gated sequences; oracle is test code |
| `approval-wire-tables` | exhaustive | risk-tier, approver-class, decision-mode and execution-state tables enumerated over their listed spellings and 80 state combinations | strings outside the lists; callers' use of these functions |
| `approval-vault-roundtrip-property` | property | 20,000 generated decision sequences stay valid and round-trip unchanged through the vault serde boundary | sampling, not exhaustive; sequences are at most 6 long; shared defects pass |
| `ssrf-link-local-config-check` | test | `llm.provider_base` is rejected at config time for link-local and metadata addresses in many spellings | one example test; DNS names, redirects, later changes |
| `internal-http-allowlist` | test | `internal_http` admits only the listed internal ranges and refuses metadata endpoints and encodings | listed addresses only; hostname resolution; per-capability allowlists |
| `lean-approval-authority` | lean | model-level: verified broker identity is exact-bound; changed tuples are rejected; bearer claims are not independent | MAC and parser (assumptions); the Rust code |
| `lean-approval-action-authority` | lean | model-level: canonical-alias refusal, strict inconclusive refusal, resume requires same recipe and credential authority | abstract numbers stand in for recipes and records; the Rust code |
| `lean-approval-criticality` | lean | model-level: human-floor, ambiguous and unavailable never direct; strict direct implies reversible; resume needs same catalog class | criticality only, not the other gate checks; the Rust code |
| `lean-credential-confinement` | lean | model-level: raw credentials reach only trusted sinks; accepted stream chunks keep declared forms out; retained tail suffices | only declared secret forms; the Rust scrubber |
| `lean-method-authority` | lean | model-level: composed method is the operator's, caller verbs are rejected | registration validation; plugin behaviour |
| `lean-startup-refusal` | lean | model-level: web startup requires strict catalog, policy-hash key and valid verifier | whether the Rust code feeds and calls the decision correctly |
| `lean-approval-recipe-model` | lean | model-level: supported recipes are human-only and non-empty; agent-reviewer recipes are unsatisfiable | execution theorems (separate claim); how sign-offs are derived |


## Known gaps

- No fuzz targets or TLA+ models exist in this repository, so none are registered.
- Registered evidence still has gaps. The drift locks do not cover the constants
  `IPV4_BLOCKED` and `IPV6_BLOCKED`, the server dispatch code that extends the
  scrub set, or the `api_decide_approval` route. Other stage-1 tests in
  `src/approval/stage1_proofs.rs` (for example the policy-precedence table and the
  grant-witness tests) run in CI but are not registered. Mutants are single
  hand-written changes, not an exhaustive mutation campaign.
- The Kani vacuity (cover) gate is enforced by `formal/run-kani.sh` in the `kani`
  job, not by the mutation detectors.
- The phrase list in `overclaim_denylist` is seeded from claim styles this
  repository should not use and from wording that earlier documentation
  downgrades removed (the list itself is in `formal/claims.json`, which is not
  scanned). Phrases such as "fails closed" are used widely and
  legitimately for specific code paths, so they are not on the list.
