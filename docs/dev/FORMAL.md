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
| `policy-refresh-ordering` | test | a stale refresh cannot overwrite a newer admin reload (async load lock plus ticket compare) in one scripted interleaving | all schedules; cross-process visibility is bounded-staleness; ticket compare alone is not tested |
| `rate-limiter-vectors` | test (golden trace) | limiter transition reproduces the committed trace fixture; invalid limiter denies | the fixture is generated by the code it checks; no cross-repo agreement on main |
| `sb02-minted-scrub` | test | credentials minted during an action are scrubbed or the response withheld, buffered and streamed | other encodings and types; server dispatch code is not drift-locked; plugin error-path residual |
| `sb04-approval-key` | test | verified approver decisions need a dedicated key distinct from the shared govder key | route-level 403 is outside the detector; key strength and distribution |
| `refinement-structural` | test | source-shape checks only: binding field list equals the Lean field list, seams and strings present | semantic refinement; it greps strings and counts call sites |
| `lean-approval-execution` | lean | model-level: reachable executions are authorized and the consumed-binding list has no duplicates | the Rust code; the model is hand-written; nanoda check is not in the detector; only `ExecutionSafety.lean` is registered |

## Known gaps

- No fuzz targets or TLA+ models exist in this repository, so none are registered.
- Existing evidence that is not registered yet: the cross-language recipe
  conformance suite `src/approval/recipe_conformance.rs` with its vector file
  `src/approval/testdata/recipe_vectors.json` (shared byte for byte with govder);
  the exhaustive and table tests in `src/approval/stage1_proofs.rs`; the Lean modules
  `Approval/Authority.lean`, `Approval/ActionAuthority.lean`,
  `Approval/Criticality.lean`, `Credentials/Confinement.lean`,
  `Action/MethodAuthority.lean`, `Configuration/Startup.lean` and the theorems in
  `Approval/Model.lean` (all model-level); the close-out SSRF tests
  `test_llm_validate_ssrf_narrowed_to_link_local` (config-time `llm.provider_base`
  check) and `internal_address_space_is_an_allowlist_and_excludes_metadata`
  (`internal_http` allowlist); and the second refresh race test
  `test_refresh_taking_ticket_first_still_applies_cross_process_kill_policy`.
  They still run in CI, but no claim, drift lock or mutant covers them.
- The Kani vacuity (cover) gate is enforced by `formal/run-kani.sh` in the `kani`
  job, not by the mutation detectors.
- The phrase list in `overclaim_denylist` is seeded from claim styles this
  repository should not use and from wording that earlier downgrades removed
  ("refinement gate prove", "gates prove enforcement"). Phrases such as "fails closed" are used widely and
  legitimately for specific code paths, so they are not on the list.
