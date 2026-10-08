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
- a phrase from `overclaim_denylist` appears in `README.md`, `docs/**/*.md` or
  `formal/**/*.md`.

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
| `permit-kernel-tests` | test | the admission table over all 12 inputs (Allow, Deny or Prompt, observe downgrade, approval required) against a written table; a witness only with a judged subject; the direct permit's binding built from the witness; `authorize` refuses each single-field change of the recomputed binding (seven fields plus the approved flag) and an unbindable payload; the approved gate at the window edges | example and table tests, not a proof; the gate inputs (the policy decision, the observe downgrade, the server's approval requirement) are computed outside the kernel; the rule digest is not recomputed from the payload; not that every plugin dispatch needs a permit (only the structural refinement gate counts the two dispatch seams) |
| `kani-permit-kernel` | kani | the admission table over every input, with the witness kind; a direct permit copies the judged subject and kind into its binding; `authorize` succeeds exactly when the seven recomputed fields equal the permit's and the payload does not claim approved execution; the approved gate over every `i64` clock value; `next_epoch` never wraps | Kani sees only the kernel: not the `ActionPayload` recomputation, the policy engine or the grant derivation; each string field is drawn from two values; vacuity gate lives in `run-kani.sh`; nothing under `wasm-plugins` |
| `permit-binding-production` | test | with the real policy engine, approval grant derivation and `ActionPayload`: params changed after mint are refused on the direct and the approved path; a change to any bound payload field (credential alias, plugin, action, params, tenant, principal, approved flag, approval id or epoch) is refused; an enforced Deny never yields a direct witness; observe mode yields only the `ObservedDeny` kind and never for a kill switch or a resource guard; a Prompt or a server approval requirement goes to approval; a Deny at resume refuses | the tests call the mint and authorize functions, not `prepare_execution` or `resume_approved` (integration tests run those, and one full-tier mutant uses them); truth of the gate inputs; the binding's action is the canonical action the server resolved from the presented label, which the evaluation judged (not checked to correspond); code in `run_action` after `authorize` (unpacking the payload, building the plugin request) is not checked by the kernel; payload fields outside the binding (the credential record beyond its alias, use token id, evidence subject, evidence action, evidence requirement); the rule digest; the params bytes as the approver saw them |
| `recipe-unit-tests` | test | agent-reviewer terms unsatisfiable, over-cap counts unsatisfiable, one key cannot fabricate slots | other recipe shapes, sign-off collection, agreement with govder |
| `kani-recipe-safety` | kani | symbolic three-term recipes plus fixed malformed shapes: no satisfaction with zero approvers, no underfill, malformed never satisfied, cap prevents overflow | recipes beyond 3 terms or the harness bounds; separation of duties |
| `kani-recipe-greedy` | kani | greedy assignment equals exhaustive search at bound 5, monotone, slot contribution agrees | counts beyond bound 5; reference written in the same module |
| `ssrf-special-purpose` | test | first and last address of each hand-transcribed not-globally-reachable registry row blocked, neighbours reachable, embedded IPv4 decoded | exhaustive address space; hand-copied registry rows; constants are not drift-locked; DNS rebinding |
| `policy-precedence-exhaustive` | exhaustive | the lazy tier scan the engine runs (kill check, then deny, prompt, allow, stopping at the first match) equals the pure precedence function kill > deny > prompt > allow > policy default > engine default for every sequence of up to 4 rule outcomes (all orders), up to 3 policy defaults and both engine defaults, and asks no weaker tier; the pure function is order independent and never reaches its fail-closed tail; every verdict maps to its decision and the tail denies; the shipped `evaluate` equals the order for every ordered pair of policies from 48 shapes | rule matching itself (URL, method, time, rate, spend conditions); the engine test uses only always-matching rules; which rule wins inside a tier follows storage order; the oracles are test code |
| `kani-policy-precedence` | kani | the pure function over symbolic outcome lists (up to 4) and defaults (up to 3): the verdict has the highest rank any source offers, swapping entries does not change it, the tail is not reached; and the lazy scan returns the same verdict and asks no tier under a kill flag | the bounds; nothing about rule matching, the verdict mapping or the engine code that supplies the matcher; the rank table is written in the harness |
| `rate-limit-default-deny-validation` | test | `Policy::validate` refuses a policy with a `RateLimit` at any depth unless its default action is deny, and an exhausted Allow-`RateLimit` rule falls through to the policy default when no other rule matches | policies already stored in the vault are not re-validated on load; the engine itself does not validate; layered rate limits are still first-match; another matching allow rule still allows an over-limit request |
| `policy-refresh-ordering` | test | a stale refresh cannot overwrite a newer admin reload (async load lock plus ticket compare), and a refresh that took its ticket first still applies another process's kill policy, in two scripted interleavings | all schedules; cross-process visibility is bounded-staleness; ticket compare alone is not tested |
| `rate-limiter-vectors` | test (golden trace) | limiter transition reproduces the committed trace fixture; invalid limiter denies | the fixture is generated by the code it checks; no cross-repo agreement on main |
| `sb02-minted-scrub` | test | credentials minted during an action are scrubbed or the response withheld, buffered and streamed | other encodings and types; server dispatch code is not drift-locked; plugin error-path residual |
| `sb04-approval-key` | test | verified approver decisions need a dedicated key distinct from the shared govder key | route-level 403 is outside the detector; key strength and distribution |
| `refinement-structural` | test | source-shape checks only: binding field list equals the Lean field list, seams and strings present | semantic refinement; it greps strings and counts call sites |
| `lean-approval-execution` | lean | model-level: reachable executions are authorized and the consumed-binding list has no duplicates | the Rust code; the model is hand-written; nanoda check is not in the detector; `reachable_execution_is_proper` holds by construction (an Execution carries its permit), so it says nothing about the transition system; one-shot is per binding, which includes the epoch, and Rust mints a fresh epoch per claim, so it is not at most one execution per approval id |
| `recipe-shared-vectors` | differential-vectors | `recipe_satisfied` matches the committed vector file shared byte for byte with govder | agreement only on the committed vectors and sweep domain; the govder half runs only in govder CI |
| `recipe-sweeps-exhaustive` | exhaustive | `recipe_satisfied` equals an independent matching oracle on three committed sweeps; the oracle discriminates | the sweep domains only; the oracle is test code |
| `recipe-greedy-optimal-real-cap` | exhaustive | senior-first greedy equals split search on 9,628,905 points at the real cap of 64 | one senior and one teammate term, no agent-reviewer slots; availability above 65 is argued, not enumerated |
| `approval-lifecycle-table` | exhaustive | `transition` matches a legality oracle on 720 states including guard order | only those 720 states; no recipe-gated sequences; oracle is test code |
| `approval-wire-tables` | test | risk-tier, approver-class, decision-mode and execution-state tables enumerated over their listed spellings and 80 state combinations | strings outside the lists; callers' use of these functions |
| `approval-vault-roundtrip-property` | property | 20,000 generated decision sequences stay valid and round-trip unchanged through the vault serde boundary | sampling, not exhaustive; sequences are at most 6 long; shared defects pass |
| `ssrf-link-local-config-check` | test | `llm.provider_base` is rejected at config time for link-local and metadata addresses in many spellings | one example test; DNS names, redirects, later changes |
| `internal-http-allowlist` | test | on listed addresses, `internal_http` admits the internal examples and refuses metadata endpoints and encodings | listed addresses only; hostname resolution; per-capability allowlists |
| `lean-approval-authority` | lean | model-level: verified broker identity is exact-bound; changed tuples are rejected; bearer claims are not independent | MAC and parser (assumptions); the Rust code; the theorems unfold their own definitions |
| `lean-approval-action-authority` | lean | model-level: canonical-alias refusal, strict inconclusive refusal, resume requires same recipe and credential authority | abstract numbers stand in for recipes and records; the Rust code |
| `lean-approval-criticality` | lean | model-level: human-floor, ambiguous and unavailable never direct; strict direct implies reversible; resume needs same catalog class | criticality only, not the other gate checks; the Rust code |
| `lean-credential-confinement` | lean | model-level: raw credentials reach only trusted sinks; accepted stream chunks keep declared forms out; retained tail suffices | only declared secret forms; the Rust scrubber |
| `lean-method-authority` | lean | model-level: composed method is the operator's, caller verbs are rejected | registration validation; plugin behaviour |
| `lean-startup-refusal` | lean | model-level: web startup requires strict catalog, policy-hash key and valid verifier | whether the Rust code feeds and calls the decision correctly |
| `lean-approval-recipe-model` | lean | model-level: supported recipes are human-only and non-empty; agent-reviewer recipes are unsatisfiable | execution theorems (separate claim); how sign-offs are derived; the floor theorem follows from the definition of a supported recipe and does not use risk tier, autonomy or irreversibility |
| `argon2-kdf-known-answer` | test | `derive_key` on argon2 0.6 decrypts AES-GCM blobs sealed under keys argon2 0.5.3 derived for three fixed cases (default cost; non-default cost with a non-ASCII password; empty password with an 8-byte salt); a vault file written by 0.5.3 opens with and without its `kdf` header; a new vault persists m=19456 KiB, t=2, p=1 | only those cases, not every password, salt or cost; the fixtures come from this repository's own 0.5.3 build, not published Argon2 vectors; key equality is inferred from AES-GCM authentication, not compared byte by byte; salts longer than 48 bytes (rejected by 0.5.3, accepted by 0.6) and shorter than 8 bytes are not tested; admin passwords (bcrypt) and API keys (SHA-256) are not covered; not the AES-GCM layer, file format or rekey |

## Known gaps

- No fuzz targets or TLA+ models exist in this repository, so none are registered.
- Registered evidence still has gaps. The drift locks do not cover the constants
  `IPV4_BLOCKED` and `IPV6_BLOCKED`, the server dispatch code that extends the
  scrub set, or the `api_decide_approval` route. Other stage-1 tests in
  `src/approval/stage1_proofs.rs` (for example the policy-precedence table and the
  grant-witness tests) run in CI but are not registered. Mutants are single
  hand-written changes, not an exhaustive mutation campaign.
- Not registered: the proptest `egress::tests::streamed_scrub_equals_buffered` (streamed scrubbing equals buffered scrubbing for any chunk split, for one fixed secret in raw form only; VUL-10 is the stronger target), and the route-level SB-04 tests in `tests/web_smoke.rs`.
- Several Lean theorems follow directly from the definitions they are about
  (`reachable_execution_is_proper`, `supported_recipe_satisfies_every_floor` and
  the `Authority` theorems). They pin those definitions against change; they do
  not derive a property of a transition system or of the Rust code.
- The Kani vacuity (cover) gate is enforced by `formal/run-kani.sh` in the `kani`
  job, not by the mutation detectors.
- The phrase list in `overclaim_denylist` is seeded from claim styles this
  repository should not use and from wording that earlier documentation
  downgrades removed (the list itself is in `formal/claims.json`, which is not
  scanned). Phrases such as "fails closed" are used widely and
  legitimately for specific code paths, so they are not on the list.
