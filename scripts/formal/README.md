# Formal kit

Shared tooling that keeps a repository's formal-verification claims honest.
Python 3 standard library only (tests pass on 3.9, 3.12 and 3.14). Each repo vendors a copy into
`scripts/formal/` (the four files below plus `tests/`).

| File | Purpose |
|---|---|
| `formal_kit.py` | library: workflow reader, symbol extractor, schema validation |
| `check_claims.py` | validates `formal/claims.json` against the repo |
| `check_mutants.py` | runs the mutants and requires each to be killed |
| `tests/` | `python3 -m unittest discover -s scripts/formal/tests` |

## claims.json schema (version 1)

```json
{
  "schema": 1,
  "overclaim_denylist": {"phrases": ["guaranteed secure"], "globs": ["docs/**/*.md", "README.md"]},
  "ci_required_exempt": [{"job": "lint", "reason": "advisory, not merge-blocking"}],
  "ci_required_conditional": [{"job": "frontend-browser", "reason": "path filtered; the gate accepts a skip only when the filter said so"}],
  "mutants": {"add-sub": {"tier": "fast", "claim": "add-sum", "detector": "optional own command"}},
  "claims": [{
    "id": "add-sum",
    "statement": "Add returns the sum of its arguments for in-range inputs.",
    "method": "test",
    "artifacts": ["p.go", "formal/add.lean"],
    "gates": ["go"],
    "detector": "go test ./... -run TestAdd",
    "covers": [{"path": "p.go", "symbol": "Add", "sha256": "<hex>"}],
    "mutants": ["add-sub"],
    "evidence_run": "1234567890",
    "does_not_establish": "Overflow behaviour; anything outside p.go."
  }]
}
```

* `method` is one of: lean, kani, tla, aeneas, exhaustive, differential-vectors, fuzz, property, mutation, e2e, test.
* `gates` are CI job ids that exist in some workflow under `.github/workflows` (at least one per claim).
* `detector` is a shell command run from the repo root. It must pass on the unmutated tree and fail on every mutant of the claim.
* `covers` is the drift lock: the sha256 of the named source. Required, non-empty.
* `mutants` lists ids; each needs `formal/mutants/<id>.patch` (a `git diff` that applies to HEAD). At least one per claim.
* `mutants` map (top level, optional): per-id `tier` (`fast` or `full`, default `full`), `claim` (needed only when several claims list the id), `detector` (overrides the claim's).
* `evidence_run` is optional, a GitHub Actions run id.
* `does_not_establish` is required and must say what the claim does not cover.
* `ci_required_exempt`: a job with no job-level `if:` that is deliberately not in `ci-required`'s needs. Needs a reason.
* `ci_required_conditional`: a job that HAS a job-level `if:` and is deliberately in `ci-required`'s needs (for example a path-filtered job whose gate step tolerates a skip). It must exist, have an `if:`, be in needs, and carry a reason; any other conditional job in needs still fails. This extends the plain "needs equals the unconditional jobs" rule; the kit does not verify that the gate step really tolerates a skip, a reviewer must.
* `overclaim_denylist` (keep `scripts/formal/` out of the globs, or use phrases that the vendored README does not contain): phrases that must not appear in files matching the globs. Matching ignores case and treats any run of whitespace, including a line break, as one space, so a phrase wrapped across lines in a hard-wrapped document is still found. Markup inside a phrase (for example `formally *verified*`) is not normalized. `formal/claims.json` itself is never scanned. A matched file that is not valid UTF-8 is still scanned (with replacement characters) and reported as a warning. Globs support `*`, `?` and `**` only. A glob set that matches no files is a failure, so a typo cannot pass silently.
* Unknown keys are errors (typos). `$comment` is allowed at top level and in claims.

## What check_claims.py checks

1. Schema, unique ids.
2. Every artifact path exists.
3. Every gate is a job id in a workflow.
4. In the workflow that defines `ci-required`, its `needs` equals exactly the set of jobs without a job-level `if:` (excluding itself), minus `ci_required_exempt`, plus `ci_required_conditional`. A job with any `if:` is otherwise excluded, so scheduled or dispatch-only jobs stay out.
5. Every `covers` hash matches the current source.
6. Every mutant id has a patch file (unreferenced patch files are warnings).
7. No overclaim phrase in the globbed files (`git ls-files -co --exclude-standard`, or a directory walk outside git).

`--run-detectors` also runs each detector on the current tree. `--root`, `--claims` override paths.

## Adding a claim

1. Write the proof or test and make it run in a CI job.
2. Add the claim with `"sha256": ""` in each cover.
3. Write a mutant: change the covered code so the claim should be false, then `git diff -- <covered file> > formal/mutants/<id>.patch` and `git checkout -- <covered file>`. Name the file in both commands: a bare `git diff` would also capture your uncommitted claim and test edits, and a bare `git checkout .` would discard them.
4. `python3 scripts/formal/check_claims.py --relock --symbol <path>:<symbol>` fills the empty hashes.
5. Commit, then `python3 scripts/formal/check_mutants.py --only <id>` must report `killed` (it tests HEAD, not the working tree).
6. State plainly in `does_not_establish` what remains unproven.

## Relock policy

Hash mismatch means the covered code changed after the claim was written. The fix is to re-read the claim, decide it still holds (or downgrade or remove it), then relock. Relocking is deliberate: use `--relock` with `--symbol path[:symbol]` for only the symbols you changed on purpose, never as a blanket step to turn CI green. The changed hashes appear in the PR diff of `formal/claims.json`, and the PR text should say which symbols were relocked and why. Relock never fixes a missing file or symbol; that needs a claims edit. Relock rewrites only the hash digits when it can, and reformats the JSON (indent 2) only if the layout is unusual.

## check_mutants.py

* Creates one detached scratch git worktree at HEAD (temp dir, or `--scratch PATH` which must be empty or absent). Uncommitted changes are NOT tested; commit first (a warning is printed).
* Runs every selected distinct detector on the unmutated scratch tree. If any fails, nothing else runs and the exit code is 1.
* For each mutant: `git apply --check`, `git apply`, run the detector in its own process group with `--timeout` (default 900 s, only that group is killed), `git apply -R`. Build caches keyed on absolute paths stay valid because the tree is reused.
* Results: `killed` (detector failed), `SURVIVED` (detector passed: the gate does not bite), `error` (patch missing or does not apply, detector timed out, tree could not be restored). Only `killed` is success. A timeout is never a kill.
* Tiers: `--tier fast` runs only fast-tier mutants; `--tier full` (default) runs all. `--only ID` runs one. `--json PATH` writes a report. A mutant with no `tier` is full. If the selected tier is empty while the claims list mutants, the run exits 1 ("a gate that selects nothing checks nothing"); pass `--allow-empty` to accept that. So a repo gating on `--tier fast` must mark at least one mutant `fast`.
* Vacuous kills: after applying a mutant the kit recomputes the claim's `covers` hashes. If none changed, a failing detector is reported as `error` (vacuous kill), not `killed`. After applying each mutant the kit also rewrites the scratch tree's `claims.json` hashes to the mutated source (the tree is restored afterwards), so a detector that runs `check_claims.py`, directly or hidden inside a make target or script, cannot kill a mutant through the drift lock alone. A warning is still printed when a detector command mentions `check_claims`.
* Still not detected: the kit cannot tell a semantic kill from a compile-break kill, nor a patch that edits only part of a covered symbol in a trivial way. Review each mutant.
* After each mutant the tree is restored with `git apply -R`, or with `git checkout -- .` if that fails, and any untracked file the patch created is removed, so it cannot leak into the next mutant. If the tree still differs from HEAD the run aborts with `error`. Files the detector itself creates (build output) are kept.
* The scratch worktree is always removed, including on failure.

Exit codes: 0 ok, 1 a check failed or a mutant survived/errored, 2 bad input or configuration.

## Evidence of record

Only a CI run counts as evidence for a claim. Local runs of the detectors or mutants are informative only. `evidence_run` records the run id a human last confirmed; the kit does not fetch it.

## Limits

Workflow reader (`parse_workflow_jobs`), a purpose-built indentation reader and not a YAML parser:
* reads only the top-level `jobs:` block mapping, each job's `if:` and `needs:`;
* `needs:` may be a scalar, an inline list (also across lines) or a block list of plain scalars;
* the value of `if:` is not evaluated; presence of any job-level `if:` counts as conditional (even `if: true`);
* block scalars (`|`, `>`) are skipped by indentation;
* block list items under `needs:` must be indented deeper than the `needs:` key (a list at the same indent, valid YAML, is rejected with an explicit error);
* a compact block sequence (items at the same indent as their key, as in `steps:` followed by `- uses:`) is accepted under any job key other than `needs` and `if`, and its items are skipped; a `- ` line at the key indent anywhere else is an error;
* it raises an error instead of guessing on: tabs in indentation, more than one document, flow-style `jobs`, anchors, aliases, merge keys, tags, duplicate jobs or keys, expressions in `needs`, inconsistent indentation, empty job bodies;
* reusable-workflow `uses:` jobs, matrices, and everything else under a job are ignored, so their contents are not validated.

Symbol extractor (Go and Rust only; other file types may only use symbol `*`):
* it is a lexical scanner, not a compiler. It masks comments, strings, raw strings (Go backticks; Rust `r"..."`, `r#"..."#`, `br`, `cr`), and char/rune literals, and does not treat Rust lifetimes or labels as char literals, then matches braces;
* an unterminated literal or comment, or unbalanced braces, is an error;
* Go declarations must start at column 0 (gofmt layout). Names: `Name`, `T.Name`, `(*T).Name`, and `func Name` for a free function when a method shares its name;
* Rust names, all of which you may use when `name` alone is ambiguous: `name`; `fn name` (non-method); `Type::name`; `Trait::name` (the trait's OWN item, a default method or a bodiless signature, never an impl); `Trait for Type::name` (last path segments); the full normalized impl header `From<u8> for Secret::name` or `CtEq for [u8]::name` (needed for a trait implemented several times for one type, or a self type that is not a plain path such as `[u8]`; whitespace around `<>(),[]&:` is ignored); `impl Type::name` or `impl Type<T>::name` for inherent impl methods; `mod::name` and `crate::name` / `crate::mod::name` for free functions. The error for an ambiguous name lists each candidate with its line number and the names that separate them. True duplicates (for example `#[cfg(..)]` twins with identical signatures) cannot be separated by any name: the error says so, and the fallback is symbol `*` (the whole file). Rust fns must start their own line (rustfmt layout); a fn written after another item on the same line is not found, which is reported as "not found", not skipped. Nested fns inside a fn body are covered by the enclosing fn's hash and are not addressable; fns defined by macros or inside macro_rules bodies are matched textually and may be misattributed;
* braces inside Rust generics in a signature or impl header (a const-generic block such as `Foo<{ N }>`) are stepped over by counting angle brackets outside parens and brackets; an unbalanced `>` there is an error;
* the hash covers the declaration line through the closing brace (or `;` for a bodiless Rust fn), with trailing whitespace stripped per line. Doc comments above the declaration, and anything outside it, are not covered. A drift lock says the text is unchanged, not that the claim is still true: a callee can change without changing the hash, so list callees in `covers` too;
* a name that matches several declarations in one file is an error until qualified (or until `*` is used for inseparable twins).
