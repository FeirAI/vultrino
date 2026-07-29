//! RUST HALF of a two-language approval-recipe conformance suite.
//!
//! The GO HALF is `govder/internal/oversight/recipe_conformance_test.go`, and it
//! reads the SAME testdata file — `testdata/recipe_vectors.json` here,
//! `internal/oversight/testdata/recipe_vectors.json` there, byte-identical, with
//! the content hash pinned on both sides (see [`SHARED_VECTORS_SHA256`]).
//!
//! # Why this exists
//!
//! [`super::recipe_satisfied`] and govder's `recipeSatisfied` are twin
//! implementations of ONE rule in two languages, on opposite sides of the
//! decide/enforce split. The sufficiency of their shared greedy senior-first
//! shortcut was, until this file, asserted only in prose ("provably sufficient —
//! see approval-recipes.md §2 for the swap argument") in a doc comment on each
//! side. Prose does not fail a build. This seam has already diverged once in
//! exactly the way prose invites: the hard-SoD same-key guard hand-rolled its own
//! contribution rule and produced a senior-fills-teammate fabrication (Codex
//! RE-REVIEW-5) — which is why `recipe_satisfied` and `class_fills_a_slot` now
//! share one `recipe_needs`.
//!
//! # What is proved vs what is sampled
//!
//! [`super::MAX_RECIPE_TERM_COUNT`] = 64 bounds BOTH the per-term count and the
//! summed total, so the recipe side of this contract is a FINITE domain. The
//! sweeps below are therefore EXHAUSTIVE over it, not samples — each sweep
//! carries in the testdata file exactly which axes are exhausted and which are
//! sampled, with the soundness argument for the sampled ones. The explicit
//! `vectors` rows are hand-authored boundary and regression cases on top.
//!
//! # A failing row is not a test problem
//!
//! It means govder and vultrino now disagree about whether an approval is
//! complete — one plane will consider a two-approver requirement met while the
//! other does not. Do not regenerate the file to make a test pass.

use super::{recipe_satisfied, recipe_well_formed, ApproverClass, Recipe};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// SHA-256 of the shared vector file. The file lives in two git repos, so "the
/// same file" is not something the filesystem can enforce; this constant is what
/// enforces it. The Go half pins the identical value. Editing one copy fails BOTH
/// suites, which is the point — a divergence in the vectors is as dangerous as a
/// divergence in the code.
const SHARED_VECTORS_SHA256: &str =
    "b087abfaace829ad572c552598331963bb9efab3b28f735fab85384c9e64b56d";

const VECTORS_JSON: &str = include_str!("testdata/recipe_vectors.json");

#[derive(Debug, Deserialize)]
struct Avail {
    senior: u32,
    teammate: u32,
    agent_reviewer: u32,
}

/// One explicit row.
///
/// `satisfied` is the COMPOSED contract: structurally well-formed AND
/// slot-matched. That is exactly what [`super::recipe_satisfied`] returns on its
/// own (it folds well-formedness in via `recipe_needs`); govder reaches the same
/// answer only after `evaluateApprovalRule`'s `validRecipes` filter has dropped
/// malformed recipes. `go_raw_satisfied` records what govder's `recipeSatisfied`
/// returns WITHOUT that filter and is asserted only on the Go side — it is
/// carried here so the two halves read one file, and so the asymmetry is visible
/// to a Rust reader.
#[derive(Debug, Deserialize)]
struct Vector {
    id: String,
    note: String,
    recipe: serde_json::Value,
    avail: Avail,
    well_formed: bool,
    satisfied: bool,
    #[allow(dead_code)]
    go_raw_satisfied: bool,
    /// False when the row's counts cannot exist on this side's wire at all
    /// (`RecipeTerm::count` is `u32`, so a negative or > u32 count is not a
    /// behaviour difference — it is unrepresentable). Such rows are not skipped:
    /// [`vectors_unrepresentable_rows_really_are_unrepresentable`] asserts the
    /// deserialize FAILS, which is the actual claim.
    rust_representable: bool,
}

#[derive(Debug, Deserialize)]
struct Sweep {
    id: String,
    exhaustive_over: String,
    sampled_over: String,
    avail_values: Vec<u32>,
    #[serde(default)]
    need_max: u32,
    #[serde(default)]
    recipes: usize,
    points: usize,
    satisfied_count: usize,
    #[serde(default)]
    greedy_vs_optimal_mismatches: usize,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Doc {
    cap: u32,
    u32_max: u32,
    vectors: Vec<Vector>,
    sweeps: Vec<Sweep>,
}

fn load() -> Doc {
    let mut h = Sha256::new();
    h.update(VECTORS_JSON.as_bytes());
    let got = hex(&h.finalize());
    assert_eq!(
        got, SHARED_VECTORS_SHA256,
        "src/approval/testdata/recipe_vectors.json has sha256 {got}, want the pinned \
         {SHARED_VECTORS_SHA256}. This file is a byte-identical copy shared with \
         govder/internal/oversight/testdata/. If you changed it here you must change it there \
         and re-pin BOTH constants, or the two planes are being conformance-tested against \
         different contracts."
    );
    let doc: Doc = serde_json::from_str(VECTORS_JSON).expect("decoding recipe_vectors.json");
    assert_eq!(
        doc.cap,
        super::MAX_RECIPE_TERM_COUNT,
        "vector file cap != MAX_RECIPE_TERM_COUNT — the cap moved, so the exhaustive domain and \
         every sweep digest below is stated over the OLD cap and no longer proves anything"
    );
    assert_eq!(doc.u32_max, u32::MAX, "u32_max in the vector file is not u32::MAX");
    assert!(
        doc.vectors.len() >= 40,
        "vector file has only {} explicit vectors — it was truncated, not extended",
        doc.vectors.len()
    );
    assert_eq!(doc.sweeps.len(), 4, "a sweep was dropped from the vector file");
    doc
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sweep_by_id<'a>(doc: &'a Doc, id: &str) -> &'a Sweep {
    doc.sweeps
        .iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("sweep {id:?} missing from the vector file"))
}

/// Streaming accumulator over the decision bitstream: one byte per point, in the
/// loop order pinned in the vector file. The digest is what makes the
/// cross-language claim checkable — Go computes the identical stream and both
/// must reproduce the frozen value.
struct Acc {
    h: Sha256,
    buf: Vec<u8>,
    n: usize,
    n_sat: usize,
}

impl Acc {
    fn new() -> Self {
        Self { h: Sha256::new(), buf: Vec::with_capacity(1 << 20), n: 0, n_sat: 0 }
    }

    fn emit(&mut self, v: bool) {
        self.buf.push(u8::from(v));
        self.n += 1;
        self.n_sat += usize::from(v);
        if self.buf.len() >= (1 << 20) {
            self.h.update(&self.buf);
            self.buf.clear();
        }
    }

    fn check(mut self, s: &Sweep) {
        self.h.update(&self.buf);
        self.buf.clear();
        let got = hex(&self.h.finalize());
        assert_eq!(
            self.n, s.points,
            "sweep {:?} enumerated {} points, the frozen spec says {} — the DOMAIN moved, so the \
             digest cannot be compared at all",
            s.id, self.n, s.points
        );
        assert_eq!(
            self.n_sat, s.satisfied_count,
            "sweep {:?}: {} of {} points satisfied, want {}",
            s.id, self.n_sat, self.n, s.satisfied_count
        );
        assert_eq!(
            got, s.sha256,
            "sweep {:?} digest mismatch.\n  exhaustive over: {}\n  sampled over:    {}\n\
             govder's recipeSatisfied reproduces the wanted digest over the identical domain. A \
             mismatch here is a CROSS-PLANE DIVERGENCE in approval satisfaction.",
            s.id, s.exhaustive_over, s.sampled_over
        );
        eprintln!(
            "sweep {:?}: {} points ({} satisfied) — EXHAUSTIVE over {}",
            s.id, self.n, self.n_sat, s.exhaustive_over
        );
    }
}

fn term(class: ApproverClass, count: u32) -> super::RecipeTerm {
    super::RecipeTerm { class, count }
}

/// Canonical recipe for a need triple. Zero-count terms are OMITTED (a zero count
/// is itself malformed, so an `ns == 0` recipe simply has no senior term). Term
/// order is pinned: senior, teammate, agent-reviewer. The Go half builds the same
/// shape, and the vector file states the rule.
fn recipe_from_needs(ns: u32, nt: u32, na: u32) -> Recipe {
    let mut terms = Vec::with_capacity(3);
    if ns > 0 {
        terms.push(term(ApproverClass::Senior, ns));
    }
    if nt > 0 {
        terms.push(term(ApproverClass::Teammate, nt));
    }
    if na > 0 {
        terms.push(term(ApproverClass::AgentReviewer, na));
    }
    Recipe { terms }
}

// --- explicit vectors -------------------------------------------------------

/// The cross-plane gate: `recipe_satisfied` must equal the frozen `satisfied`
/// value for every row, and govder's composed answer is asserted against the SAME
/// value in Go.
#[test]
fn vectors_satisfied_matches_the_shared_contract() {
    let doc = load();
    let mut checked = 0;
    for v in &doc.vectors {
        if !v.rust_representable {
            continue;
        }
        let r: Recipe = serde_json::from_value(v.recipe.clone())
            .unwrap_or_else(|e| panic!("[{}] decoding recipe into Recipe: {e}", v.id));
        assert_eq!(
            recipe_well_formed(&r),
            v.well_formed,
            "[{}] recipe_well_formed disagrees with the shared vector  ({})",
            v.id,
            v.note
        );
        let got = recipe_satisfied(&r, v.avail.senior, v.avail.teammate, v.avail.agent_reviewer);
        assert_eq!(
            got, v.satisfied,
            "[{}] recipe_satisfied({:?}, s={} t={} a={}) = {}, want {}  ({})",
            v.id, r.terms, v.avail.senior, v.avail.teammate, v.avail.agent_reviewer, got,
            v.satisfied, v.note
        );
        checked += 1;
    }
    assert!(checked >= 40, "only {checked} representable vectors were checked");
}

/// The rows the Go half exercises but this side structurally cannot: a negative
/// or `> u32::MAX` term count. This is not a skip — it asserts the CLAIM that
/// makes skipping legitimate, namely that such a recipe cannot be deserialized on
/// this side at all, so it can never reach `recipe_satisfied`. If `RecipeTerm::
/// count` ever widened to a signed type, this test fails and the Go half's
/// `malformed-negative-count` row becomes a live cross-plane concern.
#[test]
fn vectors_unrepresentable_rows_really_are_unrepresentable() {
    let doc = load();
    let mut checked = 0;
    for v in &doc.vectors {
        if v.rust_representable {
            continue;
        }
        let parsed = serde_json::from_value::<Recipe>(v.recipe.clone());
        assert!(
            parsed.is_err(),
            "[{}] the vector file says this recipe is unrepresentable in Rust, but it \
             deserialized into {:?} — the wire type changed and the Go/Rust domains no longer \
             match  ({})",
            v.id,
            parsed.ok(),
            v.note
        );
        checked += 1;
    }
    assert!(checked >= 2, "only {checked} unrepresentable rows — the claim is barely exercised");
}

/// The item-7 hard guard as a standalone property over the explicit rows: no
/// availability, however large, ever satisfies a recipe carrying an
/// agent-reviewer term.
#[test]
fn vectors_agent_reviewer_terms_are_unsatisfiable() {
    let doc = load();
    let mut checked = 0;
    for v in &doc.vectors {
        if !v.rust_representable {
            continue;
        }
        let r: Recipe = serde_json::from_value(v.recipe.clone()).unwrap();
        if !r.terms.iter().any(|t| t.class == ApproverClass::AgentReviewer) {
            continue;
        }
        checked += 1;
        assert!(!v.satisfied, "[{}] the vector file claims an agent-reviewer recipe is satisfiable", v.id);
        for avail in [0u32, 1, super::MAX_RECIPE_TERM_COUNT, u32::MAX] {
            assert!(
                !recipe_satisfied(&r, avail, avail, avail),
                "[{}] recipe_satisfied returned true at avail={avail} for {:?}",
                v.id,
                r.terms
            );
        }
    }
    assert!(checked >= 3, "only {checked} agent-reviewer vectors — the guard is barely exercised");
}

// --- exhaustive sweeps ------------------------------------------------------

/// EXHAUSTIVE, not a sample: every well-formed `(need_senior, need_teammate)`
/// pair the 64-cap permits, crossed with every availability pair in `[0,65]` plus
/// `u32::MAX`. Agent-reviewer terms are hard-disabled system-wide, so this domain
/// contains EVERY recipe the shipped system can ever actually satisfy. The digest
/// is reproduced byte-for-byte by govder's `recipeSatisfied` over the identical
/// domain and loop order.
#[test]
fn sweep_human_axis_exhaustive() {
    let doc = load();
    let s = sweep_by_id(&doc, "human-axis");
    let mut acc = Acc::new();
    for ns in 0..=super::MAX_RECIPE_TERM_COUNT {
        for nt in 0..=(super::MAX_RECIPE_TERM_COUNT - ns) {
            let r = recipe_from_needs(ns, nt, 0);
            for &avs in &s.avail_values {
                for &avt in &s.avail_values {
                    acc.emit(recipe_satisfied(&r, avs, avt, 0));
                }
            }
        }
    }
    acc.check(s);
}

/// EXHAUSTIVE over the whole THREE-class need simplex (`ns+nt+na <= 64`). Its job
/// is the item-7 guard: every need triple with `na >= 1` must be unsatisfiable at
/// every availability. The availability axis is SAMPLED at
/// `{0,1,64,65,u32::MAX}^3` — sound for the `na >= 1` rows because both
/// implementations return before reading any availability, and the `na == 0` rows
/// are covered exhaustively by the human-axis sweep.
#[test]
fn sweep_agent_reviewer_simplex_exhaustive() {
    let doc = load();
    let s = sweep_by_id(&doc, "agent-reviewer-simplex");
    let mut acc = Acc::new();
    for na in 0..=super::MAX_RECIPE_TERM_COUNT {
        for ns in 0..=(super::MAX_RECIPE_TERM_COUNT - na) {
            for nt in 0..=(super::MAX_RECIPE_TERM_COUNT - na - ns) {
                let r = recipe_from_needs(ns, nt, na);
                for &avs in &s.avail_values {
                    for &avt in &s.avail_values {
                        for &ava in &s.avail_values {
                            acc.emit(recipe_satisfied(&r, avs, avt, ava));
                        }
                    }
                }
            }
        }
    }
    acc.check(s);
}

/// EXHAUSTIVE over the 64-cap cliff: every single-term recipe for each class at
/// every count `0..=66`, and every `(senior c1, teammate c2)` pair with
/// `c1, c2 in 0..=66` — crossing the per-term cap and the summed-total cap from
/// below, at, and above. Zero-count terms are kept EXPLICIT here (unlike the
/// other sweeps) because `count == 0` is itself one of the malformed shapes under
/// test.
#[test]
fn sweep_cap_cliff_exhaustive() {
    let doc = load();
    let s = sweep_by_id(&doc, "cap-cliff");
    let mut acc = Acc::new();
    let mut recipes: Vec<Recipe> = Vec::with_capacity(s.recipes);
    for class in [ApproverClass::Senior, ApproverClass::Teammate, ApproverClass::AgentReviewer] {
        for c in 0..=(super::MAX_RECIPE_TERM_COUNT + 2) {
            recipes.push(Recipe { terms: vec![term(class, c)] });
        }
    }
    for c1 in 0..=(super::MAX_RECIPE_TERM_COUNT + 2) {
        for c2 in 0..=(super::MAX_RECIPE_TERM_COUNT + 2) {
            recipes.push(Recipe {
                terms: vec![term(ApproverClass::Senior, c1), term(ApproverClass::Teammate, c2)],
            });
        }
    }
    assert_eq!(recipes.len(), s.recipes, "cap-cliff recipe count moved away from the frozen spec");
    for r in &recipes {
        for &avs in &s.avail_values {
            for &avt in &s.avail_values {
                for &ava in &s.avail_values {
                    acc.emit(recipe_satisfied(r, avs, avt, ava));
                }
            }
        }
    }
    acc.check(s);
}

// --- greedy vs a real matching ---------------------------------------------

const UNIT_SENIOR: u8 = 0;
const UNIT_TEAMMATE: u8 = 1;
const UNIT_AGENT_REVIEWER: u8 = 2;

fn can_fill(unit: u8, slot: u8) -> bool {
    match slot {
        UNIT_SENIOR => unit == UNIT_SENIOR,
        // A senior is a fortiori a teammate; a plain teammate is not a senior.
        UNIT_TEAMMATE => unit == UNIT_SENIOR || unit == UNIT_TEAMMATE,
        _ => unit == UNIT_AGENT_REVIEWER,
    }
}

/// An INDEPENDENT oracle for "does an injective sign-off → slot assignment
/// exist?": a plain augmenting-path maximum-bipartite-matching search over
/// individual sign-off units and individual slots. It deliberately shares NO code
/// and NO algebra with [`super::recipe_satisfied`] — no leftover-senior
/// arithmetic, no Hall condition, just a search. It is the thing
/// approval-recipes.md §2's swap argument is a claim ABOUT.
pub(super) fn max_matching_exists(ns: u32, nt: u32, na: u32, avs: u32, avt: u32, ava: u32) -> bool {
    let mut units: Vec<u8> = Vec::new();
    units.extend(std::iter::repeat_n(UNIT_SENIOR, avs as usize));
    units.extend(std::iter::repeat_n(UNIT_TEAMMATE, avt as usize));
    units.extend(std::iter::repeat_n(UNIT_AGENT_REVIEWER, ava as usize));
    let mut slots: Vec<u8> = Vec::new();
    slots.extend(std::iter::repeat_n(UNIT_SENIOR, ns as usize));
    slots.extend(std::iter::repeat_n(UNIT_TEAMMATE, nt as usize));
    slots.extend(std::iter::repeat_n(UNIT_AGENT_REVIEWER, na as usize));
    if units.len() < slots.len() {
        return false;
    }

    fn try_assign(
        slot: usize,
        units: &[u8],
        slots: &[u8],
        match_of_unit: &mut [isize],
        seen: &mut [bool],
    ) -> bool {
        for u in 0..units.len() {
            if seen[u] || !can_fill(units[u], slots[slot]) {
                continue;
            }
            seen[u] = true;
            let prev = match_of_unit[u];
            if prev == -1 || try_assign(prev as usize, units, slots, match_of_unit, seen) {
                match_of_unit[u] = slot as isize;
                return true;
            }
        }
        false
    }

    let mut match_of_unit = vec![-1isize; units.len()];
    let mut seen = vec![false; units.len()];
    for s in 0..slots.len() {
        seen.iter_mut().for_each(|x| *x = false);
        if !try_assign(s, &units, &slots, &mut match_of_unit, &mut seen) {
            return false;
        }
    }
    true
}

/// Turns approval-recipes.md §2's swap argument from prose into a build gate.
/// Over an EXHAUSTIVE small cube it compares `recipe_satisfied`'s greedy
/// senior-first shortcut against [`max_matching_exists`] — a real augmenting-path
/// matching search — and requires exact agreement on every point. Scoped to
/// recipes with NO agent-reviewer term, because for those the shipped answer is a
/// POLICY override (the item-7 hard guard) rather than a matching result; that
/// half is pinned by [`sweep_agent_reviewer_simplex_exhaustive`].
///
/// The same comparison is run independently in Go and in the Python reference
/// that generated the vector file, so "greedy is sufficient" is now derived three
/// times rather than asserted once.
#[test]
fn greedy_senior_first_is_optimal() {
    let doc = load();
    let s = sweep_by_id(&doc, "matching-oracle");
    let mut acc = Acc::new();
    let mut mismatches = 0usize;
    let mut reported = 0usize;
    for ns in 0..=s.need_max {
        for nt in 0..=(s.need_max - ns) {
            let r = recipe_from_needs(ns, nt, 0);
            let wf = recipe_well_formed(&r);
            for &avs in &s.avail_values {
                for &avt in &s.avail_values {
                    for &ava in &s.avail_values {
                        let greedy = recipe_satisfied(&r, avs, avt, ava);
                        let optimal = wf && max_matching_exists(ns, nt, 0, avs, avt, ava);
                        if greedy != optimal {
                            mismatches += 1;
                            if reported < 10 {
                                reported += 1;
                                eprintln!(
                                    "greedy != optimal: need(s={ns},t={nt}) \
                                     avail(s={avs},t={avt},a={ava}): greedy={greedy} optimal={optimal}"
                                );
                            }
                        }
                        acc.emit(greedy);
                    }
                }
            }
        }
    }
    assert_eq!(
        mismatches, s.greedy_vs_optimal_mismatches,
        "greedy disagreed with a real maximum matching on {mismatches} points — the senior-first \
         shortcut is NOT sufficient and approval-recipes.md §2's swap argument is wrong"
    );
    acc.check(s);
}

/// A guard on the guard: makes sure [`max_matching_exists`] is actually
/// discriminating (not a constant-true stub that would make the test above
/// vacuous) by asserting cases it must get right by construction.
#[test]
fn matching_oracle_is_discriminating() {
    /// `(need_s, need_t, need_a, avail_s, avail_t, avail_a, want, why)`.
    type OracleCase = (u32, u32, u32, u32, u32, u32, bool, &'static str);
    let cases: &[OracleCase] = &[
        (1, 0, 0, 0, 5, 0, false, "no teammate can ever fill a senior slot"),
        (0, 1, 0, 1, 0, 0, true, "a senior fills a teammate slot"),
        (1, 1, 0, 1, 0, 0, false, "ONE senior cannot fill BOTH slots (injectivity)"),
        (1, 1, 0, 2, 0, 0, true, "two seniors fill senior+teammate"),
        (1, 1, 0, 1, 1, 0, true, "the natural fill"),
        (0, 0, 1, 0, 9, 0, false, "humans cannot fill an agent-reviewer slot"),
        (0, 0, 1, 0, 0, 1, true, "an agent-reviewer fills an agent-reviewer slot"),
        (2, 3, 0, 2, 3, 0, true, "exact fill"),
        (2, 3, 0, 1, 9, 0, false, "seniors are not substitutable downward"),
        (0, 0, 0, 0, 0, 0, true, "zero slots are vacuously matchable"),
    ];
    for &(ns, nt, na, avs, avt, ava, want, why) in cases {
        assert_eq!(
            max_matching_exists(ns, nt, na, avs, avt, ava),
            want,
            "max_matching_exists(need s={ns} t={nt} a={na}, avail s={avs} t={avt} a={ava}) — {why}"
        );
    }
}
