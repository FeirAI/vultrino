//! STAGE 1 — proving vultrino's approval core on its own.
//!
//! Plan `feir-os/plans/105-staged-verification.md` §2, obligations V1/V2/V4/V5.
//! Every test in this file states **which rung of the proof ladder it lands on
//! and why the stronger rungs do not apply**:
//!
//! | rung | name | meaning |
//! |---|---|---|
//! | 1 | unrepresentable | the bad state cannot be constructed |
//! | 2 | exhaustive | the domain is bounded and every point is checked |
//! | 3 | conformance-pinned | two implementations agree on committed shared vectors |
//! | 4 | property-based | randomised over invariants, with shrinking |
//! | 5 | example-tested | weakest; acceptable only where 1–4 cannot apply |
//!
//! # What lives here, and what deliberately does not
//!
//! The **rung-3** work — cross-language agreement between `recipe_satisfied` and
//! govder's `recipeSatisfied` — is [`super::recipe_conformance`], driven by the
//! byte-identical `testdata/recipe_vectors.json` shared with
//! `govder/internal/oversight/testdata/`. This file does not duplicate a line of
//! it and does not touch the vector file: editing that file fails both suites by
//! design, and its `matching-oracle` sweep is *reused* below rather than
//! re-implemented.
//!
//! What this file adds is the part the conformance suite structurally cannot
//! carry:
//!
//! * **V1** — the conformance suite proves the two planes *agree*; it pins
//!   greedy-vs-optimal **only over `need <= 8`, `avail <= 9`** (45,000 points).
//!   Two implementations can agree and both be wrong. [`greedy_is_optimal_at_the_real_cap`]
//!   raises the *correctness* claim to the **real 64 cap**.
//! * **V5** — the lifecycle transition table, exhausted at 720 states against an
//!   independently written legality oracle, including its **guard order**.
//! * **V2/V4** — the runtime half of the sealed-field work, and the identity
//!   asymmetry that lets an unnamed principal fill a recipe slot.

use super::*;

/// A fresh, open, single-approval request with no stamped rule. Deliberately
/// minimal: every sweep below sets the axes it varies explicitly, so nothing is
/// inherited silently from a fixture.
fn fresh() -> (ApprovalRequest, String) {
    ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo {
            principal_kind: "api_key".to_string(),
            principal_id: Some("k1".to_string()),
            principal_name: Some("agent".to_string()),
            role: Some("executor".to_string()),
            owner: None,
        },
        use_token_id: None,
        principal_id: Some("k1".to_string()),
        agent_label: None,
        tenant: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: CriticalityClass::Medium,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    })
}

// ============================================================================
// V1 — recipe satisfaction is correct over its whole reachable domain
// ============================================================================

/// An INDEPENDENT oracle for "does an injective sign-off → slot assignment
/// exist?", written as a **search over the assignment split** rather than as the
/// leftover-senior algebra [`super::recipe_satisfied`] uses.
///
/// `k` is the number of senior units placed in *teammate* slots. The search tries
/// every legal `k` and asks whether the rest fits. It never assumes the
/// senior-first order — assuming it is exactly what
/// `approval-recipes.md` §2's swap argument claims and what this is here to
/// check. It shares no code and no algebra with `recipe_satisfied`.
///
/// Bounded: `k <= min(avs, nt)` and `nt <= MAX_RECIPE_TERM_COUNT`, so the loop is
/// at most 64 iterations even when `avs == u32::MAX`.
fn matchable_by_split_search(ns: u32, nt: u32, avs: u32, avt: u32) -> bool {
    let kmax = avs.min(nt);
    for k in 0..=kmax {
        // `k` seniors go to teammate slots; the remainder must cover the senior
        // slots, and the teammates must cover what is left of the teammate slots.
        if avs - k >= ns && avt >= nt.saturating_sub(k) {
            return true;
        }
    }
    false
}

/// **Rung 2, and it is the FIRST step of a two-step argument — do not read the
/// second step without it.**
///
/// [`matchable_by_split_search`] is an oracle written for this file. An oracle
/// nobody has checked is just a second opinion. This test pins it against
/// [`super::recipe_conformance::max_matching_exists`] — the augmenting-path
/// **maximum-bipartite-matching search over individual units** that arrived with
/// the merged cross-language conformance suite — over that suite's entire
/// `matching-oracle` cube (`need_senior + need_teammate <= 8`, `avail` in
/// `[0,9]`).
///
/// Why the cube and not the full cap: `max_matching_exists` materialises one
/// `Vec` element per *unit* and per *slot* and runs an `O(V·E)` augmenting-path
/// search, so it is only affordable at small sizes. That is precisely why the
/// shipped conformance sweep stops at 8 — and precisely why step 2 needs a
/// cheaper oracle whose agreement with the expensive one has been established
/// here first.
///
/// Rung 2 (exhaustive over the cube), not rung 1: "two search procedures compute
/// the same predicate" is not a statement the type system can carry.
#[test]
fn split_search_oracle_agrees_with_the_unit_matching_oracle() {
    let mut points = 0u64;
    let mut agreed_true = 0u64;
    for ns in 0..=8u32 {
        for nt in 0..=(8 - ns) {
            for avs in 0..=9u32 {
                for avt in 0..=9u32 {
                    let unit = super::recipe_conformance::max_matching_exists(ns, nt, 0, avs, avt, 0);
                    let split = matchable_by_split_search(ns, nt, avs, avt);
                    assert_eq!(
                        split, unit,
                        "the split-search oracle disagrees with the unit-level maximum-matching \
                         oracle at need(s={ns},t={nt}) avail(s={avs},t={avt}): split={split} \
                         unit={unit}. Step 2 of this argument is invalid until this is resolved."
                    );
                    points += 1;
                    agreed_true += u64::from(unit);
                }
            }
        }
    }
    // Report the domain size and the discrimination, so a future reduction of the
    // loop bounds changes a NUMBER rather than passing quietly, and so a
    // constant-false oracle (which would make the equality vacuous) is visible.
    assert_eq!(points, 4500, "the agreement cube moved; the digest below is stated over the old one");
    assert!(
        agreed_true > 0 && agreed_true < points,
        "both oracles agreed on {agreed_true} of {points} points — a constant oracle would agree \
         trivially, so this equality would prove nothing"
    );
}

/// **Rung 2 at the real cap. This is plan 105 §2.2's E1, and it is the step the
/// merged conformance suite does not reach.**
///
/// `recipe_satisfied`'s greedy senior-first shortcut is checked against
/// [`matchable_by_split_search`] over the **entire** humans-only domain the
/// shipped system can reach:
///
/// * **the recipe axis is exactly the well-formed need pairs.**
///   `recipe_satisfied` reads a recipe ONLY through `recipe_needs`, which
///   collapses any well-formed recipe to `(need_s, need_t, need_a)`; and
///   `recipe_well_formed` caps both the per-term count and the running total at
///   `MAX_RECIPE_TERM_COUNT`, so the reachable pairs are exactly
///   `{(ns, nt) : ns + nt <= 64}` — 2,145 of them.
/// * **`need_agent_reviewer` collapses to `{0, >0}`**: `need_a > 0` is an
///   unconditional `return false`, and the `> 0` half is exhausted by the
///   conformance suite's `agent-reviewer-simplex` sweep. Here `na == 0`.
/// * **the availability axis is exactly `0..=65` plus `u32::MAX`.** Availability
///   appears only in `<` / `>=` comparisons against needs, and every need is
///   `<= 64`, so every `avail >= 65` is behaviourally identical to `avail == 65`.
///   `u32::MAX` is carried anyway, as the arithmetic edge where a non-saturating
///   implementation would wrap.
///
/// **The finiteness of the recipe axis is inherited, not proved here.** It rests
/// on `recipe_well_formed`'s two caps. The plan discharges that with Kani P6 over
/// the whole `u32` domain; in-tree it is carried by the conformance suite's
/// `cap-cliff` sweep, which crosses both caps from below, at, and above. **Any
/// presentation of this test that omits that dependency overstates it** — it is
/// an assume-guarantee composition inside one plane.
#[test]
fn greedy_is_optimal_at_the_real_cap() {
    const CAP: u32 = MAX_RECIPE_TERM_COUNT;
    assert_eq!(CAP, 64, "the cap moved; the point count below is stated over the old cap");

    let avails: Vec<u32> = (0..=65u32).chain(std::iter::once(u32::MAX)).collect();
    let mut points: u64 = 0;
    let mut satisfied: u64 = 0;
    let mut mismatches: u64 = 0;
    let mut first: Vec<String> = Vec::new();

    for ns in 0..=CAP {
        for nt in 0..=(CAP - ns) {
            // Same canonical shape the shared vector file pins: zero-count terms
            // are omitted, because a zero count is itself malformed.
            let mut terms = Vec::with_capacity(2);
            if ns > 0 {
                terms.push(RecipeTerm { class: ApproverClass::Senior, count: ns });
            }
            if nt > 0 {
                terms.push(RecipeTerm { class: ApproverClass::Teammate, count: nt });
            }
            let r = Recipe { terms };
            let well_formed = recipe_well_formed(&r);
            for &avs in &avails {
                for &avt in &avails {
                    let greedy = recipe_satisfied(&r, avs, avt, 0);
                    let optimal = well_formed && matchable_by_split_search(ns, nt, avs, avt);
                    if greedy != optimal {
                        mismatches += 1;
                        if first.len() < 10 {
                            first.push(format!(
                                "need(s={ns},t={nt}) avail(s={avs},t={avt}): greedy={greedy} optimal={optimal}"
                            ));
                        }
                    }
                    points += 1;
                    satisfied += u64::from(greedy);
                }
            }
        }
    }

    assert_eq!(
        mismatches, 0,
        "greedy senior-first disagreed with an assignment-split search on {mismatches} of {points} \
         points at the REAL 64 cap — approval-recipes.md §2's swap argument is wrong, and an action \
         can execute on a sign-off set that does not satisfy its recipe (E1 false).\nFirst: {first:#?}"
    );
    // The domain size is asserted, not just traversed: a future domain-reduction
    // error changes a NUMBER here rather than silently shrinking what is proven.
    assert_eq!(
        points, 9_628_905,
        "the E1 domain moved to {points} points — re-derive the reduction argument in this test's \
         doc comment before touching this number"
    );
    // Discrimination guard: if `recipe_satisfied` were constant, the equality
    // above would hold vacuously against a matching constant oracle.
    assert!(
        satisfied > 0 && satisfied < points,
        "recipe_satisfied returned the same answer on all {points} points — this equality proves \
         nothing"
    );
    // The join between this test and the cross-language suite, and it is not a
    // coincidence worth leaving implicit.
    //
    // `testdata/recipe_vectors.json`'s `human-axis` sweep declares
    // `points: 9628905, satisfied_count: 5792016` over the SAME loop order and the
    // SAME availability set, and govder's `recipeSatisfied` reproduces its digest
    // byte-for-byte in Go. So the domain THIS test proves correctness over is
    // provably the same domain the two planes are pinned to agree on. Without this
    // assertion the two could drift apart — a domain-reduction edit here, or a
    // regenerated vector file there — and each suite would still pass alone while
    // the composition ("correct, and agreed") quietly stopped holding.
    assert_eq!(
        satisfied, 5_792_016,
        "this sweep found {satisfied} satisfying points where the shared vector file's \
         `human-axis` sweep declares 5792016 over the same domain. Either this test's domain \
         reduction or that sweep's has moved, and the rung-2 correctness result no longer covers \
         the domain the rung-3 cross-language result is pinned over."
    );
    eprintln!("V1/E1: {points} points at the real 64 cap, {satisfied} satisfied, 0 mismatches");
}

// ============================================================================
// V5 — the lifecycle transition table is total, and its guard ORDER holds
// ============================================================================

/// What an independently written reading of the spec says
/// [`ApprovalRequest::transition`] must do.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    /// `Ok(())`, and the status afterwards.
    Ok(ApprovalStatus),
    /// `Err(..)`, and the status afterwards (some errors still mutate).
    Err(&'static str, ApprovalStatus),
}

fn err_tag(e: &ApprovalError) -> &'static str {
    match e {
        ApprovalError::MissingApproverIdentity => "missing_identity",
        ApprovalError::Expired => "expired",
        ApprovalError::AlreadyDecided(_) => "already_decided",
        ApprovalError::SeparationOfDuty => "sod",
        ApprovalError::DuplicateApprover => "duplicate",
        ApprovalError::SameAggregatorKey => "same_agg_key",
        // `transition` cannot produce these two (they belong to the lookup and
        // OOB-token paths). Named explicitly rather than caught by a wildcard, so
        // that a NEW ApprovalError variant fails to compile here and has to be
        // classified deliberately instead of silently joining an "other" bucket.
        ApprovalError::NotFound => "unreachable_not_found",
        ApprovalError::InvalidToken => "unreachable_invalid_token",
    }
}

/// The legality table, written from the SPEC rather than from the code, so that
/// a disagreement is informative. **The order of the clauses below is itself the
/// claim**: see [`lifecycle_table_is_total_and_guard_order_holds`].
fn expected_transition(
    from: ApprovalStatus,
    to: ApprovalStatus,
    executed: bool,
    veto: VetoWindow,
    kind: &str,
    past_ttl: bool,
    identity: &str,
) -> Expect {
    // GUARD 1 — a decision must carry an authenticated approver identity.
    // This runs FIRST, before the TTL check. See the test's doc comment: this
    // ordering is observable and a prose spec states it the other way round.
    if identity.trim().is_empty() {
        return Expect::Err("missing_identity", from);
    }
    // GUARD 2 — past the final deadline. `expire_if_due` flips an OPEN request to
    // Expired as a side effect; a non-open one is left alone.
    if past_ttl {
        let after = if from.is_open() { ApprovalStatus::Expired } else { from };
        return Expect::Err("expired", after);
    }
    // GUARD 3 — a decision is valid only in an open state, with exactly one
    // exception: a human veto of a delegate-approved, not-yet-executed action
    // inside the delegator's veto window.
    let is_delegate_veto = to == ApprovalStatus::Denied
        && from == ApprovalStatus::Approved
        && !executed
        && veto == VetoWindow::Open
        && kind != "delegate-agent";
    if !from.is_open() && !is_delegate_veto {
        return Expect::Err("already_decided", from);
    }
    // The request is decidable. This sweep uses no stamped rule, no SoD
    // enforcement, `required_approvals = 1` and an empty sign-off set, so:
    //   - a deny is always terminal (the numeric-threshold path keeps deny-wins
    //     verbatim, and a veto is terminal by construction);
    //   - the first positive sign-off meets the threshold and grants.
    match to {
        ApprovalStatus::Denied => Expect::Ok(ApprovalStatus::Denied),
        ApprovalStatus::Approved => Expect::Ok(ApprovalStatus::Approved),
        other => unreachable!("this sweep only targets Approved/Denied, not {other:?}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VetoWindow {
    /// No `delegate_veto_until` recorded.
    Absent,
    /// Recorded and still in the future.
    Open,
    /// Recorded and already elapsed.
    Closed,
}

/// **Rung 2 — exhaustive over the whole 720-state lifecycle table.**
///
/// Rung 1 does not apply and the reason is structural: the reachable transitions
/// are a function of *runtime* facts (a wall clock against two deadlines, a
/// mutable `executed` flag, a string that arrives off the wire), none of which a
/// Rust type parameter can carry across the serde vault boundary. Rung 3 does not
/// apply either: govder has no twin of this state machine to conform to — the
/// lifecycle is vultrino's alone. So exhaustion over the bounded product is the
/// strongest available rung, and the product genuinely is bounded:
///
/// `5 statuses × 2 targets × 2 executed × 3 veto states × 2 approver kinds ×
///  2 TTL states × 3 identity shapes = 720`.
///
/// # The guard-order clause, and why exhaustion is what finds it
///
/// The blank-identity guard (`mod.rs`, GUARD 1 in [`expected_transition`]) runs
/// **before** the TTL guard. So a decision carrying a blank approver identity,
/// arriving at an already-expired open request, leaves the request `Pending` —
/// it does **not** flip to `Expired`. It is benign (the request cannot be decided
/// either way, and the poll path expires it separately) but it is exactly the
/// clause a prose specification states backwards, and no example test would
/// notice: you have to enumerate the product of both guards' inputs to see it.
/// The survey behind plan 105 §2.6 wrote its first table the other way round and
/// this is the row that failed. It is asserted explicitly below as well as
/// implicitly by the sweep, so deleting the sweep cannot silently delete it.
#[test]
fn lifecycle_table_is_total_and_guard_order_holds() {
    use chrono::Duration;

    let statuses = [
        ApprovalStatus::Pending,
        ApprovalStatus::Escalated,
        ApprovalStatus::Approved,
        ApprovalStatus::Denied,
        ApprovalStatus::Expired,
    ];
    let targets = [ApprovalStatus::Approved, ApprovalStatus::Denied];
    let vetoes = [VetoWindow::Absent, VetoWindow::Open, VetoWindow::Closed];
    let kinds = ["human", "delegate-agent"];
    // Three identity shapes: a real one, whitespace-only (trims to empty), and
    // empty. The last two must be indistinguishable — that is part of the claim.
    let identities = ["alice@example.com", "   ", ""];

    let mut states = 0usize;
    let mut accepted = 0usize;
    let mut by_outcome: std::collections::BTreeMap<String, usize> = Default::default();

    for &from in &statuses {
        for &to in &targets {
            for &executed in &[false, true] {
                for &veto in &vetoes {
                    for &kind in &kinds {
                        for &past_ttl in &[false, true] {
                            for &identity in &identities {
                                states += 1;
                                let (mut a, _tok) = fresh();
                                a.set_status_for_test(from);
                                a.executed = executed;
                                let now = chrono::Utc::now();
                                a.expires_at = if past_ttl {
                                    now - Duration::seconds(60)
                                } else {
                                    now + Duration::hours(4)
                                };
                                a.escalate_at = a.expires_at;
                                a.delegate_veto_until = match veto {
                                    VetoWindow::Absent => None,
                                    VetoWindow::Open => Some(now + Duration::hours(1)),
                                    VetoWindow::Closed => Some(now - Duration::hours(1)),
                                };
                                let mut d = Decision::new("admin panel", identity);
                                d.approver_kind = kind.to_string();

                                let got = a.transition(to, d);
                                let want = expected_transition(
                                    from, to, executed, veto, kind, past_ttl, identity,
                                );
                                let actual = match &got {
                                    Ok(()) => Expect::Ok(a.status()),
                                    Err(e) => Expect::Err(err_tag(e), a.status()),
                                };
                                assert_eq!(
                                    actual, want,
                                    "lifecycle disagreement at from={from:?} to={to:?} \
                                     executed={executed} veto={veto:?} kind={kind:?} \
                                     past_ttl={past_ttl} identity={identity:?}"
                                );
                                if got.is_ok() {
                                    accepted += 1;
                                }
                                *by_outcome
                                    .entry(match &actual {
                                        Expect::Ok(s) => format!("ok->{s}"),
                                        Expect::Err(t, s) => format!("err:{t}->{s}"),
                                    })
                                    .or_default() += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    assert_eq!(states, 720, "the lifecycle product moved away from 720 states");
    // The accepted count is asserted, not merely observed: a future widening of
    // the accepted set (a new legal transition, a relaxed guard) must FAIL this
    // test rather than pass it quietly. That is the whole point of pinning it.
    assert_eq!(
        accepted, 49,
        "the number of ACCEPTED lifecycle transitions moved to {accepted}. If that is deliberate, \
         say which transition became legal and why, in this test. Outcome census: {by_outcome:#?}"
    );
    eprintln!("V5: 720 states, {accepted} accepted. Census: {by_outcome:#?}");
}

/// The guard-order clause, named and asserted on its own so that it survives any
/// future edit to the sweep above. A prose specification states this the other
/// way round; only exhaustion over both guards' inputs finds it.
#[test]
fn blank_identity_guard_runs_before_the_ttl_guard() {
    use chrono::Duration;
    let (mut a, _t) = fresh();
    a.expires_at = chrono::Utc::now() - Duration::seconds(60);
    assert!(a.is_past_ttl());
    assert_eq!(a.status(), ApprovalStatus::Pending);

    // A blank identity on an ALREADY-EXPIRED open request.
    let err = a
        .transition(ApprovalStatus::Approved, Decision::new("admin panel", "   "))
        .unwrap_err();
    assert!(
        matches!(err, ApprovalError::MissingApproverIdentity),
        "expected the blank-identity guard to win; got {err:?}"
    );
    assert_eq!(
        a.status(),
        ApprovalStatus::Pending,
        "the request must still be Pending: the identity guard returned before the TTL guard \
         could run `expire_if_due`. If this now reads Expired, the guard order changed and every \
         statement about it in this file and in plan 105 §2.6 is stale."
    );

    // The same request, with a real identity, DOES expire — which is what makes
    // the assertion above about ORDER rather than about the TTL guard being dead.
    let err = a
        .transition(ApprovalStatus::Approved, Decision::new("admin panel", "alice"))
        .unwrap_err();
    assert!(matches!(err, ApprovalError::Expired), "got {err:?}");
    assert_eq!(a.status(), ApprovalStatus::Expired);
}

// ============================================================================
// V2 — the runtime half: a grant that does not re-derive does not execute
// ============================================================================

/// **Rung 1 is carried by the `compile_fail` doc-tests on [`Granted`]; this is
/// the rung-2 complement for the half the type system provably cannot reach.**
///
/// `ApprovalRequest` is `Deserialize` and lives as ciphertext in the file vault,
/// so a deserialize reconstructs `status` from bytes and no type-state parameter
/// survives the round trip. These tests exercise the re-derivation that meets
/// that adversary: a record whose stored `status` says `Approved` while its
/// stored evidence does not satisfy its stored rule yields **no witness**, and
/// without a witness there is no call to the execution path that type-checks.
#[test]
fn a_forged_approved_status_yields_no_grant_witness() {
    let (mut a, _t) = fresh();

    // The exact line plan 105 §2.3 names, in the only place it is still
    // expressible (a cfg(test) setter inside this module).
    a.set_status_for_test(ApprovalStatus::Approved);
    assert_eq!(a.status(), ApprovalStatus::Approved);
    assert!(a.signoffs().is_empty());

    assert!(
        a.grant_witness().is_none(),
        "a record stamped Approved with an EMPTY sign-off set minted a grant witness — the \
         re-derivation is inert and a vault edit would execute"
    );
}

#[test]
fn a_recipe_grant_that_no_longer_satisfies_yields_no_witness() {
    // {senior: 2} — satisfiable only by two distinct seniors.
    let rule = ApprovalRule {
        recipes: vec![Recipe {
            terms: vec![RecipeTerm { class: ApproverClass::Senior, count: 2 }],
        }],
        decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
    };
    let (mut a, _t) = fresh();
    a.approval_rule = Some(rule);

    let sign = |who: &str, class: ApproverClass| Signoff {
        approver_identity: who.to_string(),
        channel: "admin panel".to_string(),
        decided_at: chrono::Utc::now(),
        note: None,
        approver_kind: "human".to_string(),
        delegation_grant_ref: None,
        resolved_class: Some(class),
        controller: None,
        approve: true,
    };

    // Honest grant: two distinct seniors satisfy {senior:2}.
    a.set_status_for_test(ApprovalStatus::Approved);
    a.set_signoffs_for_test(vec![
        sign("alice@corp", ApproverClass::Senior),
        sign("bob@corp", ApproverClass::Senior),
    ]);
    let w = a.grant_witness().expect("an honestly satisfied recipe must mint a witness");
    assert_eq!(
        w.basis(),
        &GrantBasis::Recipe { recipes: 1, counted_signoffs: 2 },
        "the witness must name the predicate it was minted from"
    );

    // Now the shapes a vault edit produces, one axis at a time.
    for (label, signoffs) in [
        ("one senior short", vec![sign("alice@corp", ApproverClass::Senior)]),
        (
            "two sign-offs, one bare human identity duplicated (D4(b) distinctness)",
            vec![
                sign("alice@corp", ApproverClass::Senior),
                sign("ALICE@corp", ApproverClass::Senior),
            ],
        ),
        (
            "two humans, but only one is senior",
            vec![
                sign("alice@corp", ApproverClass::Senior),
                sign("bob@corp", ApproverClass::Teammate),
            ],
        ),
        (
            "two seniors whose class never resolved",
            vec![
                Signoff { resolved_class: None, ..sign("alice@corp", ApproverClass::Senior) },
                Signoff { resolved_class: None, ..sign("bob@corp", ApproverClass::Senior) },
            ],
        ),
    ] {
        a.set_status_for_test(ApprovalStatus::Approved);
        a.set_signoffs_for_test(signoffs);
        assert!(
            a.grant_witness().is_none(),
            "[{label}] a stored Approved status minted a grant witness on evidence that does not \
             satisfy the stored rule"
        );
    }
}

/// The witness is not merely *available* on the execution path — it is the
/// precondition for it. Demonstrated where it is load-bearing: the storage
/// claim path refuses a record it cannot mint one for.
///
/// This is deliberately asserted against the same predicate `transition` grants
/// on, so that a future change to one and not the other is caught here rather
/// than in production: an honestly-granted request must ALWAYS re-derive.
#[test]
fn every_honestly_granted_request_re_derives() {
    let (mut a, _t) = fresh();
    a.approve(Decision::new("admin panel", "alice@corp")).unwrap();
    assert_eq!(a.status(), ApprovalStatus::Approved);
    let w = a
        .grant_witness()
        .expect("a request granted by transition() must re-derive; if it does not, the claim path \
                 now refuses legitimate work and the two predicates have drifted");
    assert_eq!(w.basis(), &GrantBasis::NumericThreshold { need: 1, have: 1 });

    // A denied or still-open request never mints one, whatever else is true.
    let (mut d, _t) = fresh();
    d.deny(Decision::new("admin panel", "alice@corp")).unwrap();
    assert_eq!(d.status(), ApprovalStatus::Denied);
    assert!(d.grant_witness().is_none());

    let (open, _t) = fresh();
    assert!(open.grant_witness().is_none());
}

// ============================================================================
// V4 — one principal fills at most one slot, and an UNNAMED principal fills none
// ============================================================================

/// **Rung 1 for the shape, rung 5 for the reachability claim, and the gap between
/// them is the whole finding.**
///
/// `approval_rule_satisfied` drops a malformed sign-off on the **full namespaced**
/// identity (`approver_identity.trim().is_empty()`), while recipe distinctness
/// keys on the **bare** identity (`bare_approver_identity(..).trim()`). So
/// `agg:<key-id>:` with an *empty operator* is non-empty as a full string —
/// surviving the drop — and then dedupes under the key `""`. An **unnamed
/// principal fills a recipe slot**: a direct non-substitution (obligation X)
/// violation, in a system whose class guarantees are otherwise at rung 1.
///
/// No shipped entry point produces that shape today (`web/api.rs` substitutes
/// `NO_OPERATOR_SENTINEL`, the admin panel uses the session user, the OOB link
/// filters non-empty, the CLI uses `cli:<user>`). But `Signoff` deserializes from
/// the vault with **no** identity validation, so the shape is reachable through
/// exactly the boundary V3 names — and "unreachable today, by convention, in four
/// places" is the reasoning this program exists to stop accepting.
///
/// **Fail-closed wins ties**: the drop now reads the same function the
/// distinctness key reads, so the two can no longer hold different opinions about
/// what a principal is. The change strictly drops MORE sign-offs; it can never
/// newly satisfy a recipe.
#[test]
fn an_unnamed_principal_fills_no_slot() {
    let rule = ApprovalRule {
        recipes: vec![Recipe {
            terms: vec![RecipeTerm { class: ApproverClass::Teammate, count: 1 }],
        }],
        decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
    };
    let unnamed = |ident: &str| Signoff {
        approver_identity: ident.to_string(),
        channel: "aggregator".to_string(),
        decided_at: chrono::Utc::now(),
        note: None,
        approver_kind: "human".to_string(),
        delegation_grant_ref: None,
        resolved_class: Some(ApproverClass::Teammate),
        controller: None,
        approve: true,
    };

    // The empty-operator shapes. Each is non-empty as a FULL string, so each
    // survived the old drop, and each collapses to the bare key "".
    for ident in [
        "agg:00000000-0000-0000-0000-000000000000:",
        "agg:00000000-0000-0000-0000-000000000000:   ",
        "agg:key-a:",
    ] {
        assert!(
            !ident.trim().is_empty(),
            "[{ident}] this test is vacuous unless the FULL identity is non-empty"
        );
        assert!(
            bare_approver_identity(ident).trim().is_empty(),
            "[{ident}] this test is vacuous unless the BARE identity is empty"
        );
        assert!(
            !approval_rule_satisfied(&rule, &[unnamed(ident)]),
            "[{ident}] an aggregator-asserted sign-off with an EMPTY operator filled a recipe \
             slot — an unnamed principal satisfied a {{teammate:1}} rule"
        );
    }

    // Control: the same shape with a real operator DOES fill the slot, so the
    // assertions above are about the blank operator and not about the whole
    // `agg:` scheme having been broken.
    assert!(
        approval_rule_satisfied(
            &rule,
            &[unnamed("agg:00000000-0000-0000-0000-000000000000:alice@corp")]
        ),
        "a NAMED aggregator-asserted teammate must still fill a teammate slot"
    );
    // And a bare (non-aggregator) blank is still dropped, as it always was.
    assert!(!approval_rule_satisfied(&rule, &[unnamed("   ")]));
}

/// The two functions that decide *what a principal is* must read the same
/// predicate. This is the drift the code's own comments call out for
/// `recipe_satisfied`/`class_fills_a_slot` ("Codex RE-REVIEW-5"), applied to the
/// identity axis: **two functions with different opinions about what a principal
/// is**. Rung 2 over a small closed table of identity shapes.
#[test]
fn the_drop_and_the_distinctness_key_agree_about_what_a_principal_is() {
    let shapes = [
        "alice@corp",
        "   alice@corp  ",
        "agg:key-a:alice@corp",
        "agg:key-a:",
        "agg:key-a:   ",
        "agg:key-a",     // malformed: no second colon, treated as opaque
        "agg:",          // malformed
        "   ",
        "",
    ];
    for s in shapes {
        let dropped_by_the_guard = bare_approver_identity(s).trim().is_empty();
        // The distinctness key: an empty key is the "unnamed principal" bucket.
        let key = bare_approver_identity(s).trim().to_ascii_lowercase();
        let unnamed_under_the_key = key.is_empty();
        assert_eq!(
            dropped_by_the_guard, unnamed_under_the_key,
            "[{s:?}] the malformed-sign-off drop and the D4(b) distinctness key disagree: \
             dropped={dropped_by_the_guard} unnamed_key={unnamed_under_the_key}. One of them \
             thinks this is a principal and the other does not."
        );
    }
}
