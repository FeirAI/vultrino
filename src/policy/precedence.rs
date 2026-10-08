//! The pure default-deny precedence decision of the policy engine.
//!
//! `PolicyEngine::evaluate_inner` finds which rules matched (that part reads the
//! clock and the rate-limit counters, so it stays in the engine) and hands the
//! outcomes to [`resolve_precedence`], which decides. This function has no side
//! effects and no I/O, so it can be checked over its whole finite domain.
//!
//! Specification, strongest first:
//! `kill > deny > prompt > allow > policy default > engine default`.
//! Among policy defaults the same order applies (deny > prompt > allow). The
//! engine default applies only when no policy matched the credential and
//! principal at all, which is the case `policy_defaults` is empty.

use super::{PolicyAction, PolicyDecision};

/// What one matched rule (or one matching policy's kill flag) contributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleOutcome {
    /// A matching policy carries the authoritative kill flag.
    Kill,
    /// A deny rule matched.
    Deny,
    /// A prompt rule matched.
    Prompt,
    /// An allow rule matched.
    Allow,
    /// A rule was looked at and did not match; contributes nothing. The engine
    /// never passes it (it records only matches); the tests and proof include it
    /// so the function is checked on that input too.
    #[allow(dead_code)]
    NoMatch,
}

/// The decision, with enough detail for the engine to pick the audit message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Kill,
    Deny,
    Prompt,
    Allow,
    PolicyDefaultDeny,
    PolicyDefaultPrompt,
    PolicyDefaultAllow,
    EngineDefaultDeny,
    EngineDefaultAllow,
    /// Nothing decided although a policy matched. Unreachable (see the tests and
    /// the Kani harness), and if it were reached the request is denied.
    FailClosedTail,
}

/// The verdict when no rule and no default produced a decision. It maps to a
/// denial in [`decision_for`], whatever the engine default is.
pub(crate) fn fail_closed_tail() -> Verdict {
    Verdict::FailClosedTail
}

/// Map a verdict to the decision the engine returns. `rule_deny_policy` is the
/// name of the policy whose deny rule matched and `default_deny_policy` the name
/// of a matching policy whose default action is deny; both only feed the reason
/// text. Every denying verdict (kill, deny rule, deny default, engine default
/// deny and the fail-closed tail) yields `Deny`.
pub(crate) fn decision_for(
    verdict: Verdict,
    rule_deny_policy: &str,
    default_deny_policy: &str,
) -> PolicyDecision {
    match verdict {
        // Generic reason to the caller: don't leak the kill-policy name or
        // label scheme to a (possibly compromised) agent. The specifics live
        // in the halt audit log.
        Verdict::Kill => PolicyDecision::Deny("denied: this principal has been halted".to_string()),
        Verdict::Deny => PolicyDecision::Deny(format!(
            "Denied by policy '{rule_deny_policy}': rule matched"
        )),
        Verdict::Prompt | Verdict::PolicyDefaultPrompt => PolicyDecision::Prompt,
        Verdict::Allow | Verdict::PolicyDefaultAllow | Verdict::EngineDefaultAllow => {
            PolicyDecision::Allow
        }
        Verdict::PolicyDefaultDeny => PolicyDecision::Deny(format!(
            "Denied by policy '{default_deny_policy}': default action"
        )),
        Verdict::EngineDefaultDeny => PolicyDecision::Deny(
            "no_policy: no policy matches this credential (default-deny enforcement)".to_string(),
        ),
        Verdict::FailClosedTail => PolicyDecision::Deny(
            "denied: policy evaluation reached no decision (fail-closed)".to_string(),
        ),
    }
}

/// The shipped, lazy form of the precedence decision. `kill` is true when a
/// matching policy carries the kill flag; then no rule is asked about. Otherwise
/// the tiers are asked in the order deny, prompt, allow through `matched` (which
/// reads the clock and charges rate limits in the engine) and the scan stops at
/// the first tier that matches, so a weaker tier is never asked and never
/// charged. The result equals `resolve_precedence` over the full set of tier
/// outcomes (checked exhaustively in the tests and by a Kani harness).
pub(crate) fn resolve_lazily(
    kill: bool,
    mut matched: impl FnMut(RuleOutcome) -> bool,
    policy_defaults: &[PolicyAction],
    engine_default_deny: bool,
) -> Verdict {
    if kill {
        return resolve_precedence(&[RuleOutcome::Kill], policy_defaults, engine_default_deny);
    }
    for tier in [RuleOutcome::Deny, RuleOutcome::Prompt, RuleOutcome::Allow] {
        if matched(tier) {
            return resolve_precedence(&[tier], policy_defaults, engine_default_deny);
        }
    }
    resolve_precedence(&[], policy_defaults, engine_default_deny)
}

/// Resolve the decision from the matched rule outcomes, the `default_action` of
/// every matching policy, and the engine default. Independent of the order of
/// both slices.
pub(crate) fn resolve_precedence(
    outcomes: &[RuleOutcome],
    policy_defaults: &[PolicyAction],
    engine_default_deny: bool,
) -> Verdict {
    if outcomes.contains(&RuleOutcome::Kill) {
        return Verdict::Kill;
    }
    if outcomes.contains(&RuleOutcome::Deny) {
        return Verdict::Deny;
    }
    if outcomes.contains(&RuleOutcome::Prompt) {
        return Verdict::Prompt;
    }
    if outcomes.contains(&RuleOutcome::Allow) {
        return Verdict::Allow;
    }
    if policy_defaults.contains(&PolicyAction::Deny) {
        return Verdict::PolicyDefaultDeny;
    }
    if policy_defaults.contains(&PolicyAction::Prompt) {
        return Verdict::PolicyDefaultPrompt;
    }
    if policy_defaults.contains(&PolicyAction::Allow) {
        return Verdict::PolicyDefaultAllow;
    }
    if policy_defaults.is_empty() {
        return if engine_default_deny {
            Verdict::EngineDefaultDeny
        } else {
            Verdict::EngineDefaultAllow
        };
    }
    fail_closed_tail()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTCOMES: [RuleOutcome; 5] = [
        RuleOutcome::Kill,
        RuleOutcome::Deny,
        RuleOutcome::Prompt,
        RuleOutcome::Allow,
        RuleOutcome::NoMatch,
    ];
    const ACTIONS: [PolicyAction; 3] = [
        PolicyAction::Deny,
        PolicyAction::Prompt,
        PolicyAction::Allow,
    ];

    /// Every sequence over `alphabet` of length 0..=max_len, in every order.
    fn sequences<T: Copy>(alphabet: &[T], max_len: usize) -> Vec<Vec<T>> {
        let mut all: Vec<Vec<T>> = vec![vec![]];
        let mut frontier: Vec<Vec<T>> = vec![vec![]];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for seq in &frontier {
                for item in alphabet {
                    let mut longer = seq.clone();
                    longer.push(*item);
                    next.push(longer);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    /// Independent statement of the specification: a numeric rank per source,
    /// the highest rank wins. Written differently from `resolve_precedence` on
    /// purpose (rank maximum instead of an if-chain).
    fn spec(outcomes: &[RuleOutcome], defaults: &[PolicyAction], engine_deny: bool) -> Verdict {
        let mut best = (0u8, None::<Verdict>);
        let mut offer = |rank: u8, v: Verdict| {
            if rank > best.0 {
                best = (rank, Some(v));
            }
        };
        for o in outcomes {
            match o {
                RuleOutcome::Kill => offer(10, Verdict::Kill),
                RuleOutcome::Deny => offer(9, Verdict::Deny),
                RuleOutcome::Prompt => offer(8, Verdict::Prompt),
                RuleOutcome::Allow => offer(7, Verdict::Allow),
                RuleOutcome::NoMatch => {}
            }
        }
        for d in defaults {
            match d {
                PolicyAction::Deny => offer(6, Verdict::PolicyDefaultDeny),
                PolicyAction::Prompt => offer(5, Verdict::PolicyDefaultPrompt),
                PolicyAction::Allow => offer(4, Verdict::PolicyDefaultAllow),
            }
        }
        if defaults.is_empty() {
            if engine_deny {
                offer(3, Verdict::EngineDefaultDeny);
            } else {
                offer(2, Verdict::EngineDefaultAllow);
            }
        }
        best.1.unwrap_or(Verdict::FailClosedTail)
    }

    /// Exhaustive over the finite domain: every sequence of up to 4 rule outcomes
    /// (kill, deny, prompt, allow, no-match; every multiset in every order), every
    /// sequence of up to 3 policy defaults, both engine defaults. The result equals
    /// the specification, is unchanged by reordering, and never reaches the tail.
    #[test]
    fn precedence_equals_spec_and_is_order_independent_over_the_finite_domain() {
        let outcome_seqs = sequences(&OUTCOMES, 4);
        let default_seqs = sequences(&ACTIONS, 3);
        assert_eq!(outcome_seqs.len(), 1 + 5 + 25 + 125 + 625);
        assert_eq!(default_seqs.len(), 1 + 3 + 9 + 27);
        let mut seen_tail = 0usize;
        let mut cases = 0usize;
        for outcomes in &outcome_seqs {
            let mut sorted = outcomes.clone();
            sorted.sort_by_key(|o| *o as u8);
            let mut reversed = outcomes.clone();
            reversed.reverse();
            for defaults in &default_seqs {
                let mut sorted_defaults = defaults.clone();
                sorted_defaults.sort_by_key(|a| *a as u8);
                for engine_deny in [true, false] {
                    let got = resolve_precedence(outcomes, defaults, engine_deny);
                    assert_eq!(
                        got,
                        spec(outcomes, defaults, engine_deny),
                        "{outcomes:?} {defaults:?} engine_deny={engine_deny}"
                    );
                    assert_eq!(got, resolve_precedence(&sorted, defaults, engine_deny));
                    assert_eq!(got, resolve_precedence(&reversed, defaults, engine_deny));
                    assert_eq!(
                        got,
                        resolve_precedence(outcomes, &sorted_defaults, engine_deny)
                    );
                    if got == Verdict::FailClosedTail {
                        seen_tail += 1;
                    }
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 781 * 40 * 2);
        // Reachability of the tail from this function: never, in the whole domain.
        assert_eq!(seen_tail, 0, "the fail-closed tail was reached");
    }

    /// The fixed order written out, so a reader does not need the spec helper.
    #[test]
    fn precedence_order_examples() {
        use PolicyAction as A;
        use RuleOutcome as O;
        let r = |o: &[RuleOutcome], d: &[PolicyAction], e| resolve_precedence(o, d, e);
        assert_eq!(r(&[O::Allow, O::Kill], &[A::Allow], false), Verdict::Kill);
        assert_eq!(r(&[O::Allow, O::Deny], &[A::Allow], false), Verdict::Deny);
        assert_eq!(r(&[O::Prompt, O::Deny], &[], false), Verdict::Deny);
        assert_eq!(
            r(&[O::Allow, O::Prompt], &[A::Deny], false),
            Verdict::Prompt
        );
        assert_eq!(r(&[O::Allow], &[A::Deny], true), Verdict::Allow);
        assert_eq!(
            r(&[O::NoMatch], &[A::Allow, A::Deny], false),
            Verdict::PolicyDefaultDeny
        );
        assert_eq!(
            r(&[], &[A::Allow, A::Prompt], false),
            Verdict::PolicyDefaultPrompt
        );
        assert_eq!(r(&[], &[], true), Verdict::EngineDefaultDeny);
        assert_eq!(r(&[], &[], false), Verdict::EngineDefaultAllow);
    }

    /// The tail is unreachable from `resolve_precedence`, so only a direct call
    /// can check it. It is the verdict `decision_for` turns into a denial.
    #[test]
    fn the_unreachable_tail_fails_closed() {
        assert_eq!(fail_closed_tail(), Verdict::FailClosedTail);
        assert!(matches!(
            decision_for(fail_closed_tail(), "r", "d"),
            PolicyDecision::Deny(_)
        ));
    }

    /// Every verdict maps to the decision class the specification gives it, so
    /// the shipped mapping (not only the verdict) is checked, including the tail.
    #[test]
    fn every_verdict_maps_to_its_decision() {
        let deny = |v| matches!(decision_for(v, "r", "d"), PolicyDecision::Deny(_));
        for v in [
            Verdict::Kill,
            Verdict::Deny,
            Verdict::PolicyDefaultDeny,
            Verdict::EngineDefaultDeny,
            Verdict::FailClosedTail,
        ] {
            assert!(deny(v), "{v:?} must deny");
        }
        for v in [Verdict::Prompt, Verdict::PolicyDefaultPrompt] {
            assert_eq!(decision_for(v, "r", "d"), PolicyDecision::Prompt, "{v:?}");
        }
        for v in [
            Verdict::Allow,
            Verdict::PolicyDefaultAllow,
            Verdict::EngineDefaultAllow,
        ] {
            assert_eq!(decision_for(v, "r", "d"), PolicyDecision::Allow, "{v:?}");
        }
        assert_eq!(
            decision_for(Verdict::Deny, "rule-p", "def-p"),
            PolicyDecision::Deny("Denied by policy 'rule-p': rule matched".to_string())
        );
        assert_eq!(
            decision_for(Verdict::PolicyDefaultDeny, "rule-p", "def-p"),
            PolicyDecision::Deny("Denied by policy 'def-p': default action".to_string())
        );
    }

    /// The lazy scan the engine runs equals `resolve_precedence` over the full
    /// outcome set, for every sequence of up to 4 outcomes (so every multiset in
    /// every order), every sequence of up to 3 policy defaults and both engine
    /// defaults. It asks no tier weaker than the one that decided, asks every
    /// stronger tier, and asks nothing once a kill flag is present.
    #[test]
    fn lazy_scan_equals_full_precedence_and_asks_no_weaker_tier() {
        let tiers = [RuleOutcome::Deny, RuleOutcome::Prompt, RuleOutcome::Allow];
        let mut cases = 0usize;
        for outcomes in &sequences(&OUTCOMES, 4) {
            let kill = outcomes.contains(&RuleOutcome::Kill);
            for defaults in &sequences(&ACTIONS, 3) {
                for engine_deny in [true, false] {
                    let mut asked: Vec<RuleOutcome> = Vec::new();
                    let got = resolve_lazily(
                        kill,
                        |t| {
                            asked.push(t);
                            outcomes.contains(&t)
                        },
                        defaults,
                        engine_deny,
                    );
                    assert_eq!(
                        got,
                        resolve_precedence(outcomes, defaults, engine_deny),
                        "{outcomes:?} {defaults:?} engine_deny={engine_deny}"
                    );
                    // Expected questions: tiers in order up to and including the
                    // first present one; none at all under a kill flag.
                    let expected: Vec<RuleOutcome> = if kill {
                        vec![]
                    } else {
                        let mut v = Vec::new();
                        for t in tiers {
                            v.push(t);
                            if outcomes.contains(&t) {
                                break;
                            }
                        }
                        v
                    };
                    assert_eq!(asked, expected, "{outcomes:?}");
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 781 * 40 * 2);
    }
}

#[cfg(kani)]
mod kani_precedence_proofs {
    use super::*;

    fn outcome(n: u8) -> RuleOutcome {
        match n {
            0 => RuleOutcome::Kill,
            1 => RuleOutcome::Deny,
            2 => RuleOutcome::Prompt,
            3 => RuleOutcome::Allow,
            _ => RuleOutcome::NoMatch,
        }
    }

    fn action(n: u8) -> PolicyAction {
        match n {
            0 => PolicyAction::Deny,
            1 => PolicyAction::Prompt,
            _ => PolicyAction::Allow,
        }
    }

    /// Strength of a verdict in the specified order, higher wins.
    fn rank(v: Verdict) -> u8 {
        match v {
            Verdict::Kill => 10,
            Verdict::Deny => 9,
            Verdict::Prompt => 8,
            Verdict::Allow => 7,
            Verdict::PolicyDefaultDeny => 6,
            Verdict::PolicyDefaultPrompt => 5,
            Verdict::PolicyDefaultAllow => 4,
            Verdict::EngineDefaultDeny => 3,
            Verdict::EngineDefaultAllow => 2,
            Verdict::FailClosedTail => 0,
        }
    }

    /// For every list of up to 4 rule outcomes, every list of up to 3 policy
    /// defaults and both engine defaults: the verdict has the highest rank any
    /// source offers, is unchanged by swapping two outcomes or two defaults, and
    /// is never the tail.
    #[kani::proof]
    #[kani::unwind(6)]
    fn precedence_is_the_maximum_rank_and_order_independent() {
        let o: [u8; 4] = kani::any();
        let d: [u8; 3] = kani::any();
        let olen: usize = kani::any();
        let dlen: usize = kani::any();
        kani::assume(olen <= 4 && dlen <= 3);
        let engine_deny: bool = kani::any();
        let i: usize = kani::any();
        let j: usize = kani::any();
        kani::assume(i < 4 && j < 4);
        let k: usize = kani::any();
        let l: usize = kani::any();
        kani::assume(k < 3 && l < 3);

        let mut outs = [RuleOutcome::NoMatch; 4];
        for n in 0..4 {
            outs[n] = outcome(o[n]);
        }
        let mut defs = [PolicyAction::Deny; 3];
        for n in 0..3 {
            defs[n] = action(d[n]);
        }
        let got = resolve_precedence(&outs[..olen], &defs[..dlen], engine_deny);

        // Highest rank offered by any source.
        let mut best = 0u8;
        for n in 0..olen {
            let r = match outs[n] {
                RuleOutcome::Kill => 10,
                RuleOutcome::Deny => 9,
                RuleOutcome::Prompt => 8,
                RuleOutcome::Allow => 7,
                RuleOutcome::NoMatch => 0,
            };
            if r > best {
                best = r;
            }
        }
        for n in 0..dlen {
            let r = match defs[n] {
                PolicyAction::Deny => 6,
                PolicyAction::Prompt => 5,
                PolicyAction::Allow => 4,
            };
            if r > best {
                best = r;
            }
        }
        if dlen == 0 {
            let r = if engine_deny { 3 } else { 2 };
            if r > best {
                best = r;
            }
        }
        assert!(got != Verdict::FailClosedTail);
        assert!(rank(got) == best);

        // Order independence: swap two entries of each list.
        let mut outs2 = outs;
        outs2.swap(i, j);
        let mut defs2 = defs;
        defs2.swap(k, l);
        // A swap that moves an entry across the length boundary changes the
        // prefix, so only compare when both indices are inside (or both outside).
        if (i < olen) == (j < olen) && (k < dlen) == (l < dlen) {
            let again = resolve_precedence(&outs2[..olen], &defs2[..dlen], engine_deny);
            assert!(again == got);
        }

        kani::cover!(got == Verdict::Kill, "kill decides");
        kani::cover!(got == Verdict::Deny, "deny decides");
        kani::cover!(got == Verdict::Prompt, "prompt decides");
        kani::cover!(got == Verdict::Allow, "allow decides");
        kani::cover!(
            got == Verdict::PolicyDefaultDeny,
            "policy default deny decides"
        );
        kani::cover!(
            got == Verdict::PolicyDefaultPrompt,
            "policy default prompt decides"
        );
        kani::cover!(
            got == Verdict::PolicyDefaultAllow,
            "policy default allow decides"
        );
        kani::cover!(
            got == Verdict::EngineDefaultDeny,
            "engine default deny decides"
        );
        kani::cover!(
            got == Verdict::EngineDefaultAllow,
            "engine default allow decides"
        );
    }

    /// The lazy scan equals the full resolver for every list of up to 4 outcomes
    /// (membership is all the engine's tier scan can observe), and under a kill
    /// flag it asks about no tier.
    #[kani::proof]
    #[kani::unwind(6)]
    fn lazy_scan_equals_full_precedence() {
        let o: [u8; 4] = kani::any();
        let d: [u8; 3] = kani::any();
        let olen: usize = kani::any();
        let dlen: usize = kani::any();
        kani::assume(olen <= 4 && dlen <= 3);
        let engine_deny: bool = kani::any();
        let mut outs = [RuleOutcome::NoMatch; 4];
        for n in 0..4 {
            outs[n] = outcome(o[n]);
        }
        let mut defs = [PolicyAction::Deny; 3];
        for n in 0..3 {
            defs[n] = action(d[n]);
        }
        let outs = &outs[..olen];
        let defs = &defs[..dlen];
        let kill = outs.contains(&RuleOutcome::Kill);
        let mut asked = 0u8;
        let got = resolve_lazily(
            kill,
            |t| {
                asked += 1;
                outs.contains(&t)
            },
            defs,
            engine_deny,
        );
        assert!(got == resolve_precedence(outs, defs, engine_deny));
        if kill {
            assert!(asked == 0);
        }
        assert!(asked <= 3);
        kani::cover!(kill, "kill present");
        kani::cover!(!kill && got == Verdict::Allow, "allow tier decides lazily");
        kani::cover!(
            !kill && got == Verdict::Prompt,
            "prompt tier decides lazily"
        );
        kani::cover!(!kill && got == Verdict::Deny, "deny tier decides lazily");
        kani::cover!(
            !kill && got == Verdict::PolicyDefaultAllow,
            "no tier matched"
        );
    }
}
