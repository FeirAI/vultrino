//! The durable kill fence (P3-KILL; BACKLOG XV-03).
//!
//! The policy engine is per process. It loads stored policies at an admin reload
//! and on the periodic refresh, so a kill policy stored through one process
//! reaches another process's engine only at that process's next refresh, and
//! any process can evaluate work before a kill lands and dispatch it after.
//! govder could therefore report a kill as contained while another vultrino
//! process (or a resume already past its policy evaluation) still dispatched.
//!
//! The fence closes that gap without reading the engine. Immediately before
//! every plugin dispatch (buffered and streamed; live calls and every approval
//! resume path), at approval claim time and at approval open, the vault itself
//! is read under its cross-process lock, and the work is refused when:
//!
//! * a stored kill policy matches the work's principal and credential (the
//!   agent is halted now), with the same matching as the engine's kill check
//!   ([`super::PolicyEngine::is_halted`]); or
//! * a kill policy matching it was stored at a kill epoch later than the epoch
//!   the work was admitted under, even if that kill policy has since been
//!   deleted (a lift). Work admitted before a kill never runs after it.
//!
//! The epoch and the per-policy marks live in the vault next to the policies and
//! are written in the same locked mutation as the kill policy itself, so they are
//! as durable, and as visible to every process sharing the vault, as the kill.
//! Model: govder `formal/tla/KillFence.tla`.

use super::{credential_matches, principal_matches, Policy, Principal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A durable record that a kill policy was stored at a kill epoch. It is kept
/// after the policy is deleted, so a lift never re-admits work that was admitted
/// before the kill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillMark {
    /// The kill policy's credential pattern when it was stored.
    pub credential_pattern: String,
    /// The kill policy's principal pattern when it was stored (`None` = every principal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_pattern: Option<String>,
    /// The kill epoch this store produced.
    pub epoch: u64,
    /// When the kill policy was stored. Marks written before v10 carry none and are stamped at
    /// migration; a mark with no timestamp is never garbage-collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The fence state kept in the vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillFenceState {
    /// Bumped by every kill policy store. Never decreases.
    #[serde(default)]
    pub epoch: u64,
    /// The last epoch at which each kill policy id was stored, kept after delete.
    #[serde(default)]
    pub marks: BTreeMap<String, KillMark>,
}

impl KillFenceState {
    /// Record a policy store. A kill policy bumps the epoch and (re)marks its id;
    /// any other policy leaves the fence unchanged. Returns the new epoch for a
    /// kill policy.
    pub fn record_store(&mut self, policy: &Policy) -> Option<u64> {
        if !policy.kill {
            return None;
        }
        self.epoch = self.epoch.saturating_add(1);
        self.marks.insert(
            policy.id.clone(),
            KillMark {
                credential_pattern: policy.credential_pattern.clone(),
                principal_pattern: policy.principal_pattern.clone(),
                epoch: self.epoch,
                stored_at: Some(chrono::Utc::now()),
            },
        );
        Some(self.epoch)
    }

    /// Give every mark that has no timestamp one (the v10 migration), so garbage collection can
    /// age it. Returns how many were stamped.
    pub fn stamp_unstamped(&mut self, now: chrono::DateTime<chrono::Utc>) -> usize {
        let mut n = 0;
        for mark in self.marks.values_mut() {
            if mark.stored_at.is_none() {
                mark.stored_at = Some(now);
                n += 1;
            }
        }
        n
    }
}

/// A kill mark older than this (and otherwise dead, see [`dead_kill_marks`]) is garbage-collected.
/// It must exceed the longest time work can sit between its admission (the epoch snapshot taken
/// before policy evaluation) and its dispatch. Approvals are tracked explicitly, so this bounds the
/// only other holder of an admission epoch: a live request in flight inside one process. 24 hours is
/// orders of magnitude above any request timeout.
pub const KILL_MARK_GC_GRACE_SECS: i64 = 24 * 60 * 60;

/// The ids of kill marks that can be dropped without ever re-admitting killed work.
///
/// A mark can only refuse work whose admission epoch is lower than the mark's epoch, and only
/// while no stored kill policy already refuses the work outright. So a mark is dead when ALL hold:
///
/// 1. its kill policy is no longer stored as a kill (it was lifted or replaced),
/// 2. it carries a `stored_at` at least [`KILL_MARK_GC_GRACE_SECS`] old, and
/// 3. no live admission could still be refused by it: every admission epoch in `live_admitted`
///    (one per approval that has not finished and can still be claimed) is at or above the mark's
///    epoch.
///
/// A mark with no timestamp, a mark whose policy is still a stored kill, and a mark an older live
/// admission still depends on are all kept. The kill epoch itself is never lowered.
pub fn dead_kill_marks(
    state: &KillFenceState,
    is_stored_kill: impl Fn(&str) -> bool,
    live_admitted: impl IntoIterator<Item = u64>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<String> {
    let oldest_live = live_admitted.into_iter().min();
    state
        .marks
        .iter()
        .filter(|(id, mark)| {
            !is_stored_kill(id)
                && mark
                    .stored_at
                    .is_some_and(|t| (now - t).num_seconds() >= KILL_MARK_GC_GRACE_SECS)
                && oldest_live.is_none_or(|e| e >= mark.epoch)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// What the fence is asked about: the work's credential, its principal, and the
/// kill epoch it was admitted under.
#[derive(Debug, Clone, Copy)]
pub struct KillFenceQuery<'a> {
    /// The credential alias the work runs against.
    pub credential_alias: &'a str,
    /// The principal the work runs as (`None`: a local, principal-less request,
    /// which no principal-scoped kill matches, exactly as in the engine).
    pub principal: Option<&'a Principal>,
    /// The kill epoch the work was admitted under. Work admitted before this
    /// build recorded one is checked with 0, so any later kill refuses it.
    pub admitted_epoch: u64,
}

/// The fence's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillFenceVerdict {
    /// No stored kill policy matches, and none was stored after admission.
    Clear,
    /// A stored kill policy matches: the agent is halted now.
    Halted { policy_id: String },
    /// A kill policy matching the work was stored after its admission epoch
    /// (it may have been lifted since).
    KilledSinceAdmission { policy_id: String, epoch: u64 },
}

impl KillFenceVerdict {
    /// Whether the work may proceed.
    pub fn is_clear(&self) -> bool {
        matches!(self, KillFenceVerdict::Clear)
    }

    /// The refusal reason shown to the caller and recorded on a refused approval.
    pub fn refusal_reason(&self) -> Option<String> {
        match self {
            KillFenceVerdict::Clear => None,
            KillFenceVerdict::Halted { policy_id } => Some(format!(
                "the agent is halted (kill policy '{policy_id}'); nothing ran"
            )),
            KillFenceVerdict::KilledSinceAdmission { policy_id, epoch } => Some(format!(
                "the agent was killed (kill policy '{policy_id}', kill epoch {epoch}) after this \
                 work was admitted; nothing ran, submit it again"
            )),
        }
    }
}

/// Judge the fence over the stored policies and the fence state read from the
/// vault. A matching stored kill policy wins over an epoch mark; ties are broken
/// by policy id so the answer is deterministic.
pub fn kill_fence_verdict<'p>(
    stored: impl IntoIterator<Item = &'p Policy>,
    state: &KillFenceState,
    query: &KillFenceQuery<'_>,
) -> KillFenceVerdict {
    let mut halted: Vec<&str> = stored
        .into_iter()
        .filter(|p| {
            p.kill
                && credential_matches(&p.credential_pattern, query.credential_alias)
                && principal_matches(p.principal_pattern.as_deref(), query.principal)
        })
        .map(|p| p.id.as_str())
        .collect();
    halted.sort_unstable();
    if let Some(id) = halted.first() {
        return KillFenceVerdict::Halted {
            policy_id: (*id).to_string(),
        };
    }
    // BTreeMap order: the first matching mark by policy id.
    for (id, mark) in &state.marks {
        if mark.epoch > query.admitted_epoch
            && credential_matches(&mark.credential_pattern, query.credential_alias)
            && principal_matches(mark.principal_pattern.as_deref(), query.principal)
        {
            return KillFenceVerdict::KilledSinceAdmission {
                policy_id: id.clone(),
                epoch: mark.epoch,
            };
        }
    }
    KillFenceVerdict::Clear
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(id: &str, label: Option<&str>) -> Principal {
        Principal {
            id: id.to_string(),
            agent_label: label.map(str::to_string),
            owner: None,
            workload_id: None,
        }
    }

    fn query<'a>(cred: &'a str, p: Option<&'a Principal>, adm: u64) -> KillFenceQuery<'a> {
        KillFenceQuery {
            credential_alias: cred,
            principal: p,
            admitted_epoch: adm,
        }
    }

    #[test]
    fn a_kill_store_bumps_the_epoch_and_a_non_kill_store_does_not() {
        let mut s = KillFenceState::default();
        assert_eq!(s.record_store(&Policy::allow_all("a", "*")), None);
        assert_eq!(s.epoch, 0);
        assert_eq!(s.record_store(&Policy::kill_switch("halt:x", "x")), Some(1));
        assert_eq!(s.record_store(&Policy::kill_switch("halt:x", "x")), Some(2));
        assert_eq!(s.marks["halt:x"].epoch, 2);
    }

    #[test]
    fn a_stored_kill_halts_its_principal_on_every_credential_and_no_one_else() {
        let kill = Policy::kill_switch("halt:agent-k", "agent-k");
        let mut s = KillFenceState::default();
        s.record_store(&kill);
        let by_label = principal("vut_1", Some("agent-k"));
        let by_id = principal("agent-k", None);
        let other = principal("vut_2", Some("agent-j"));
        for p in [&by_label, &by_id] {
            assert_eq!(
                kill_fence_verdict([&kill], &s, &query("any-cred", Some(p), 1)),
                KillFenceVerdict::Halted {
                    policy_id: "halt:agent-k".to_string()
                }
            );
        }
        assert!(kill_fence_verdict([&kill], &s, &query("any-cred", Some(&other), 0)).is_clear());
        // A principal-less request is never matched by a principal-scoped kill (engine parity).
        assert!(kill_fence_verdict([&kill], &s, &query("any-cred", None, 0)).is_clear());
    }

    #[test]
    fn a_credential_scoped_kill_matches_only_its_credentials() {
        let kill = Policy::deny_all("kill-1", "pay-*").with_principal("agent-k");
        let kill = Policy { kill: true, ..kill };
        let mut s = KillFenceState::default();
        s.record_store(&kill);
        let p = principal("vut_1", Some("agent-k"));
        assert!(!kill_fence_verdict([&kill], &s, &query("pay-main", Some(&p), 1)).is_clear());
        assert!(kill_fence_verdict([&kill], &s, &query("read-only", Some(&p), 0)).is_clear());
    }

    #[test]
    fn a_lifted_kill_still_refuses_work_admitted_before_it() {
        let kill = Policy::kill_switch("halt:agent-k", "agent-k");
        let mut s = KillFenceState::default();
        s.record_store(&kill);
        let p = principal("vut_1", Some("agent-k"));
        // Lifted: the policy is no longer stored, its mark stays.
        let stored: [&Policy; 0] = [];
        assert_eq!(
            kill_fence_verdict(stored, &s, &query("c", Some(&p), 0)),
            KillFenceVerdict::KilledSinceAdmission {
                policy_id: "halt:agent-k".to_string(),
                epoch: 1
            }
        );
        // Work admitted at or after the kill epoch is not refused by the mark.
        assert!(kill_fence_verdict(stored, &s, &query("c", Some(&p), 1)).is_clear());
    }

    #[test]
    fn a_non_kill_deny_is_not_a_fence() {
        let deny = Policy::deny_all("deny-1", "*").with_principal("agent-k");
        let mut s = KillFenceState::default();
        s.record_store(&deny);
        let p = principal("vut_1", Some("agent-k"));
        assert!(kill_fence_verdict([&deny], &s, &query("c", Some(&p), 0)).is_clear());
    }

    fn mark(epoch: u64, age_hours: i64, now: chrono::DateTime<chrono::Utc>) -> KillMark {
        KillMark {
            credential_pattern: "x".into(),
            principal_pattern: None,
            epoch,
            stored_at: Some(now - chrono::Duration::hours(age_hours)),
        }
    }

    fn state_with(marks: Vec<(&str, KillMark)>) -> KillFenceState {
        let epoch = marks.iter().map(|(_, m)| m.epoch).max().unwrap_or(0);
        KillFenceState {
            epoch,
            marks: marks.into_iter().map(|(k, m)| (k.to_string(), m)).collect(),
        }
    }

    #[test]
    fn dead_marks_need_a_lifted_policy_an_old_stamp_and_no_older_live_admission() {
        let now = chrono::Utc::now();
        let st = state_with(vec![
            ("lifted-old", mark(1, 30, now)),
            ("lifted-young", mark(2, 1, now)),
            ("stored-old", mark(3, 30, now)),
            ("lifted-old-2", mark(4, 30, now)),
        ]);
        let stored = |id: &str| id == "stored-old";
        // No live admissions: only the lifted, old marks go.
        let mut dead = dead_kill_marks(&st, stored, [], now);
        dead.sort();
        assert_eq!(
            dead,
            vec!["lifted-old".to_string(), "lifted-old-2".to_string()]
        );
        // A live admission at epoch 2 depends on marks above 2 (it is refused by them), so the
        // epoch-4 mark stays; the epoch-1 mark cannot refuse it and goes.
        let dead = dead_kill_marks(&st, stored, [2], now);
        assert_eq!(dead, vec!["lifted-old".to_string()]);
        // A live admission at epoch 0 (an approval from before epochs existed) keeps all of them.
        assert!(dead_kill_marks(&st, stored, [0], now).is_empty());
        // The oldest live admission decides, not the newest.
        assert!(dead_kill_marks(&st, stored, [9, 0, 5], now).is_empty());
    }

    #[test]
    fn a_mark_without_a_timestamp_is_never_dead_and_the_grace_boundary_is_inclusive() {
        let now = chrono::Utc::now();
        let mut unstamped = mark(1, 0, now);
        unstamped.stored_at = None;
        let st = state_with(vec![
            ("unstamped", unstamped),
            ("just-inside", mark(2, 23, now)),
            ("exact", {
                let mut m = mark(3, 0, now);
                m.stored_at = Some(now - chrono::Duration::seconds(KILL_MARK_GC_GRACE_SECS));
                m
            }),
        ]);
        assert_eq!(
            dead_kill_marks(&st, |_| false, [], now),
            vec!["exact".to_string()]
        );
    }

    #[test]
    fn stamping_gives_every_unstamped_mark_a_timestamp_and_leaves_the_rest() {
        let now = chrono::Utc::now();
        let mut old = mark(1, 5, now);
        let keep = old.stored_at;
        let mut unstamped = mark(2, 0, now);
        unstamped.stored_at = None;
        old.epoch = 1;
        let mut st = state_with(vec![("a", old), ("b", unstamped)]);
        assert_eq!(st.stamp_unstamped(now), 1);
        assert_eq!(st.marks["a"].stored_at, keep);
        assert_eq!(st.marks["b"].stored_at, Some(now));
    }
}
