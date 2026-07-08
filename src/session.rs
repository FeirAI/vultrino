//! In-flight execution session registry and halt callbacks (V6).
//!
//! A [`SessionRegistry`] records the gated executions currently running in this
//! process, keyed by a per-execution id, so a halt can see what an agent is
//! doing right now and fire any registered abort callback. It is **in-memory and
//! per-process** — the same model and limitations as the policy engine's
//! rate-limit counters: it resets on restart, and in a web+MCP deployment
//! each process only sees the executions it is running.
//!
//! Halt has two cross-process, storage-authoritative legs (revoke the agent's
//! use tokens; install an authoritative per-agent kill policy) plus this
//! per-process leg (fire abort callbacks for what's in flight here). Without a
//! harness abort primitive the achievable semantics is "deny the next gated
//! call"; with a registered [`HaltCallback`] an in-flight execution can be
//! actively preempted.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Notify;

/// A record of one in-flight gated execution (V6). Carries no secrets.
#[derive(Debug, Clone, Serialize)]
pub struct SessionEntry {
    /// Unique id for this execution (the request id).
    pub session_id: String,
    /// Agent label of the principal, if any (a halt target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    /// Resolved principal id (key/token id), if authenticated — the other halt
    /// target, so a label-less agent halted by id is matched too.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Use-token id the execution is spending, if token-authorized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// Credential alias being used.
    pub credential: String,
    /// Fully-qualified action (`plugin.action`).
    pub action: String,
    /// When the execution started.
    pub started_at: DateTime<Utc>,
}

/// Per-process registry of in-flight executions (V6).
#[derive(Default)]
pub struct SessionRegistry {
    sessions: RwLock<HashMap<String, SessionEntry>>,
    /// Per-session abort handles, keyed by `session_id`. Kept in a SEPARATE map so
    /// [`SessionEntry`] stays a pure serializable record (it's surfaced in the halt
    /// API). A streaming execution `select!`s on its handle so a halt cancels it
    /// mid-stream (the in-process leg of a halt, beyond "deny the next call").
    aborts: RwLock<HashMap<String, Arc<Notify>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an in-flight execution; returns an RAII [`SessionGuard`] that
    /// deregisters it on drop (so an early return or panic still clears it) PLUS a
    /// cloneable abort handle. A long-lived execution (a stream) should `select!` on
    /// `notified()` so [`Self::signal_halt`] can cancel it; a buffered execution can
    /// ignore the handle (halt's token-revoke + kill-policy legs still apply).
    pub fn begin(self: &Arc<Self>, entry: SessionEntry) -> (SessionGuard, Arc<Notify>) {
        let session_id = entry.session_id.clone();
        let abort = Arc::new(Notify::new());
        self.sessions.write().insert(session_id.clone(), entry);
        self.aborts
            .write()
            .insert(session_id.clone(), Arc::clone(&abort));
        (
            SessionGuard {
                registry: Arc::clone(self),
                session_id,
            },
            abort,
        )
    }

    /// Signal an abort to every in-flight session matching a **halt target** (the
    /// same predicate the kill policy + [`Self::for_halt_target`] use: agent label OR
    /// principal id OR token id). Each matched session's `select!` on its abort
    /// handle wakes and tears the stream down. Returns the number signalled. This is
    /// the per-process leg of a halt; the cross-process legs (token revoke + kill
    /// policy) still apply to everything else.
    pub fn signal_halt(&self, target: &str) -> usize {
        let ids: Vec<String> = {
            let sessions = self.sessions.read();
            sessions
                .values()
                .filter(|s| {
                    s.agent_label.as_deref() == Some(target)
                        || s.principal_id.as_deref() == Some(target)
                        || s.token_id.as_deref() == Some(target)
                })
                .map(|s| s.session_id.clone())
                .collect()
        };
        let aborts = self.aborts.read();
        let mut signalled = 0;
        for id in &ids {
            if let Some(abort) = aborts.get(id) {
                // `notify_one` (not `notify_waiters`) so the signal is NOT lost if the
                // stream hasn't reached its `select!` on `notified()` yet: a permit is
                // stored and the next poll completes immediately. Each session has its
                // own handle with a single waiter (the adaptor), so one permit suffices.
                abort.notify_one();
                signalled += 1;
            }
        }
        signalled
    }

    /// A snapshot of all in-flight sessions.
    pub fn list(&self) -> Vec<SessionEntry> {
        self.sessions.read().values().cloned().collect()
    }

    /// In-flight sessions for a given agent label.
    pub fn for_agent(&self, label: &str) -> Vec<SessionEntry> {
        self.sessions
            .read()
            .values()
            .filter(|s| s.agent_label.as_deref() == Some(label))
            .cloned()
            .collect()
    }

    /// In-flight sessions matching a **halt target** — the same target the kill
    /// policy matches: the principal's agent label OR its principal/token id. So
    /// a label-less agent halted by id has its sessions found here too.
    pub fn for_halt_target(&self, target: &str) -> Vec<SessionEntry> {
        self.sessions
            .read()
            .values()
            .filter(|s| {
                s.agent_label.as_deref() == Some(target)
                    || s.principal_id.as_deref() == Some(target)
                    || s.token_id.as_deref() == Some(target)
            })
            .cloned()
            .collect()
    }

    /// Number of in-flight sessions (test/observability helper).
    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    /// Whether there are no in-flight sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.read().is_empty()
    }
}

/// RAII guard returned by [`SessionRegistry::begin`]: deregisters its session on
/// drop so the registry reflects only genuinely in-flight executions.
pub struct SessionGuard {
    registry: Arc<SessionRegistry>,
    session_id: String,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.registry.sessions.write().remove(&self.session_id);
        self.registry.aborts.write().remove(&self.session_id);
    }
}

/// A harness abort callback (V6). On halt, this is fired (best-effort) for an
/// agent's in-flight sessions. Where a harness exposes an abort/pause primitive,
/// register one to actively preempt in-flight work; without one, halt still
/// denies the agent's next gated call via the kill policy + token revocation.
#[async_trait::async_trait]
pub trait HaltCallback: Send + Sync {
    /// Channel/integration name, for logging.
    fn name(&self) -> &str;
    /// Fired when `agent_label` is halted, with its in-flight sessions.
    async fn on_halt(&self, agent_label: &str, in_flight: &[SessionEntry]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, label: Option<&str>) -> SessionEntry {
        SessionEntry {
            session_id: id.to_string(),
            agent_label: label.map(str::to_string),
            principal_id: None,
            token_id: None,
            credential: "cred".to_string(),
            action: "mock.echo".to_string(),
            started_at: Utc::now(),
        }
    }

    #[test]
    fn test_registry_begin_list_and_guard_drop() {
        let reg = Arc::new(SessionRegistry::new());
        assert!(reg.is_empty());
        {
            let (_g1, _a1) = reg.begin(entry("s1", Some("bot-7")));
            let (_g2, _a2) = reg.begin(entry("s2", Some("bot-9")));
            let (_g3, _a3) = reg.begin(entry("s3", None));
            assert_eq!(reg.len(), 3);
            assert_eq!(reg.for_agent("bot-7").len(), 1);
            assert_eq!(reg.for_agent("bot-7")[0].session_id, "s1");
            assert_eq!(reg.for_agent("absent").len(), 0);

            // for_halt_target matches by principal id and token id independently
            // (distinct values so each match arm is exercised on its own).
            let (by_id, _a4) = reg.begin(SessionEntry {
                session_id: "s4".to_string(),
                agent_label: None,
                principal_id: Some("vk_principal".to_string()),
                token_id: Some("vut_token".to_string()),
                credential: "cred".to_string(),
                action: "mock.echo".to_string(),
                started_at: Utc::now(),
            });
            assert_eq!(
                reg.for_halt_target("vk_principal").len(),
                1,
                "matched by principal id"
            );
            assert_eq!(
                reg.for_halt_target("vut_token").len(),
                1,
                "matched by token id"
            );
            assert_eq!(reg.for_halt_target("bot-7").len(), 1, "matched by label");
            assert_eq!(
                reg.for_agent("vk_principal").len(),
                0,
                "for_agent is label-only"
            );
            drop(by_id);
        }
        // All guards dropped → registry is empty again.
        assert!(reg.is_empty(), "guards should deregister on drop");
    }

    #[test]
    fn test_guard_drop_is_scoped_per_session() {
        let reg = Arc::new(SessionRegistry::new());
        let (g1, _a1) = reg.begin(entry("s1", Some("bot-7")));
        {
            let (_g2, _a2) = reg.begin(entry("s2", Some("bot-7")));
            assert_eq!(reg.for_agent("bot-7").len(), 2);
        }
        assert_eq!(reg.for_agent("bot-7").len(), 1, "only s2 removed");
        drop(g1);
        assert!(reg.is_empty());
    }

    #[tokio::test]
    async fn test_signal_halt_wakes_matching_session_abort() {
        let reg = Arc::new(SessionRegistry::new());
        let (_g1, abort1) = reg.begin(entry("s1", Some("bot-7")));
        let (_g2, abort2) = reg.begin(entry("s2", Some("bot-9")));

        // A waiter on bot-7's abort handle.
        let waiter = {
            let abort1 = Arc::clone(&abort1);
            tokio::spawn(async move { abort1.notified().await })
        };
        // Give the waiter a moment to register, then halt bot-7.
        tokio::task::yield_now().await;
        let signalled = reg.signal_halt("bot-7");
        assert_eq!(signalled, 1, "exactly bot-7's session is signalled");

        // The matched waiter wakes; the unmatched handle is untouched.
        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("halt must wake the matched session within 2s")
            .unwrap();
        assert_eq!(
            reg.signal_halt("bot-9"),
            1,
            "bot-9 still present + signallable"
        );
        let _ = abort2;
    }

    #[test]
    fn test_guard_drop_removes_abort_handle() {
        let reg = Arc::new(SessionRegistry::new());
        let (g1, _a1) = reg.begin(entry("s1", Some("bot-7")));
        assert_eq!(reg.signal_halt("bot-7"), 1);
        drop(g1);
        // After the guard drops, there is no abort handle left to signal.
        assert_eq!(
            reg.signal_halt("bot-7"),
            0,
            "abort handle removed with the session"
        );
    }
}
