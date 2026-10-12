//! P3-VAULT tests: write cost, shared-lock fence reads, crash consistency, kill-mark GC and the
//! v9 migration. Everything here asserts bytes, records, files and states, never wall time.

use super::*;
use crate::auth::NewUseToken;
use crate::policy::{KillFenceQuery, KillFenceVerdict};
use crate::{CredentialData, Secret};
use tempfile::tempdir;

const PW: &str = "pw";

async fn open(path: &Path) -> FileStorage {
    FileStorage::new(path, &SecretString::from(PW))
        .await
        .unwrap()
}

fn token(i: usize) -> UseToken {
    let (_p, t) = UseToken::create(NewUseToken {
        name: format!("tok-{i}"),
        credential_scope: "*".into(),
        action_scope: None,
        max_uses: Some(5),
        require_approval: false,
        expires_in: None,
    });
    t
}

fn cred(alias: &str) -> Credential {
    Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new(format!("secret-{alias}")),
            header_name: "Authorization".into(),
            header_prefix: "Bearer ".into(),
        },
    )
}

fn kill(id: &str, cred_pat: &str) -> Policy {
    let mut p = Policy::allow_all(id, cred_pat);
    p.id = id.to_string();
    p.kill = true;
    p
}

fn q(alias: &str, admitted_epoch: u64) -> KillFenceQuery<'_> {
    KillFenceQuery {
        credential_alias: alias,
        principal: None,
        admitted_epoch,
    }
}

fn wal_lines(path: &Path) -> usize {
    std::fs::read(path.with_extension("wal"))
        .unwrap_or_default()
        .iter()
        .filter(|b| **b == b'\n')
        .count()
}

// ---------------------------------------------------------------- write cost

#[tokio::test]
async fn write_cost_does_not_grow_with_unrelated_records() {
    // One admin write touches one record, whatever else the vault holds: same bytes, one record,
    // one log line, no decrypt of anything, no snapshot rewrite. Counted, not timed.
    let mut measured = Vec::new();
    for n in [0usize, 60, 400] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let s = open(&path).await;
        s.verify_replay
            .store(false, std::sync::atomic::Ordering::Relaxed);
        s.set_compact_min_bytes(u64::MAX);
        for i in 0..n {
            s.store_use_token(&token(i)).await.unwrap();
        }
        let snapshot_before = std::fs::read(&path).unwrap();
        let lines_before = wal_lines(&path);
        let a = s.io_stats();
        s.store_policy(&Policy::allow_all("probe", "probe-*"))
            .await
            .unwrap();
        let d = s.io_stats().since(a);
        assert_eq!(
            d.records_written, 1,
            "n={n}: exactly the one changed record"
        );
        assert_eq!(d.decrypts, 0, "n={n}: a write decrypts nothing");
        assert_eq!(d.bytes_decrypted, 0, "n={n}");
        assert_eq!(
            wal_lines(&path),
            lines_before + 1,
            "n={n}: one log line appended"
        );
        assert_eq!(
            snapshot_before,
            std::fs::read(&path).unwrap(),
            "n={n}: the snapshot is not rewritten by a write"
        );
        measured.push(d.bytes_written);
    }
    let (lo, hi) = (
        *measured.iter().min().unwrap(),
        *measured.iter().max().unwrap(),
    );
    assert!(
        hi <= lo + 16,
        "bytes written per write must not depend on vault size: {measured:?}"
    );
}

#[tokio::test]
async fn a_provision_burst_costs_its_own_writes_not_the_vault_size() {
    let mut per_burst = Vec::new();
    for n in [0usize, 300] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let s = open(&path).await;
        s.verify_replay
            .store(false, std::sync::atomic::Ordering::Relaxed);
        s.set_compact_min_bytes(u64::MAX);
        for i in 0..n {
            s.store_use_token(&token(i)).await.unwrap();
        }
        let a = s.io_stats();
        for i in 0..40 {
            s.store_use_token(&token(10_000 + i)).await.unwrap();
        }
        let d = s.io_stats().since(a);
        assert_eq!(d.records_written, 40);
        assert_eq!(d.bytes_decrypted, 0);
        per_burst.push(d.bytes_written);
    }
    assert!(
        per_burst[1] <= per_burst[0] + 40 * 16,
        "a 40-write burst must cost the same at 0 and 300 stored tokens: {per_burst:?}"
    );
}

#[tokio::test]
async fn a_closure_that_changes_nothing_writes_nothing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.store(&cred("a")).await.unwrap();
    let a = s.io_stats();
    let lines = wal_lines(&path);
    s.locked_mutate(|_| Ok(())).await.unwrap();
    assert_eq!(s.io_stats().since(a).bytes_written, 0);
    assert_eq!(wal_lines(&path), lines);
}

#[tokio::test]
async fn an_aborted_mutation_rolls_back_memory_and_writes_nothing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.store(&cred("keep")).await.unwrap();
    let t = token(1);
    s.store_use_token(&t).await.unwrap();
    let a = s.io_stats();
    let tid = t.id.clone();
    let err = s
        .locked_mutate(move |c| {
            c.use_tokens.remove(&tid);
            let (_p, extra) = UseToken::create(NewUseToken {
                name: "x".into(),
                credential_scope: "*".into(),
                action_scope: None,
                max_uses: Some(1),
                require_approval: false,
                expires_in: None,
            });
            c.use_tokens.insert(extra.id.clone(), extra);
            c.pending_events.clear();
            Err::<(), _>(StorageError::Conflict("abort".into()))
        })
        .await;
    assert!(err.is_err());
    assert_eq!(s.io_stats().since(a).bytes_written, 0, "nothing committed");
    assert!(
        s.get_use_token(&t.id).await.unwrap().is_some(),
        "the removed token is back"
    );
    assert_eq!(
        s.list_use_tokens().await.unwrap().len(),
        1,
        "the inserted token is gone"
    );
    let s2 = open(&path).await;
    assert_eq!(s2.list_use_tokens().await.unwrap().len(), 1);
}

// ------------------------------------------------------------- fence reads

#[tokio::test]
async fn an_unchanged_vault_fence_read_decrypts_nothing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    for i in 0..50 {
        s.store_use_token(&token(i)).await.unwrap();
    }
    let a = s.io_stats();
    for _ in 0..5 {
        assert!(s
            .kill_fence_check(&q("gh-main", 0))
            .await
            .unwrap()
            .is_clear());
    }
    let d = s.io_stats().since(a);
    assert_eq!(
        (d.decrypts, d.bytes_decrypted, d.bytes_written, d.fsyncs),
        (0, 0, 0, 0)
    );
}

#[tokio::test]
async fn a_fence_read_after_a_foreign_write_decrypts_only_that_record() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let a = open(&path).await;
    a.set_compact_min_bytes(u64::MAX);
    for i in 0..200 {
        a.store_use_token(&token(i)).await.unwrap();
    }
    let b = open(&path).await;
    b.set_compact_min_bytes(u64::MAX);
    let before = b.io_stats();
    a.store_policy(&kill("k-foreign", "gh-*")).await.unwrap();
    let verdict = b.kill_fence_check(&q("gh-main", 0)).await.unwrap();
    assert!(
        matches!(verdict, KillFenceVerdict::Halted { ref policy_id } if policy_id == "k-foreign"),
        "{verdict:?}"
    );
    let d = b.io_stats().since(before);
    assert_eq!(d.decrypts, 1, "exactly the one appended record");
    assert!(d.bytes_decrypted < 2_000, "not the vault: {d:?}");
}

#[tokio::test]
async fn the_fence_sees_another_handles_kill_and_its_lift_without_a_reload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let a = open(&path).await;
    let b = open(&path).await;
    let epoch0 = b.kill_fence_epoch().await;
    a.store_policy(&kill("k1", "gh-*")).await.unwrap();
    assert!(matches!(
        b.kill_fence_check(&q("gh-main", epoch0)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
    a.delete_policy("k1").await.unwrap();
    // Lifted: nothing is stored, but work admitted before the kill is still refused.
    assert!(matches!(
        b.kill_fence_check(&q("gh-main", epoch0)).await.unwrap(),
        KillFenceVerdict::KilledSinceAdmission { .. }
    ));
    // Work admitted after the kill is clear.
    let now_epoch = a.kill_fence_epoch().await;
    assert!(b
        .kill_fence_check(&q("gh-main", now_epoch))
        .await
        .unwrap()
        .is_clear());
}

#[tokio::test]
async fn fence_reads_hold_the_lock_shared_so_dispatches_do_not_serialize() {
    // With a shared holder in place a second fence read still completes; under the old exclusive
    // lock it would block until the holder released.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = std::sync::Arc::new(open(&path).await);
    let holder = open(&path).await;
    let flock = holder.lock_file().unwrap();
    let guard = flock.read().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let s2 = std::sync::Arc::clone(&s);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let v = rt.block_on(s2.kill_fence_check(&q("gh-main", 0))).unwrap();
        tx.send(v.is_clear()).unwrap();
    });
    let got = rx.recv_timeout(std::time::Duration::from_secs(10));
    assert_eq!(
        got,
        Ok(true),
        "a fence read must not wait behind a shared holder"
    );
    drop(guard);
}

#[tokio::test]
async fn a_writer_still_excludes_fence_readers() {
    // The other half: the fence only sees committed state because a writer holds the lock
    // exclusively, so a reader started while a writer holds it must wait.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = std::sync::Arc::new(open(&path).await);
    let holder = open(&path).await;
    let mut flock = holder.lock_file().unwrap();
    let guard = flock.write().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let s2 = std::sync::Arc::clone(&s);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let v = rt.block_on(s2.kill_fence_check(&q("gh-main", 0))).unwrap();
        tx.send(v.is_clear()).unwrap();
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(400))
            .is_err(),
        "a fence read must wait while a writer holds the lock"
    );
    drop(guard);
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(10)),
        Ok(true)
    );
}

#[tokio::test]
async fn another_handles_compaction_is_picked_up_by_the_fence() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let a = open(&path).await;
    let b = open(&path).await;
    a.store_policy(&kill("k-pre", "gh-*")).await.unwrap();
    a.compact().await.unwrap();
    assert!(!b
        .kill_fence_check(&q("gh-main", 0))
        .await
        .unwrap()
        .is_clear());
    a.store_policy(&kill("k-post", "slack-*")).await.unwrap();
    assert!(matches!(
        b.kill_fence_check(&q("slack-bot", 0)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
}

// ------------------------------------------------------- crash consistency

/// The state a crash test checks: every acknowledged record, plus the kill fence.
async fn assert_acknowledged(s: &FileStorage, cred_alias: &str, tokens: &[String], epoch: u64) {
    assert!(
        s.get_by_alias(cred_alias).await.unwrap().is_some(),
        "committed credential lost"
    );
    for t in tokens {
        assert!(
            s.get_use_token(t).await.unwrap().is_some(),
            "committed token {t} lost"
        );
    }
    assert!(
        s.kill_fence_epoch().await >= epoch,
        "committed kill epoch lost"
    );
}

async fn build_base(path: &Path) -> (String, Vec<String>, u64) {
    let s = open(path).await;
    s.set_compact_min_bytes(u64::MAX);
    s.store(&cred("committed")).await.unwrap();
    let mut ids = Vec::new();
    for i in 0..5 {
        let t = token(i);
        ids.push(t.id.clone());
        s.store_use_token(&t).await.unwrap();
    }
    s.store_policy(&kill("base-kill", "base-*")).await.unwrap();
    ("committed".into(), ids, s.kill_fence_epoch().await)
}

/// The in-flight write is a kill policy: it changes three things at once (the policy, the epoch,
/// the mark), which must be all present or all absent after a crash, never a mix.
async fn assert_kill_all_or_nothing(s: &FileStorage, base_epoch: u64) {
    let stored = s.get_policy("w-kill").await.unwrap().is_some();
    let epoch = s.kill_fence_epoch().await;
    let marked = s
        .kill_fence_check(&q("w-target", base_epoch))
        .await
        .unwrap();
    if stored {
        assert_eq!(
            epoch,
            base_epoch + 1,
            "policy present but epoch not bumped: torn write"
        );
        assert!(matches!(marked, KillFenceVerdict::Halted { .. }));
    } else {
        assert_eq!(
            epoch, base_epoch,
            "epoch bumped without the policy: torn write"
        );
        assert!(
            marked.is_clear(),
            "mark without policy: torn write ({marked:?})"
        );
    }
}

#[tokio::test]
async fn a_crash_at_each_append_step_loses_no_committed_write_and_tears_no_record() {
    // Steps: before the append; half a line written; whole line written, not fsynced; fsynced
    // with the acknowledgement lost. The 4th is a durable write the caller never heard about.
    for step in [
        "wal.before_append",
        "wal.torn",
        "wal.after_write",
        "wal.after_fsync",
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let (alias, tokens, epoch) = build_base(&path).await;
        {
            let s = open(&path).await;
            s.set_compact_min_bytes(u64::MAX);
            *s.fault.lock() = Some(step.to_string());
            let r = s.store_policy(&kill("w-kill", "w-target")).await;
            assert!(
                r.is_err(),
                "{step}: the injected crash surfaces as an error"
            );
            // The process dies here: drop the handle without any cleanup.
        }
        let s = open(&path).await;
        assert_acknowledged(&s, &alias, &tokens, epoch).await;
        assert_kill_all_or_nothing(&s, epoch).await;
        // The vault is writable again and the new write survives yet another reopen.
        s.store(&cred("after-crash")).await.unwrap();
        drop(s);
        let s = open(&path).await;
        assert!(
            s.get_by_alias("after-crash").await.unwrap().is_some(),
            "{step}"
        );
        assert_acknowledged(&s, &alias, &tokens, epoch).await;
        assert_kill_all_or_nothing(&s, epoch).await;
        // A torn tail is repaired by the next writer: the log is whole lines only.
        let bytes = std::fs::read(path.with_extension("wal")).unwrap();
        assert!(
            bytes.is_empty() || bytes.ends_with(b"\n"),
            "{step}: log ends mid-line"
        );
    }
}

#[tokio::test]
async fn a_torn_tail_is_only_present_after_the_torn_step_and_is_never_applied() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let (_alias, _tokens, epoch) = build_base(&path).await;
    // A second handle opened BEFORE the crash stands in for a live reader process.
    let reader = open(&path).await;
    {
        let s = open(&path).await;
        *s.fault.lock() = Some("wal.torn".into());
        assert!(s.store_policy(&kill("w-kill", "w-target")).await.is_err());
    }
    let bytes = std::fs::read(path.with_extension("wal")).unwrap();
    assert!(
        !bytes.ends_with(b"\n"),
        "the injected tear leaves an unterminated tail"
    );
    // A READER (fence check) ignores the tail and does not modify the file.
    assert!(reader
        .kill_fence_check(&q("w-target", epoch))
        .await
        .unwrap()
        .is_clear());
    assert_eq!(
        std::fs::read(path.with_extension("wal")).unwrap(),
        bytes,
        "a read never repairs"
    );
    // The next WRITE truncates the tail first.
    reader.store(&cred("next")).await.unwrap();
    let after = std::fs::read(path.with_extension("wal")).unwrap();
    assert!(after.ends_with(b"\n"));
    drop(reader);
    let s = open(&path).await;
    assert!(s.get_by_alias("next").await.unwrap().is_some());
    assert!(
        s.get_policy("w-kill").await.unwrap().is_none(),
        "the torn write never appears"
    );
}

#[tokio::test]
async fn a_crash_at_each_compaction_step_loses_nothing_and_leaves_a_usable_vault() {
    for step in [
        "compact.after_snapshot_tmp",
        "compact.after_snapshot_rename",
        "compact.after_wal_tmp",
        "compact.after_wal_rename",
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let (alias, tokens, epoch) = build_base(&path).await;
        {
            let s = open(&path).await;
            *s.fault.lock() = Some(step.to_string());
            assert!(s.compact().await.is_err(), "{step}");
        }
        let s = open(&path).await;
        assert_acknowledged(&s, &alias, &tokens, epoch).await;
        s.store(&cred("post-compact-crash")).await.unwrap();
        s.compact().await.unwrap();
        drop(s);
        let s = open(&path).await;
        assert_acknowledged(&s, &alias, &tokens, epoch).await;
        assert!(
            s.get_by_alias("post-compact-crash")
                .await
                .unwrap()
                .is_some(),
            "{step}"
        );
        assert_eq!(
            wal_lines(&path),
            0,
            "{step}: a finished compaction leaves an empty log"
        );
        assert!(
            !s.kill_fence_check(&q("base-x", 0))
                .await
                .unwrap()
                .is_clear(),
            "{step}: the stored kill still halts after compaction"
        );
    }
}

#[tokio::test]
async fn a_crash_after_the_snapshot_rename_leaves_a_log_the_snapshot_already_contains() {
    // The one window where the log still holds records the new snapshot has folded in: replay must
    // skip them (not double-apply) and the next append must continue the sequence.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let (alias, tokens, epoch) = build_base(&path).await;
    let lines_before = wal_lines(&path);
    assert!(lines_before > 0);
    {
        let s = open(&path).await;
        *s.fault.lock() = Some("compact.after_snapshot_rename".into());
        assert!(s.compact().await.is_err());
    }
    assert_eq!(wal_lines(&path), lines_before, "the old log is still there");
    let s = open(&path).await;
    assert_acknowledged(&s, &alias, &tokens, epoch).await;
    s.store(&cred("continues")).await.unwrap();
    drop(s);
    let s = open(&path).await;
    assert!(s.get_by_alias("continues").await.unwrap().is_some());
    assert_acknowledged(&s, &alias, &tokens, epoch).await;
}

#[tokio::test]
async fn automatic_compaction_bounds_the_log_and_loses_nothing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.verify_replay
        .store(false, std::sync::atomic::Ordering::Relaxed);
    s.set_compact_min_bytes(4 * 1024);
    let mut ids = Vec::new();
    let mut max_wal = 0u64;
    for i in 0..120 {
        let t = token(i);
        ids.push(t.id.clone());
        s.store_use_token(&t).await.unwrap();
        max_wal = max_wal.max(
            std::fs::metadata(path.with_extension("wal"))
                .map(|m| m.len())
                .unwrap_or(0),
        );
    }
    let snap = std::fs::metadata(&path).unwrap().len();
    assert!(
        max_wal <= 4 * 1024.max(snap) + 2_000,
        "the log must stay within max(threshold, snapshot) plus one record: {max_wal} vs {snap}"
    );
    drop(s);
    let s = open(&path).await;
    for id in &ids {
        assert!(s.get_use_token(id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn a_corrupt_or_reordered_log_record_fails_the_open_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    {
        let s = open(&path).await;
        s.store(&cred("a")).await.unwrap();
        s.store(&cred("b")).await.unwrap();
        s.store(&cred("c")).await.unwrap();
    }
    let wal = path.with_extension("wal");
    let good = std::fs::read(&wal).unwrap();
    let lines: Vec<&[u8]> = good
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 3);
    // Missing middle record (gap).
    let mut gap = Vec::new();
    gap.extend_from_slice(lines[0]);
    gap.push(b'\n');
    gap.extend_from_slice(lines[2]);
    gap.push(b'\n');
    std::fs::write(&wal, &gap).unwrap();
    assert!(
        FileStorage::new(&path, &SecretString::from(PW))
            .await
            .is_err(),
        "gap"
    );
    // Swapped records (reorder).
    let mut swapped = Vec::new();
    for i in [1usize, 0, 2] {
        swapped.extend_from_slice(lines[i]);
        swapped.push(b'\n');
    }
    std::fs::write(&wal, &swapped).unwrap();
    assert!(
        FileStorage::new(&path, &SecretString::from(PW))
            .await
            .is_err(),
        "reorder"
    );
    // A flipped byte inside a terminated record (tamper / bit rot) fails authentication.
    let mut flipped = good.clone();
    let mid = lines[1].as_ptr() as usize - good.as_ptr() as usize + lines[1].len() / 2;
    flipped[mid] = if flipped[mid] == b'A' { b'B' } else { b'A' };
    std::fs::write(&wal, &flipped).unwrap();
    assert!(
        FileStorage::new(&path, &SecretString::from(PW))
            .await
            .is_err(),
        "flip"
    );
    // Restored: opens.
    std::fs::write(&wal, &good).unwrap();
    let s = open(&path).await;
    assert!(s.get_by_alias("c").await.unwrap().is_some());
}

#[tokio::test]
async fn rekey_folds_the_log_and_the_old_key_log_is_never_decrypted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    {
        let s = open(&path).await;
        s.store(&cred("pre")).await.unwrap();
        s.store_policy(&kill("k", "gh-*")).await.unwrap();
        assert!(wal_lines(&path) > 0);
        s.rekey(&SecretString::from("new-pw")).await.unwrap();
    }
    assert!(
        FileStorage::new(&path, &SecretString::from(PW))
            .await
            .is_err(),
        "old password"
    );
    let s = FileStorage::new(&path, &SecretString::from("new-pw"))
        .await
        .unwrap();
    assert!(s.get_by_alias("pre").await.unwrap().is_some());
    assert_eq!(s.kill_fence_epoch().await, 1);
    s.store(&cred("post")).await.unwrap();
    drop(s);
    let s = FileStorage::new(&path, &SecretString::from("new-pw"))
        .await
        .unwrap();
    assert!(s.get_by_alias("post").await.unwrap().is_some());
    assert!(s.get_by_alias("pre").await.unwrap().is_some());
}

#[tokio::test]
async fn a_crash_between_the_rekey_rename_and_the_log_reset_leaves_a_vault_that_opens() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    {
        let s = open(&path).await;
        s.store(&cred("pre")).await.unwrap();
        *s.fault.lock() = Some("compact.after_wal_tmp".into());
        assert!(s.rekey(&SecretString::from("new-pw")).await.is_err());
    }
    // Old-key records remain in the log but are all at or below the snapshot's applied_seq.
    assert!(wal_lines(&path) > 0);
    let s = FileStorage::new(&path, &SecretString::from("new-pw"))
        .await
        .unwrap();
    assert!(s.get_by_alias("pre").await.unwrap().is_some());
    s.store(&cred("post")).await.unwrap();
    drop(s);
    let s = FileStorage::new(&path, &SecretString::from("new-pw"))
        .await
        .unwrap();
    assert!(s.get_by_alias("post").await.unwrap().is_some());
}

// ------------------------------------------------------------- kill-mark GC

fn now_plus_hours(h: i64) -> DateTime<Utc> {
    Utc::now() + chrono::Duration::hours(h)
}

#[tokio::test]
async fn gc_drops_a_lifted_old_mark_and_never_lowers_the_epoch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.store_policy(&kill("k1", "gh-*")).await.unwrap();
    s.delete_policy("k1").await.unwrap();
    assert_eq!(s.kill_fence_epoch().await, 1);
    // Young mark: kept.
    assert_eq!(s.gc_vault_at(now_plus_hours(1)).await.unwrap().2, 0);
    // Past the grace, lifted, no live admissions: dropped.
    assert_eq!(s.gc_vault_at(now_plus_hours(25)).await.unwrap().2, 1);
    assert_eq!(s.kill_fence_epoch().await, 1, "the epoch only rises");
    // The drop is durable, and so is the epoch.
    drop(s);
    let s = open(&path).await;
    assert_eq!(s.kill_fence_epoch().await, 1);
    assert_eq!(
        s.gc_vault_at(now_plus_hours(48)).await.unwrap().2,
        0,
        "nothing left to drop"
    );
    // Work admitted at the current epoch is clear; a new kill still works and refuses work
    // admitted before it.
    assert!(s
        .kill_fence_check(&q("gh-main", 1))
        .await
        .unwrap()
        .is_clear());
    s.store_policy(&kill("k2", "gh-*")).await.unwrap();
    assert!(matches!(
        s.kill_fence_check(&q("gh-main", 1)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
}

#[tokio::test]
async fn gc_never_drops_a_live_kill_however_old() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.store_policy(&kill("live", "gh-*")).await.unwrap();
    assert_eq!(s.gc_vault_at(now_plus_hours(24 * 365)).await.unwrap().2, 0);
    assert!(matches!(
        s.kill_fence_check(&q("gh-main", 1)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
    // Lift it (the mark is now dead), then kill again under the SAME id: the id is a stored kill
    // again, so its fresh mark is not collectable and the agent is halted.
    s.delete_policy("live").await.unwrap();
    s.store_policy(&kill("live", "gh-*")).await.unwrap();
    assert_eq!(s.gc_vault_at(now_plus_hours(24 * 365)).await.unwrap().2, 0);
    assert!(matches!(
        s.kill_fence_check(&q("gh-main", 0)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
}

#[tokio::test]
async fn gc_keeps_a_mark_that_a_live_approval_still_depends_on() {
    use crate::approval::ApprovalStatus;
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    // An approval opened at epoch 0, still pending.
    let mut appr = super::tests::mk_approval("live");
    appr.kill_epoch_at_open = Some(0);
    s.store_approval(&appr).await.unwrap();
    s.store_policy(&kill("k1", "gh-*")).await.unwrap();
    s.delete_policy("k1").await.unwrap();
    // Old and lifted, but the live approval was admitted before it: the mark stays.
    assert_eq!(s.gc_vault_at(now_plus_hours(48)).await.unwrap().2, 0);
    assert!(
        matches!(
            s.kill_fence_check(&q("gh-main", 0)).await.unwrap(),
            KillFenceVerdict::KilledSinceAdmission { .. }
        ),
        "the approval opened before the kill must still be refused"
    );
    // Once the approval is finished (denied), the mark is collectable.
    let mut done = s.get_approval("appr_live").await.unwrap().unwrap();
    done.deny(crate::approval::Decision::new("test", "bob@corp"))
        .unwrap();
    assert_eq!(done.status(), ApprovalStatus::Denied);
    s.update_approval(&done).await.unwrap();
    assert_eq!(s.gc_vault_at(now_plus_hours(48)).await.unwrap().2, 1);
}

#[tokio::test]
async fn gc_keeps_a_mark_for_an_approval_opened_before_the_epoch_field_existed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    let appr = super::tests::mk_approval("legacy"); // kill_epoch_at_open = None, checked as 0
    s.store_approval(&appr).await.unwrap();
    s.store_policy(&kill("k1", "gh-*")).await.unwrap();
    s.delete_policy("k1").await.unwrap();
    assert_eq!(s.gc_vault_at(now_plus_hours(48)).await.unwrap().2, 0);
}

#[tokio::test]
async fn gc_leaves_an_unstamped_mark_alone() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.locked_mutate(|c| {
        c.kill_fence.epoch = 3;
        c.kill_fence.marks.insert(
            "old".into(),
            crate::policy::KillMark {
                credential_pattern: "gh-*".into(),
                principal_pattern: None,
                epoch: 3,
                stored_at: None,
            },
        );
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(s.gc_vault_at(now_plus_hours(24 * 365)).await.unwrap().2, 0);
}

// ----------------------------------------------------------------- migration

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-v9")
}

#[tokio::test]
async fn a_real_v9_vault_migrates_with_a_backup_and_keeps_everything() {
    let exp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_dir().join("expected.json")).unwrap())
            .unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let original = std::fs::read(fixture_dir().join("vault.enc")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(header["version"], 9, "the fixture is a genuine v9 file");

    let pw = SecretString::from(exp["password"].as_str().unwrap());
    let s = FileStorage::new(&path, &pw).await.unwrap();

    // Everything the v9 build wrote is there.
    for a in exp["aliases"].as_array().unwrap() {
        assert!(
            s.get_by_alias(a.as_str().unwrap()).await.unwrap().is_some(),
            "{a}"
        );
    }
    for t in exp["token_ids"].as_array().unwrap() {
        assert!(
            s.get_use_token(t.as_str().unwrap())
                .await
                .unwrap()
                .is_some(),
            "{t}"
        );
    }
    let pols = s.list_stored_policies().await.unwrap();
    assert_eq!(pols.len(), 2, "the allow policy and the live kill");
    assert!(pols.iter().any(|p| p.id == "kill-live" && p.kill));
    assert_eq!(
        s.kill_fence_epoch().await,
        exp["kill_epoch"].as_u64().unwrap()
    );
    // The lifted kill's mark survived the migration and still refuses pre-kill work.
    assert!(matches!(
        s.kill_fence_check(&q("slack-bot", 0)).await.unwrap(),
        KillFenceVerdict::KilledSinceAdmission { ref policy_id, .. } if policy_id == "kill-lifted"
    ));

    // One-way: the file is now v10 and the v9 original is kept byte-for-byte.
    let migrated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(migrated["version"], 10);
    assert_eq!(
        std::fs::read(path.with_extension("v9.bak")).unwrap(),
        original
    );
    // Old marks were stamped so GC can age them, from the migration time.
    assert_eq!(s.gc_vault_at(now_plus_hours(1)).await.unwrap().2, 0);
    assert_eq!(
        s.gc_vault_at(now_plus_hours(25)).await.unwrap().2,
        1,
        "the lifted mark ages out"
    );
    let marks: Vec<String> = s
        .locked_read(|c| c.kill_fence.marks.keys().cloned().collect())
        .await
        .unwrap();
    assert_eq!(
        marks,
        vec!["kill-live".to_string()],
        "only the stored kill keeps its mark"
    );
    assert!(
        s.get_policy("kill-live").await.unwrap().is_some(),
        "the stored kill is untouched by GC"
    );
    drop(s);

    // A second open does not migrate again and never overwrites the backup.
    std::fs::write(path.with_extension("v9.bak"), b"sentinel").unwrap();
    let s = FileStorage::new(&path, &pw).await.unwrap();
    assert_eq!(
        std::fs::read(path.with_extension("v9.bak")).unwrap(),
        b"sentinel"
    );
    s.store(&cred("after-migration")).await.unwrap();
    drop(s);
    let s = FileStorage::new(&path, &pw).await.unwrap();
    assert!(s.get_by_alias("after-migration").await.unwrap().is_some());
    assert!(s.get_by_alias("gh-main").await.unwrap().is_some());
}

#[tokio::test]
async fn a_crash_during_migration_leaves_the_v9_vault_intact_and_re_migrates() {
    let exp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_dir().join("expected.json")).unwrap())
            .unwrap();
    let pw = SecretString::from(exp["password"].as_str().unwrap());
    let original = std::fs::read(fixture_dir().join("vault.enc")).unwrap();
    for step in [
        "compact.after_snapshot_tmp",
        "compact.after_snapshot_rename",
        "compact.after_wal_tmp",
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        std::fs::write(&path, &original).unwrap();
        // Crash the migration at `step` by arming a fault on a hand-built handle.
        {
            let content = std::fs::read_to_string(&path).unwrap();
            let sf: StorageFile = serde_json::from_str(&content).unwrap();
            let salt = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sf.salt)
                .unwrap();
            let key = Arc::new(derive_key(&pw, &salt, sf.kdf).unwrap());
            let st = FileStorage {
                path: path.clone(),
                master_key: Arc::clone(&key),
                outbox: OutboxStore::new(outbox_path(&path), key),
                averin: None,
                cache: RwLock::new(StorageCache::default()),
                salt,
                kdf: sf.kdf,
                log: parking_lot::Mutex::new(LogState::default()),
                fault: parking_lot::Mutex::new(Some(step.to_string())),
                verify_replay: std::sync::atomic::AtomicBool::new(false),
                compact_min: std::sync::atomic::AtomicU64::new(DEFAULT_COMPACT_MIN_BYTES),
                io: IoCounters::default(),
            };
            assert!(st.bootstrap_locked().is_err(), "{step}");
        }
        // Whatever the crash left, the next open recovers every record.
        let s = FileStorage::new(&path, &pw).await.unwrap();
        for a in exp["aliases"].as_array().unwrap() {
            assert!(
                s.get_by_alias(a.as_str().unwrap()).await.unwrap().is_some(),
                "{step}: {a}"
            );
        }
        assert_eq!(
            s.kill_fence_epoch().await,
            exp["kill_epoch"].as_u64().unwrap(),
            "{step}"
        );
        assert_eq!(
            std::fs::read(path.with_extension("v9.bak")).unwrap(),
            original,
            "{step}"
        );
    }
}

#[tokio::test]
async fn a_v9_build_would_be_refused_a_v10_vault() {
    // The old build's gate is `check_version`: it must refuse anything above its own version so it
    // cannot read the snapshot, ignore the log and write over committed records.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    open(&path).await;
    let header: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(header["version"], 10);
    // The v9 build's gate is `found <= 9`; this file carries a larger number.
    assert!(
        header["version"].as_u64().unwrap() > 9,
        "a v9 build refuses a version above 9"
    );
    assert!(
        check_version(11).is_err(),
        "and this build refuses a newer one in turn"
    );
}

#[tokio::test]
async fn an_older_build_rewriting_the_snapshot_under_a_running_process_is_refused() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.store(&cred("a")).await.unwrap();
    // Simulate a v9 process atomically replacing the vault file (whole-file rewrite, version 9).
    let mut header: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    header["version"] = serde_json::json!(9);
    let tmp = path.with_extension("old.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&header).unwrap()).unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    let r = s.kill_fence_check(&q("gh-main", 0)).await;
    assert!(matches!(r, Err(StorageError::Unavailable(_))), "{r:?}");
}

// ------------------------------------------------ review fix round 1: rollback, GC, races

#[tokio::test]
async fn gc_keeps_a_mark_for_an_approved_not_yet_executed_approval() {
    // An approval opened before the kill, approved after the lift, resumed much later: its mark
    // must survive GC and the claim must still be refused afterwards.
    use crate::approval::ApprovalStatus;
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    let mut appr = super::tests::mk_approval("appr-open");
    appr.kill_epoch_at_open = Some(0);
    s.store_approval(&appr).await.unwrap();
    s.store_policy(&kill("k1", "gh-*")).await.unwrap();
    s.delete_policy("k1").await.unwrap();
    let mut a = s.get_approval("appr_appr-open").await.unwrap().unwrap();
    a.approve(crate::approval::Decision::new("test", "bob@corp"))
        .unwrap();
    assert_eq!(a.status(), ApprovalStatus::Approved);
    assert!(!a.executed && !a.executing);
    s.update_approval(&a).await.unwrap();
    assert_eq!(
        s.gc_vault_at(now_plus_hours(48)).await.unwrap().2,
        0,
        "an approved, not executed approval still depends on the mark"
    );
    drop(s);
    let s = open(&path).await;
    assert!(
        matches!(
            s.kill_fence_check(&q("gh-main", 0)).await.unwrap(),
            KillFenceVerdict::KilledSinceAdmission { .. }
        ),
        "the claim is still refused after GC ran"
    );
}

#[tokio::test]
async fn gc_keeps_a_mark_for_an_executing_approval() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    let mut appr = super::tests::mk_approval("appr-exec");
    appr.kill_epoch_at_open = Some(0);
    appr.approve(crate::approval::Decision::new("test", "bob@corp"))
        .unwrap();
    appr.executing = true;
    appr.executing_since = Some(Utc::now());
    s.store_approval(&appr).await.unwrap();
    s.store_policy(&kill("k1", "gh-*")).await.unwrap();
    s.delete_policy("k1").await.unwrap();
    assert_eq!(s.gc_vault_at(now_plus_hours(48)).await.unwrap().2, 0);
    assert!(matches!(
        s.kill_fence_check(&q("gh-main", 0)).await.unwrap(),
        KillFenceVerdict::KilledSinceAdmission { .. }
    ));
}

#[tokio::test]
async fn a_leftover_log_beside_a_pre_v10_snapshot_is_refused_not_replayed() {
    // Roll back as documented, but leave the log (the operator deleted the wrong file or forgot):
    // the next open must fail closed instead of replaying abandoned writes onto the v9 state.
    let exp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_dir().join("expected.json")).unwrap())
            .unwrap();
    let pw = SecretString::from(exp["password"].as_str().unwrap());
    let dir = tempdir().unwrap();
    let path = dir.path().join("credentials.enc");
    let original = std::fs::read(fixture_dir().join("vault.enc")).unwrap();
    std::fs::write(&path, &original).unwrap();
    {
        let s = FileStorage::new(&path, &pw).await.unwrap();
        s.set_compact_min_bytes(u64::MAX);
        s.delete_policy("kill-live").await.unwrap();
        s.store(&cred("v10-period")).await.unwrap();
    }
    let wal = path.with_extension("wal");
    assert!(wal.exists() && std::fs::metadata(&wal).unwrap().len() > 0);
    // Roll back the snapshot only (the log is left behind).
    std::fs::copy(path.with_extension("v9.bak"), &path).unwrap();
    let err = FileStorage::new(&path, &pw).await.err().expect("refused");
    let msg = err.to_string();
    assert!(
        msg.contains("credentials.wal"),
        "names the real file: {msg}"
    );
    // Nothing was replayed or changed on disk by the refusal.
    assert_eq!(std::fs::read(&path).unwrap(), original);
    // Deleting the log (the documented rollback, with the real name) then opens the v9 state.
    std::fs::remove_file(&wal).unwrap();
    let s = FileStorage::new(&path, &pw).await.unwrap();
    assert!(s.get_policy("kill-live").await.unwrap().is_some());
    assert!(s.get_by_alias("v10-period").await.unwrap().is_none());
}

#[tokio::test]
async fn migration_never_overwrites_a_differing_backup() {
    let exp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_dir().join("expected.json")).unwrap())
            .unwrap();
    let pw = SecretString::from(exp["password"].as_str().unwrap());
    let dir = tempdir().unwrap();
    let path = dir.path().join("credentials.enc");
    let original = std::fs::read(fixture_dir().join("vault.enc")).unwrap();
    std::fs::write(&path, &original).unwrap();
    std::fs::write(path.with_extension("v9.bak"), b"an older backup").unwrap();
    drop(FileStorage::new(&path, &pw).await.unwrap());
    assert_eq!(
        std::fs::read(path.with_extension("v9.bak")).unwrap(),
        b"an older backup",
        "the existing backup is kept"
    );
    let extra: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            n.starts_with("credentials.v9.") && n.ends_with(".bak") && n != "credentials.v9.bak"
        })
        .collect();
    assert_eq!(extra.len(), 1, "the current v9 state got its own backup");
    let copy = std::fs::read(dir.path().join(&extra[0])).unwrap();
    assert_eq!(copy, original);
}

#[tokio::test]
async fn creating_a_vault_that_another_process_just_created_opens_it() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let first = open(&path).await;
    first.store(&cred("from-first")).await.unwrap();
    // The loser of the creation race reaches `create` although the file now exists.
    let second = FileStorage::create(path.clone(), &SecretString::from(PW), false, false)
        .await
        .unwrap();
    assert!(second.get_by_alias("from-first").await.unwrap().is_some());
    first.store(&cred("later")).await.unwrap();
    drop((first, second));
    let s = open(&path).await;
    assert!(s.get_by_alias("later").await.unwrap().is_some());
}

#[tokio::test]
async fn a_failed_append_does_not_leave_an_acknowledged_looking_record() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.set_compact_min_bytes(u64::MAX);
    s.store(&cred("kept")).await.unwrap();
    let before = std::fs::read(path.with_extension("wal")).unwrap();
    *s.fault.lock() = Some("wal.after_write".into());
    assert!(s.store(&cred("failed")).await.is_err());
    assert_eq!(
        std::fs::read(path.with_extension("wal")).unwrap(),
        before,
        "the unacknowledged line is taken back out"
    );
    let reader = open(&path).await;
    assert!(reader.get_by_alias("failed").await.unwrap().is_none());
    assert!(reader.get_by_alias("kept").await.unwrap().is_some());
}

// ------------------------------------------------------------- panic atomicity

/// A panic inside a mutation closure must leave neither the live view nor the next commit with
/// the half-applied change: a panic in the middle of a kill lift must not become a lift.
#[tokio::test]
async fn a_panic_inside_a_mutation_rolls_back_and_never_commits() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = std::sync::Arc::new(open(&path).await);
    s.store_policy(&kill("halt:x", "gh-*")).await.unwrap();
    let epoch0 = 0;

    let s2 = std::sync::Arc::clone(&s);
    let joined = tokio::spawn(async move {
        let _: Result<(), StorageError> = s2
            .locked_mutate(|c| {
                c.policies.remove("halt:x");
                if c.policies.is_empty() {
                    panic!("injected panic mid-lift");
                }
                Ok(())
            })
            .await;
    })
    .await;
    assert!(joined.unwrap_err().is_panic());

    // The live view still has the kill.
    assert!(s.get_policy("halt:x").await.unwrap().is_some());
    assert!(!s
        .kill_fence_check(&q("gh-main", epoch0))
        .await
        .unwrap()
        .is_clear());

    // An unrelated successful write must not commit the abandoned lift.
    s.store_use_token(&token(1)).await.unwrap();
    assert!(s.get_policy("halt:x").await.unwrap().is_some());
    drop(s);
    let r = open(&path).await;
    assert!(
        r.get_policy("halt:x").await.unwrap().is_some(),
        "the kill was lost through a panicked mutation"
    );
    assert!(!r
        .kill_fence_check(&q("gh-main", epoch0))
        .await
        .unwrap()
        .is_clear());
}

// ------------------------------------------------------------- wrong password with averin

/// The password is verified (snapshot decrypt) before the averin queue is replayed, so a wrong
/// password with a non-empty queue is a decrypt error, never a "corrupt queue" claim.
#[tokio::test]
async fn a_wrong_password_with_averin_enabled_is_a_decrypt_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    {
        let s = FileStorage::new_with_averin(&path, &SecretString::from(PW), true)
            .await
            .unwrap();
        s.averin_queue()
            .unwrap()
            .append("tok-1", "averin.use", serde_json::json!({"n": 1}))
            .unwrap();
    }
    let r = FileStorage::new_with_averin(&path, &SecretString::from("wrong"), true).await;
    assert!(
        matches!(r, Err(StorageError::Encryption(_))),
        "expected a decrypt error"
    );
}

// ------------------------------------------------ follow-up: the log must not vanish or shrink

/// A vault with a stored kill, opened twice: `b` has synced the kill, the snapshot is unchanged
/// (nothing compacted), and the log holds the record that carries the kill.
async fn halted_vault(path: &Path) -> (FileStorage, u64) {
    let a = open(path).await;
    a.set_compact_min_bytes(u64::MAX);
    let epoch0 = a.kill_fence_epoch().await;
    let b = open(path).await;
    a.store_policy(&kill("k1", "gh-*")).await.unwrap();
    assert!(matches!(
        b.kill_fence_check(&q("gh-main", epoch0)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
    drop(a);
    (b, epoch0)
}

#[tokio::test]
async fn removing_the_log_under_a_running_process_never_turns_a_halt_clear() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let (b, epoch0) = halted_vault(&path).await;
    std::fs::remove_file(path.with_extension("wal")).unwrap();
    let r = b.kill_fence_check(&q("gh-main", epoch0)).await;
    assert!(matches!(r, Err(StorageError::Unavailable(_))), "{r:?}");
    // Refusal is sticky: a second look does not quietly accept the shorter state.
    let r = b.kill_fence_check(&q("gh-main", epoch0)).await;
    assert!(matches!(r, Err(StorageError::Unavailable(_))), "{r:?}");
    // A write is refused too (it would append at the wrong sequence).
    assert!(b.store(&cred("late")).await.is_err());
}

#[tokio::test]
async fn shrinking_the_log_under_a_running_process_never_turns_a_halt_clear() {
    for keep in [0u64, 1] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let (b, epoch0) = halted_vault(&path).await;
        let wal = path.with_extension("wal");
        let len = std::fs::metadata(&wal).unwrap().len();
        assert!(len > 1);
        let f = std::fs::OpenOptions::new().write(true).open(&wal).unwrap();
        f.set_len(keep).unwrap();
        let r = b.kill_fence_check(&q("gh-main", epoch0)).await;
        assert!(
            matches!(r, Err(StorageError::Unavailable(_))),
            "keep={keep}: {r:?}"
        );
    }
}

#[tokio::test]
async fn a_v10_snapshot_whose_log_is_missing_is_refused_at_open() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    {
        let s = open(&path).await;
        s.store_policy(&kill("k1", "gh-*")).await.unwrap();
        s.compact().await.unwrap();
    }
    let wal = path.with_extension("wal");
    assert!(
        wal.exists(),
        "a fresh and a compacted vault always has a log file"
    );
    std::fs::remove_file(&wal).unwrap();
    let err = FileStorage::new(&path, &SecretString::from(PW))
        .await
        .err()
        .expect("refused");
    assert!(err.to_string().contains("vault.wal"), "{err}");
    assert!(!wal.exists(), "the refusal creates nothing");
}

#[tokio::test]
async fn the_log_exists_before_the_snapshot_that_needs_it_is_renamed_in() {
    // Create and migration both go through compact_locked. Crash right after the snapshot rename:
    // the v10 snapshot is on disk, and the log must already be there (empty), so the next open
    // does not mistake a crash for a deleted log.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    {
        let salt = crate::crypto::generate_salt();
        let kdf = crate::crypto::KdfParams::default();
        let key = Arc::new(derive_key(&SecretString::from(PW), &salt, kdf).unwrap());
        let st = FileStorage {
            path: path.clone(),
            master_key: Arc::clone(&key),
            outbox: OutboxStore::new(outbox_path(&path), key),
            averin: None,
            cache: RwLock::new(StorageCache::default()),
            salt,
            kdf,
            log: parking_lot::Mutex::new(LogState::default()),
            fault: parking_lot::Mutex::new(Some("compact.after_snapshot_rename".into())),
            verify_replay: std::sync::atomic::AtomicBool::new(false),
            compact_min: std::sync::atomic::AtomicU64::new(DEFAULT_COMPACT_MIN_BYTES),
            io: IoCounters::default(),
        };
        let mut log = st.log.lock();
        let cache = st.cache.read();
        assert!(st.compact_locked(&mut log, &cache).is_err());
    }
    assert!(path.exists());
    let wal = path.with_extension("wal");
    assert!(
        wal.exists(),
        "the log must exist before the snapshot is renamed in"
    );
    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
    open(&path).await;
}

#[tokio::test]
async fn an_older_build_rewriting_the_snapshot_after_compaction_is_refused() {
    // The log is empty and its length equals the process's offset (0): the only sign of the foreign
    // rewrite is the snapshot token and the version in it.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.store(&cred("a")).await.unwrap();
    s.compact().await.unwrap();
    assert_eq!(
        std::fs::metadata(path.with_extension("wal")).unwrap().len(),
        0
    );
    assert_eq!(s.kill_fence_epoch().await, 0);
    let mut header: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    header["version"] = serde_json::json!(9);
    let tmp = path.with_extension("old.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&header).unwrap()).unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    for _ in 0..2 {
        let r = s.kill_fence_check(&q("gh-main", 0)).await;
        assert!(matches!(r, Err(StorageError::Unavailable(_))), "{r:?}");
    }
    assert!(s.store(&cred("b")).await.is_err());
}

// ------------------------------------------------ follow-up: force a reload after the durable point

#[tokio::test]
async fn a_commit_error_after_the_record_is_durable_reloads_conservatively() {
    // Observable behaviour is the same with or without the reload (the failed append never
    // advances the offset, so the next look reads the durable record as a foreign append). The
    // flag check pins the conservative reload; it is not a semantic claim.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = open(&path).await;
    s.set_compact_min_bytes(u64::MAX);
    let epoch0 = s.kill_fence_epoch().await;
    *s.fault.lock() = Some("wal.after_fsync".into());
    assert!(s.store_policy(&kill("k1", "gh-*")).await.is_err());
    assert!(!s.log.lock().loaded);
    assert!(matches!(
        s.kill_fence_check(&q("gh-main", epoch0)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
    s.store(&cred("after")).await.unwrap();
    drop(s);
    let r = open(&path).await;
    assert!(r.get_policy("k1").await.unwrap().is_some());
    assert!(r.get_by_alias("after").await.unwrap().is_some());
}

#[tokio::test]
async fn a_panic_after_the_record_is_durable_does_not_turn_the_fence_clear() {
    // The log append succeeded (offsets advanced) and then the writer panicked: rollback restores
    // the pre-write kill state, and only the forced reload makes the durable kill visible.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = std::sync::Arc::new(open(&path).await);
    s.set_compact_min_bytes(u64::MAX);
    let epoch0 = s.kill_fence_epoch().await;
    *s.fault.lock() = Some("commit.panic_after_append".into());
    let s2 = std::sync::Arc::clone(&s);
    let joined = tokio::spawn(async move {
        let _ = s2.store_policy(&kill("k1", "gh-*")).await;
    })
    .await;
    assert!(joined.unwrap_err().is_panic());
    assert!(matches!(
        s.kill_fence_check(&q("gh-main", epoch0)).await.unwrap(),
        KillFenceVerdict::Halted { .. }
    ));
    assert!(s.get_policy("k1").await.unwrap().is_some());
    assert!(s.kill_fence_epoch().await > epoch0);
    drop(s);
    let r = open(&path).await;
    assert!(r.get_policy("k1").await.unwrap().is_some());
}

#[tokio::test]
async fn a_panic_in_a_mutation_closure_rolls_back_and_reloads() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = std::sync::Arc::new(open(&path).await);
    s.store_policy(&kill("halt:x", "gh-*")).await.unwrap();
    let s2 = std::sync::Arc::clone(&s);
    let joined = tokio::spawn(async move {
        let _: Result<(), StorageError> = s2
            .locked_mutate(|c| {
                c.policies.remove("halt:x");
                panic!("injected panic");
            })
            .await;
    })
    .await;
    assert!(joined.unwrap_err().is_panic());
    assert!(s.get_policy("halt:x").await.unwrap().is_some());
}
