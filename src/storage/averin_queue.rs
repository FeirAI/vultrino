//! The averin USE queue's durable primitive (plan 088 D0): an append-only, segmented, per-record-
//! sealed **delta journal** with an O(1) durable append, backing the SAME reused in-memory outbox
//! state machine (`super::outbox_model`) that `OutboxStore` uses for the govder outbox.
//!
//! WHY this exists (the append-cost pivot): `OutboxStore::write_to_disk` re-serializes + re-encrypts
//! the ENTIRE retained event map and fsync-rewrites the whole file on every append
//! (`outbox_store.rs::write_to_disk`) — O(retained events) per append, so a burst while averin is
//! unreachable is O(n²). That's fine for the govder outbox (control-plane frequency, `PopKeyEntry`-
//! style whole-file stores are still used for the averin PoP-key/quarantine stores, D2/D4 — control-
//! plane frequency, not hot-path). It is NOT fine for the `/execute` hot-path seal enqueue this module
//! backs. Here, append cost is **O(1)**: one small length-framed, individually AES-256-GCM-sealed
//! record, appended to the CURRENT segment file and fsynced — the append never reads, re-serializes,
//! or rewrites any prior record, so its cost does not grow with how many events are already retained.
//!
//! # On-disk shape
//!
//! A queue lives in its own directory. Two kinds of files:
//! - **delta segments** (`<20-digit index>.delta`): an append-only sequence of frames, each
//!   `MAGIC(4 bytes, "AVQ1") ‖ uint32_be(len) ‖ uint32_be(len_crc32) ‖ sealed_bytes` (a fixed
//!   [`FRAME_HEADER_LEN`]-byte self-describing header — see "Crash safety" below for why — followed
//!   by `sealed_bytes`, which is `serde_json::to_vec` of the crate's own [`crate::crypto::EncryptedData`]
//!   (nonce + AES-256-GCM ciphertext of one JSON-serialized [`Delta`])) — the SAME encrypted envelope
//!   shape `OutboxStore`/the vault use, just one small record per frame instead of one giant document.
//!   A segment rolls to a fresh file at [`SEGMENT_ROLL_BYTES`] (fsyncing the queue directory once, via
//!   [`fsync_parent_dir`]).
//! - **snapshot segments** (`<20-digit index>.snapshot`): written only by [`AverinQueue::compact`] (the
//!   ONE O(n) operation, off the append hot path) — a single encrypted document (mirroring
//!   `OutboxStore`'s own file format) holding the ENTIRE live map, superseding every delta segment
//!   below its index.
//!
//! Startup ([`AverinQueue::open`]) loads the highest-indexed snapshot (if any) as the replay base, then
//! replays every delta segment above it, in index order, rebuilding the map — cost is O(records in the
//! live segments), which `compact` bounds.
//!
//! # Crash safety
//!
//! A record is "committed" only after ITS `fsync` returns (see [`Writer`], below). The on-disk frame
//! header is `MAGIC ‖ len ‖ len_crc32` (crc32 covers ONLY the 4 `len` bytes — the payload's own AEAD
//! tag remains the payload integrity check; this header exists only to make the otherwise-unprotected
//! length prefix self-describing). On replay, exactly two shapes are a genuine **torn trailing
//! record** (discarded; everything durably written before it survives untouched): (1) fewer than
//! [`FRAME_HEADER_LEN`] bytes remain (a partial header), or (2) the header is fully intact (magic
//! matches, `len_crc32` matches) but fewer than `len` payload bytes remain — a process death mid-`write()`
//! truncates the file at whatever point it reached, it never fabricates a wrong magic or a
//! self-consistent-but-wrong length. Every OTHER failure is **interior corruption**, fails closed
//! (`AverinQueue::open` returns `Err`, refusing to serve a store that may have silently lost a record)
//! regardless of where in the file it occurs — this includes a GCM authentication failure on a frame
//! whose header is intact AND whose full claimed-length payload is present (even if it's the LAST frame
//! in the file): a fully-present frame means the single `write()` call that appended it (see
//! `Writer::write_and_maybe_roll`) completed, so a failed auth tag there can only be corruption after
//! the fact, never an in-progress write — silently discarding it as "torn" would fail OPEN on a
//! genuinely corrupted, already-fsynced record (Codex review HIGH-5 on plan 088). A bit-flipped length
//! prefix on an INTERIOR frame is caught by the `len_crc32` (or, if the flip also collides with a wrong
//! magic read, by the magic check) rather than being misread as a valid — if bogus — frame boundary
//! (the original vulnerability: an unprotected length prefix let interior corruption masquerade as a
//! torn tail, silently dropping that record and every later one). (Phase-0 spike item 3 is the origin
//! of the interior-corruption-fails-closed contract itself; this crc32 hardening closes the gap Codex
//! found in how the boundary between "torn" and "interior" was originally drawn.)
//!
//! # Durable GROUP-COMMIT, not lossy mpsc (D0 fallback ladder, tier 1)
//!
//! Measured on this dev machine (macOS APFS, the same hardware the design-spike numbers in plan 088's
//! header came from) a single synchronous per-record `fsync` sits right at/over the plan's p99 ≤ 5ms
//! SLO (~4.9-5.0ms measured here — see the Step-1 commit message for the exact run). Per plan 088 D0's
//! explicit instruction ("if per-record fsync p99 exceeds 5ms... implement the DURABLE GROUP-COMMIT
//! fallback... prefer durable group-commit... never ship a lossy tier"), this module's writer is a
//! SINGLE background thread ([`Writer`]) that drains however many records are queued at that instant
//! and issues ONE `fsync` for the whole batch (drain-queue-then-one-fsync — the exact shape the spike
//! measured at 38µs/record at K=128, 12µs/record at K=512). Each producer's call still BLOCKS until
//! ITS OWN record's batch fsync has returned before it returns `Ok` — this is NOT the lossy `mpsc`
//! tier (which returns before durability and can lose queued-but-unflushed records on a crash).
//!
//! MEASURED HONESTLY (`averin_enqueue_bench`): the append is O(1) — solo-append p99 is FLAT across
//! backlog (10 → 100k retained: ratio ≤ ~1.2× the 10-record baseline at every depth, and NOT
//! monotonically growing), which is the reproducible contract Step 1 proves. The ABSOLUTE latency is
//! entirely machine-load-dependent and does NOT reproduce to a fixed figure: on an IDLE dev Mac a solo
//! append is p99 ~5–6ms (right at the raw APFS `fsync` floor — same as the spike's ~5.9ms), while under
//! heavy concurrent machine load (e.g. a full `cargo test` running alongside) the same solo p99 climbs
//! to ~10–35ms because each solo append pays a full `fsync` PLUS a cross-thread wakeup of the writer
//! thread, and that wakeup is what stretches under scheduler pressure. So a solo caller does NOT
//! reliably degrade to "the same latency as a lone fsync" once the box is busy — the group-commit's
//! dedicated-writer shape (the plan's inc-1-B3-endorsed design) optimizes concurrent THROUGHPUT
//! (16 threads ≈ 400–560µs/record amortized), not solo latency. The plan's p99 ≤ 5ms is a LINUX-NVMe
//! SLO (sub-ms `fdatasync` + a less contended scheduler), a deployment-target property to validate
//! under the four-plane e2e — NOT a dev-Mac guarantee. Step 1 proves the O(1) contract here; this
//! durable tier is opt-in (default OFF) precisely because it trades enqueue latency for at-least-once
//! durability.
//!
//! # Locking model (scoped deliberately, see each method's doc)
//!
//! [`AverinQueue::append`] — the ONLY hot-path method (D0's SLO target) — releases the in-memory lock
//! BEFORE waiting on durability, so concurrent producers' commits land in the SAME group-commit batch.
//! [`AverinQueue::claim`] and [`AverinQueue::record_delivery`] (worker/off-path methods) hold the
//! in-memory lock for their FULL duration instead, trading their own cross-call concurrency for a
//! simpler, obviously-correct implementation — acceptable because neither is the enqueue hot path
//! D0's SLO targets, and a real delivery worker (plan 088 Step 3) is normally single-instance per
//! queue anyway (mirroring `OutboxStore::claim`'s existing single-worker-tick usage pattern).
//!
//! A `committing` set (`QueueMemory::committing`, guarded by the SAME `mem` lock) plus a dedicated
//! [`Condvar`] (`AverinQueue::committing_cv`) closes a related hole a prior fix opened (Codex
//! re-review #2/#3 — full incident in [`AverinQueue::append`]'s doc): [`AverinQueue::append`]
//! publishes into `mem.cache.outbox` IMMEDIATELY (so [`AverinQueue::compact`]/
//! [`AverinQueue::prune_delivered_prefix`] always observe it) but marks the sequence `committing`
//! until its own commit is confirmed durable. [`AverinQueue::claim`]/[`AverinQueue::deliverable`]/
//! [`AverinQueue::record_delivery`] skip anything still `committing` (no resurrection — the original
//! hole this reuses [`AverinQueue::claim`]'s already-held lock to close for free), while `compact`/
//! `prune_delivered_prefix` WAIT for `committing` to drain before snapshotting/pruning (no durable-
//! but-unpublished event can be lost or mispruned). `Condvar::wait` releases `mem` for the duration of
//! the wait, and nothing ever holds `mem` across a blocking `writer.commit`/`writer.roll` call, so
//! this cannot cycle with the group-commit writer thread — see `append`'s doc for the full argument.
//!
//! # Cross-process safety: single-writer-PROCESS + graceful degradation (Step 3a, Option A)
//!
//! This queue is single-writer-PROCESS by design: the append/claim/record_delivery/compact locking
//! model above (the in-memory `mem` lock + the dedicated group-commit writer thread) is correct and
//! deadlock-free precisely BECAUSE no cross-process file lock sits in those hot paths. (An earlier
//! attempt to make the append itself multi-process — `O_APPEND` + a per-reserve `flock` + a segment-
//! roll `flock` in the writer thread — deadlocked: `claim`/`compact` hold `mem` while waiting on the
//! writer, the writer took `flock` on a roll, and a concurrent reserve held `flock` while waiting for
//! `mem` — a three-way cycle. Genuinely-concurrent multi-process durable append is the harder cross-
//! process-linearizability problem the plan's Phase-0 spike scoped as a separate follow-on; it is NOT
//! attempted here.)
//!
//! Instead, [`AverinQueue::open`] takes an EXCLUSIVE, process-lifetime `flock(LOCK_EX|LOCK_NB)` on
//! `<dir>/queue.owner.lock` (held by the [`AverinQueue::_owner_lock`] `File` for the queue's whole
//! lifetime; advisory, auto-released when the struct drops OR the process dies — a crash never strands
//! it). A SECOND live process opening the same directory gets `EWOULDBLOCK` →
//! [`StorageError::AverinQueueBusy`], which `FileStorage` turns into "this process has no durable
//! averin queue and seals via the 087 async fail-open path instead" (graceful + logged, never a hang
//! or a startup failure). So `serve` and `mcp` can co-run against the same vault: exactly one owns the
//! durable queue; any other seals fail-open (the 087 default). `SegmentWriter::create`'s truncate is
//! safe under this lock because only the one owning process ever creates/rolls segments here.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::crypto::{decrypt, encrypt, EncryptedData, MasterKey};
use crate::outbox::{DeliveryState, OutboxEvent};
use crate::storage::outbox_model::{
    earliest_pending_per_subject, record_delivery_transition, OutboxCache,
};
// Reused verbatim (both are `pub(super)` in outbox_store.rs, i.e. visible throughout `crate::storage`):
// the 0600-private-file creator and the crash-durable parent-dir fsync. Not duplicated here.
use crate::storage::outbox_store::{create_private_file, fsync_parent_dir};
use crate::storage::StorageError;

/// Segment roll threshold (D0: "at a size cap (e.g. 8 MiB) start a new segment").
const SEGMENT_ROLL_BYTES: u64 = 8 * 1024 * 1024;

/// On-disk format version for a snapshot segment (independent of the vault's/outbox's own version
/// counters — this is a THIRD, separate encrypted file family). A newer file is refused (downgrade
/// guard), mirroring `OutboxStore`/the vault.
const SNAPSHOT_FILE_VERSION: u32 = 1;

/// One durable mutation of the queue's state (D0). Every variant round-trips through
/// `serde_json` → AES-256-GCM (fresh nonce per record) → one length-framed write + fsync.
///
/// `GrantResolved` is defined here (plan 088 D2/D3 will consume it once the popkey store exists) so a
/// crash between a grant delivering and the popkey store's `{grant_id, capability}` write-back can be
/// reconciled from this queue's own durable journal — it does not mutate [`OutboxCache`] and is kept in
/// a side map ([`AverinQueue::resolved_grant`]); Step 1 only needs its shape to exist and round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Delta {
    /// A fresh event, already stamped with its sequence (assigned before the record is framed, so
    /// replay is a pure re-insert — no re-derivation of "what sequence was this").
    Append(OutboxEvent),
    /// Stamp (or clear, via `until: None`) a delivery lease on `seq`.
    Lease {
        seq: u64,
        until: Option<DateTime<Utc>>,
    },
    /// A failed delivery attempt that did NOT (yet) dead-letter: the post-increment `attempts`, the
    /// resulting backoff lease, when the attempt was recorded, and the error. Storing the computed
    /// values (rather than recomputing `Utc::now()`/backoff math on replay) keeps replay a pure
    /// re-application of exactly what was decided at commit time.
    Attempt {
        seq: u64,
        attempts: u32,
        backoff_until: DateTime<Utc>,
        attempted_at: DateTime<Utc>,
        error: Option<String>,
    },
    /// Terminal success.
    Delivered { seq: u64 },
    /// Terminal failure (`attempts >= max_attempts`).
    DeadLetter { seq: u64 },
    /// Drop every sequence `<= upto_seq` from the live map (mirrors `OutboxStore::gc`'s prefix prune).
    /// Emitted by [`AverinQueue::prune_delivered_prefix`] (Codex HIGH-3 fix, plan 088 GC hardening) for
    /// the largest contiguous run of terminal-`Delivered` records past the retention window — a
    /// still-`Pending`/leased or still-`DeadLettered`-unreclaimed record blocks the prefix at that
    /// point, same as `OutboxStore::gc`'s own semantics.
    Prune { upto_seq: u64 },
    /// D4's "true MOVE", completed (plan 088 Step 6a): drop exactly ONE sequence from the live map —
    /// deliberately NOT a prefix operation like [`Delta::Prune`], because a mid-sequence `DeadLetter`
    /// can resolve (via the worker's quarantine call) while LOWER-numbered sequences for OTHER
    /// subjects are still genuinely `Pending`; a prefix drop would wrongly discard those too.
    /// **Invariant (D4, load-bearing): the caller ([`AverinQueue::reclaim_dead_letter`]) commits this
    /// ONLY for a sequence already `DeadLettered` AND already durably copied into the quarantine
    /// store** (`AverinDeadLetterStore::quarantine` must have returned `Ok` first) — never for a
    /// still-`Pending`/`Delivered` record, and never for a `DeadLettered` record whose quarantine-move
    /// has not (yet) succeeded, or the audit copy could be lost with no surviving record anywhere.
    Reclaimed { seq: u64 },
    /// averin's response to `POST /v2/grants` resolved for `token_id` (plan 088 D3). Recorded in THIS
    /// journal (not only the popkey store) so a crash between the grant delivering and the popkey
    /// write-back can be reconciled by replaying the queue that already knows the outcome.
    GrantResolved {
        token_id: String,
        grant_id: String,
        capability: String,
    },
}

/// A grant resolution recorded via [`Delta::GrantResolved`] (see its doc) and kept in a side map
/// alongside the reused [`OutboxCache`] — orthogonal to the outbox event model, so it is not folded
/// into `OutboxCache` itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolvedGrant {
    grant_id: String,
    capability: String,
}

/// The full in-memory state a [`AverinQueue`] rebuilds on replay and mutates live.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct QueueSnapshot {
    cache: OutboxCache,
    #[serde(default)]
    resolved_grants: HashMap<String, ResolvedGrant>,
}

/// The encrypted on-disk envelope for a snapshot segment (mirrors `OutboxStore`'s own file format —
/// same `encrypt`/`decrypt` + version-guard shape, just a different file family).
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotFile {
    version: u32,
    data: EncryptedData,
}

/// An open delta segment file the writer thread is currently appending to.
struct SegmentWriter {
    file: std::fs::File,
    path: PathBuf,
    index: u64,
    size: u64,
}

impl SegmentWriter {
    fn create(dir: &Path, index: u64) -> Result<Self, StorageError> {
        let path = dir.join(segment_name(index, false));
        let file = create_private_file(&path)?;
        Ok(Self {
            file,
            path,
            index,
            size: 0,
        })
    }
}

/// `<index>.delta` or `<index>.snapshot` — a fixed-width decimal index so lexical and numeric sort
/// agree (directory listings, `ls`, come back in replay order).
fn segment_name(index: u64, is_snapshot: bool) -> String {
    format!("{:020}.{}", index, if is_snapshot { "snapshot" } else { "delta" })
}

/// Parse a segment filename back into `(index, is_snapshot)`; `None` for anything else in the
/// directory (defensive — an operator dropping a stray file in the queue dir must not crash replay).
fn parse_segment_name(name: &str) -> Option<(u64, bool)> {
    let (stem, ext) = name.rsplit_once('.')?;
    let is_snapshot = match ext {
        "snapshot" => true,
        "delta" => false,
        _ => return None,
    };
    let index: u64 = stem.parse().ok()?;
    Some((index, is_snapshot))
}

/// List `(index, path, is_snapshot)` for every recognized segment file in `dir`, ascending by index.
fn list_segments(dir: &Path) -> Result<Vec<(u64, PathBuf, bool)>, StorageError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some((index, is_snapshot)) = parse_segment_name(&name) {
            out.push((index, entry.path(), is_snapshot));
        }
    }
    out.sort_by_key(|(index, _, _)| *index);
    Ok(out)
}

/// The frame's magic prefix (Codex HIGH-5 hardening): makes the header self-describing so that
/// interior corruption of the length prefix cannot be misread as a valid frame boundary and mistaken
/// for a torn tail. `AVQ1` — "AVerin Queue, format 1".
const FRAME_MAGIC: [u8; 4] = *b"AVQ1";

/// `MAGIC(4) ‖ len:u32_be(4) ‖ len_crc32:u32_be(4)` — the fixed-size, self-describing frame header
/// (Codex HIGH-5). `sealed_bytes` (the AEAD-sealed, `len`-byte payload) follows immediately after.
const FRAME_HEADER_LEN: usize = 12;

/// Minimal CRC-32 (IEEE 802.3 / zlib polynomial `0xEDB88320`), computed bit-by-bit rather than via a
/// lookup table — this only ever runs over the 4-byte length field (never the payload, which is
/// already AEAD-sealed and doesn't need a second integrity check), so a table's throughput would be
/// wasted. Deliberately self-contained (no new crate dependency) so this fix stays scoped to this
/// module; see the module doc's "Crash safety" section for what this closes.
fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Seal one [`Delta`] into a ready-to-write frame: `MAGIC ‖ len:u32_be ‖ len_crc32:u32_be ‖
/// sealed_bytes`, where `sealed_bytes` is the JSON encoding of the crate's [`EncryptedData`] (fresh
/// nonce per record, the shared vault master key) — the same envelope shape `OutboxStore` uses for its
/// whole-file blob, applied here per-record, with a self-describing header (Codex HIGH-5) added around
/// it.
fn seal_delta(delta: &Delta, key: &MasterKey) -> Result<Vec<u8>, StorageError> {
    let plaintext =
        serde_json::to_vec(delta).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let sealed = encrypt(&plaintext, key)?;
    let body =
        serde_json::to_vec(&sealed).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let len = u32::try_from(body.len()).map_err(|_| {
        StorageError::Serialization("averin-queue record exceeds the 4 GiB frame limit".into())
    })?;
    let len_bytes = len.to_be_bytes();
    let len_crc = crc32_ieee(&len_bytes);
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.extend_from_slice(&len_bytes);
    frame.extend_from_slice(&len_crc.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn parse_and_decrypt_delta(body: &[u8], key: &MasterKey) -> Result<Delta, StorageError> {
    let sealed: EncryptedData =
        serde_json::from_slice(body).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let plaintext = decrypt(&sealed, key)?;
    serde_json::from_slice(&plaintext).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Replay one delta segment into a flat `Vec<Delta>`, in file order. See the module doc's "Crash
/// safety" section for the torn-tail vs. interior-corruption distinction this implements (Codex
/// HIGH-5: the header is now self-describing — `MAGIC ‖ len ‖ len_crc32` — so a corrupted length can
/// no longer be misread as a valid-but-wrong frame boundary).
fn replay_segment(path: &Path, key: &MasterKey) -> Result<Vec<Delta>, StorageError> {
    let buf = std::fs::read(path)?;
    let mut pos = 0usize;
    let mut deltas = Vec::new();
    while pos < buf.len() {
        let remaining = buf.len() - pos;

        // (1) Partial header: fewer than FRAME_HEADER_LEN bytes remain. A process death mid-`write()`
        // truncates the file at exactly the point it reached — this is a genuine torn tail.
        if remaining < FRAME_HEADER_LEN {
            tracing::warn!(
                file = %path.display(),
                offset = pos,
                discarded_bytes = remaining,
                "torn trailing averin-queue record (partial frame header) — discarding; \
                 all prior records in this segment are intact"
            );
            break;
        }

        let magic: [u8; 4] = buf[pos..pos + 4].try_into().expect("4 bytes");
        // (2) Bad magic: a torn write never fabricates a wrong magic (it only truncates), so this is
        // interior corruption — fail closed rather than risk misreading a bogus frame boundary.
        if magic != FRAME_MAGIC {
            return Err(StorageError::Serialization(format!(
                "corrupt averin-queue frame header in {} at offset {pos} (bad magic) — not a torn \
                 tail (a torn write only truncates, it never fabricates a wrong magic); refusing to \
                 replay past possible interior data loss",
                path.display()
            )));
        }

        let len_bytes: [u8; 4] = buf[pos + 4..pos + 8].try_into().expect("4 bytes");
        let len = u32::from_be_bytes(len_bytes) as usize;
        let claimed_crc = u32::from_be_bytes(buf[pos + 8..pos + 12].try_into().expect("4 bytes"));
        // (3) The magic matched but the length's own CRC doesn't: the header was durably committed
        // (magic intact), so a corrupted length here is interior corruption, not a torn tail — this
        // is exactly the case Codex HIGH-5 flagged (an enlarged/corrupted interior length previously
        // fell straight through to "claims more bytes than remain" and was silently treated as a torn
        // tail, dropping that record and every later one).
        if crc32_ieee(&len_bytes) != claimed_crc {
            return Err(StorageError::Serialization(format!(
                "corrupt averin-queue frame header in {} at offset {pos} (length-prefix CRC \
                 mismatch, claimed_len={len}) — not a torn tail (the magic was intact); refusing to \
                 replay past possible interior data loss",
                path.display()
            )));
        }

        // (4) Header fully valid, but the claimed payload doesn't fit in what's left: a genuine torn
        // tail (a record was mid-write when the process died).
        if FRAME_HEADER_LEN + len > remaining {
            tracing::warn!(
                file = %path.display(),
                offset = pos,
                claimed_len = len,
                available = remaining - FRAME_HEADER_LEN,
                "torn trailing averin-queue record (intact header, partial payload) — discarding; \
                 all prior records in this segment are intact"
            );
            break;
        }

        let body = &buf[pos + FRAME_HEADER_LEN..pos + FRAME_HEADER_LEN + len];
        match parse_and_decrypt_delta(body, key) {
            Ok(delta) => {
                deltas.push(delta);
                pos += FRAME_HEADER_LEN + len;
            }
            Err(e) => {
                // (5) Header fully valid AND the full claimed-length payload is present, yet it fails
                // to authenticate/parse. A fully-present frame means the single `write()` call that
                // appended it (`Writer::write_and_maybe_roll`) completed — there is no "torn" shape
                // left to explain this. Codex HIGH-5: previously a failure here was assumed torn
                // WHENEVER it was the last frame in the file, silently discarding a genuinely
                // corrupted, already-fsynced record. Fail closed instead, regardless of position.
                return Err(StorageError::Serialization(format!(
                    "corrupt averin-queue record in {} at offset {pos} (frame header intact, full \
                     payload present, but it failed to authenticate: {e}) — not a torn tail; \
                     refusing to replay past possible interior data loss",
                    path.display()
                )));
            }
        }
    }
    Ok(deltas)
}

/// Apply one [`Delta`] to the live in-memory state — shared by replay (folding a whole segment) and
/// live operation (applying exactly one delta right after its commit is confirmed durable).
fn apply_delta(cache: &mut OutboxCache, resolved: &mut HashMap<String, ResolvedGrant>, delta: Delta) {
    match delta {
        Delta::Append(event) => {
            cache.outbox_seq = cache.outbox_seq.max(event.sequence);
            cache.outbox.insert(event.sequence, event);
        }
        Delta::Lease { seq, until } => {
            if let Some(e) = cache.outbox.get_mut(&seq) {
                e.leased_until = until;
            }
        }
        Delta::Attempt {
            seq,
            attempts,
            backoff_until,
            attempted_at,
            error,
        } => {
            if let Some(e) = cache.outbox.get_mut(&seq) {
                e.attempts = attempts;
                e.last_attempt_at = Some(attempted_at);
                e.last_error = error;
                e.leased_until = Some(backoff_until);
            }
        }
        Delta::Delivered { seq } => {
            if let Some(e) = cache.outbox.get_mut(&seq) {
                e.delivery = DeliveryState::Delivered;
                e.leased_until = None;
                e.last_error = None;
            }
        }
        Delta::DeadLetter { seq } => {
            if let Some(e) = cache.outbox.get_mut(&seq) {
                e.delivery = DeliveryState::DeadLettered;
                e.leased_until = None;
            }
        }
        Delta::Prune { upto_seq } => {
            cache.outbox.retain(|seq, _| *seq > upto_seq);
        }
        Delta::Reclaimed { seq } => {
            cache.outbox.remove(&seq);
        }
        Delta::GrantResolved {
            token_id,
            grant_id,
            capability,
        } => {
            resolved.insert(token_id, ResolvedGrant { grant_id, capability });
        }
    }
}

fn write_snapshot(
    dir: &Path,
    index: u64,
    key: &MasterKey,
    snapshot: &QueueSnapshot,
) -> Result<(), StorageError> {
    let data =
        serde_json::to_vec(snapshot).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt(&data, key)?;
    let file = SnapshotFile {
        version: SNAPSHOT_FILE_VERSION,
        data: encrypted,
    };
    let content =
        serde_json::to_string(&file).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let final_path = dir.join(segment_name(index, true));
    let tmp_path = dir.join(format!("{:020}.snapshot.tmp", index));
    {
        // fsync the tmp BEFORE the rename, same discipline as `OutboxStore::write_to_disk`: the
        // rename gives crash-atomicity of the directory entry, only `sync_all` makes the CONTENTS
        // durable before that entry becomes visible.
        let f = create_private_file(&tmp_path)?;
        use std::io::Write;
        let mut w = std::io::BufWriter::new(f);
        w.write_all(content.as_bytes())?;
        w.flush()?;
        w.into_inner()
            .map_err(|e| StorageError::Io(e.into_error()))?
            .sync_all()?;
    }
    std::fs::rename(&tmp_path, &final_path)?;
    fsync_parent_dir(&final_path)?;
    Ok(())
}

fn read_snapshot(path: &Path, key: &MasterKey) -> Result<QueueSnapshot, StorageError> {
    let content = std::fs::read_to_string(path)?;
    let file: SnapshotFile =
        serde_json::from_str(&content).map_err(|e| StorageError::Serialization(e.to_string()))?;
    if file.version > SNAPSHOT_FILE_VERSION {
        return Err(StorageError::UnsupportedVersion {
            found: file.version,
            supported: SNAPSHOT_FILE_VERSION,
        });
    }
    let plaintext = decrypt(&file.data, key)?;
    serde_json::from_slice(&plaintext).map_err(|e| StorageError::Serialization(e.to_string()))
}

// ---- the group-commit background writer ----

/// One unit of work the writer thread executes, in strict FIFO order relative to every other job any
/// caller has enqueued (this ordering is what makes [`AverinQueue::compact`]'s cutover safe — see its
/// doc). `Roll` forces an immediate segment rotation (used only by `compact`); ordinary appends never
/// need to force one (the writer rolls on its own at [`SEGMENT_ROLL_BYTES`]).
enum WriteJob {
    Data(Vec<u8>),
    Roll,
}

struct JobResult {
    outcome: Mutex<Option<Result<u64, String>>>,
    cv: Condvar,
}

impl JobResult {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(None),
            cv: Condvar::new(),
        })
    }

    fn finish(&self, outcome: Result<u64, String>) {
        *self.outcome.lock() = Some(outcome);
        self.cv.notify_one();
    }

    /// Block until the writer thread has recorded an outcome for this job.
    fn wait(&self) -> Result<u64, StorageError> {
        let mut guard = self.outcome.lock();
        loop {
            if let Some(outcome) = guard.take() {
                return outcome.map_err(|msg| StorageError::Io(std::io::Error::other(msg)));
            }
            self.cv.wait(&mut guard);
        }
    }
}

struct PendingJob {
    job: WriteJob,
    result: Arc<JobResult>,
}

struct WriterShared {
    queue: Mutex<VecDeque<PendingJob>>,
    cv: Condvar,
    shutdown: AtomicBool,
}

/// The dedicated single writer thread (D0: "a dedicated single writer thread + producer enqueue +
/// group-commit"). Producers never touch the segment file directly; they hand a sealed frame to
/// [`Writer::commit`], which blocks until the batch containing it has been written AND fsynced.
struct Writer {
    shared: Arc<WriterShared>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Writer {
    fn spawn(dir: PathBuf, segment: SegmentWriter) -> Self {
        let shared = Arc::new(WriterShared {
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
        });
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name("averin-queue-writer".into())
            .spawn(move || Self::run(thread_shared, dir, segment))
            .expect("spawning the averin-queue durable writer thread");
        Self {
            shared,
            handle: Some(handle),
        }
    }

    fn run(shared: Arc<WriterShared>, dir: PathBuf, mut segment: SegmentWriter) {
        loop {
            let mut q = shared.queue.lock();
            shared
                .cv
                .wait_while(&mut q, |q| q.is_empty() && !shared.shutdown.load(Ordering::Acquire));
            if q.is_empty() {
                // Only reachable via shutdown with nothing left queued.
                return;
            }
            let batch: VecDeque<PendingJob> = std::mem::take(&mut *q);
            drop(q); // release the queue lock before doing any I/O

            Self::run_batch(&mut segment, &dir, batch);
        }
    }

    /// Write every job in `batch`, in order, then issue ONE fsync covering all of it (group-commit) —
    /// unless an explicit `Roll` job or the size cap forces an earlier fsync+rotation. A failure at
    /// any point fails every job from that point on in the batch (conservative: no ambiguous partial
    /// durability within one batch); jobs already durably written before the failure keep their `Ok`.
    fn run_batch(segment: &mut SegmentWriter, dir: &Path, batch: VecDeque<PendingJob>) {
        let mut failed: Option<String> = None;
        let mut pending_ok: Vec<Arc<JobResult>> = Vec::with_capacity(batch.len());
        let mut dirty_since_fsync = false;

        for pj in batch {
            if let Some(msg) = &failed {
                pj.result.finish(Err(msg.clone()));
                continue;
            }
            let outcome = match &pj.job {
                WriteJob::Data(frame) => Self::write_and_maybe_roll(
                    segment,
                    dir,
                    frame,
                    &mut dirty_since_fsync,
                ),
                WriteJob::Roll => Self::force_roll(segment, dir, &mut dirty_since_fsync),
            };
            match outcome {
                Ok(()) => pending_ok.push(pj.result),
                Err(e) => {
                    let msg = e.to_string();
                    pj.result.finish(Err(msg.clone()));
                    failed = Some(msg);
                }
            }
        }

        if failed.is_none() && dirty_since_fsync {
            if let Err(e) = segment.file.sync_all() {
                failed = Some(e.to_string());
            }
        }
        let final_index = segment.index;
        for result in pending_ok {
            match &failed {
                None => result.finish(Ok(final_index)),
                Some(msg) => result.finish(Err(msg.clone())),
            }
        }
    }

    fn write_and_maybe_roll(
        segment: &mut SegmentWriter,
        dir: &Path,
        frame: &[u8],
        dirty_since_fsync: &mut bool,
    ) -> Result<(), StorageError> {
        use std::io::Write;
        // A whole record in ONE bounded `write()` call (D0/D1: the spike proved this is atomic even
        // across concurrent OS processes when the file is opened `O_APPEND` — see the module doc's
        // "Scope boundary" section for why this Step-1 module doesn't rely on that yet: one writer
        // thread per process, sequential writes on a single held-open handle, is enough for now).
        let n = segment.file.write(frame)?;
        if n != frame.len() {
            return Err(StorageError::Io(std::io::Error::other(
                "short write appending an averin-queue record (not a single atomic write)",
            )));
        }
        segment.size += frame.len() as u64;
        *dirty_since_fsync = true;
        if segment.size >= SEGMENT_ROLL_BYTES {
            segment.file.sync_all()?;
            *dirty_since_fsync = false;
            let next = SegmentWriter::create(dir, segment.index + 1)?;
            *segment = next;
            fsync_parent_dir(&segment.path)?;
        }
        Ok(())
    }

    fn force_roll(
        segment: &mut SegmentWriter,
        dir: &Path,
        dirty_since_fsync: &mut bool,
    ) -> Result<(), StorageError> {
        if *dirty_since_fsync {
            segment.file.sync_all()?;
            *dirty_since_fsync = false;
        }
        let next = SegmentWriter::create(dir, segment.index + 1)?;
        *segment = next;
        fsync_parent_dir(&segment.path)
    }

    /// Durably append one sealed frame. Blocks until the batch containing it (whatever else was
    /// queued at the same instant, from any caller) has been fully written AND fsynced.
    fn commit(&self, frame: Vec<u8>) -> Result<(), StorageError> {
        let result = JobResult::new();
        {
            let mut q = self.shared.queue.lock();
            q.push_back(PendingJob {
                job: WriteJob::Data(frame),
                result: Arc::clone(&result),
            });
        }
        self.shared.cv.notify_one();
        result.wait().map(|_| ())
    }

    /// Flush everything queued so far and rotate to a brand-new segment; returns the new segment's
    /// index. Used only by [`AverinQueue::compact`] to establish a clean cutover point.
    fn roll(&self) -> Result<u64, StorageError> {
        let result = JobResult::new();
        {
            let mut q = self.shared.queue.lock();
            q.push_back(PendingJob {
                job: WriteJob::Roll,
                result: Arc::clone(&result),
            });
        }
        self.shared.cv.notify_one();
        result.wait()
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Pre-existing, unrelated lost-wakeup fix (found while stress-testing this file for the
        // committing-set fix, and reproduced on the UNMODIFIED base code too — ~1/25 runs hung under
        // `--test-threads=1`, so it predates and is independent of the `committing` change above):
        // `shutdown` MUST be set while holding `shared.queue`'s lock, the SAME lock `Writer::run`'s
        // `wait_while` holds while re-checking `q.is_empty() && !shutdown.load(..)` right before
        // atomically unlocking-and-parking. Setting it without that lock (the original code) races:
        // if the store + `notify_all` land entirely inside the writer's "predicate just evaluated
        // true, about to park" window, there is nothing yet registered for `notify_all` to wake, and
        // the notification is silently lost — the writer parks forever and `join()` below hangs.
        // Acquiring `shared.queue` first forces the store to happen-after any park registration
        // already in flight (the writer can't be mid-park while we hold its mutex), so a subsequent
        // `notify_all` is guaranteed to either find it already parked or arrive before it next checks.
        {
            let _queue_guard = self.shared.queue.lock();
            self.shared.shutdown.store(true, Ordering::Release);
        }
        self.shared.cv.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---- the queue itself ----

struct QueueMemory {
    cache: OutboxCache,
    resolved_grants: HashMap<String, ResolvedGrant>,
    /// Sequences published into `cache.outbox` (so [`AverinQueue::compact`]/
    /// [`AverinQueue::prune_delivered_prefix`] always observe them) whose durable commit has NOT yet
    /// been confirmed by the group-commit writer. [`AverinQueue::claim`]/[`AverinQueue::deliverable`]/
    /// [`AverinQueue::record_delivery`] treat any sequence in this set as not-yet-durable and skip/
    /// refuse it — claiming or delivering it before its own `Delta::Append` has committed is exactly
    /// the Codex HIGH-2 resurrection hole. [`AverinQueue::compact`]/
    /// [`AverinQueue::prune_delivered_prefix`] instead WAIT (on [`AverinQueue::committing_cv`]) for
    /// this set to fully drain before snapshotting/pruning, so a durably-committed-but-still-
    /// committing event is never snapshotted-and-then-deleted out from under itself (Codex re-review
    /// #2/#3) nor pruned past by an `upto_seq` computed while it was still invisible to that scan. See
    /// [`AverinQueue::append`]'s doc for the full incident and fix.
    committing: HashSet<u64>,
}

/// Same head-of-line semantics as [`earliest_pending_per_subject`], but additionally treats any
/// sequence present in `committing` as if it weren't in the map at all — i.e. not yet durable, so it
/// must never be claimed or reported deliverable (see [`AverinQueue::append`]'s doc for why).
/// Delegates straight to the shared helper when `committing` is empty (the overwhelmingly common
/// case — appends are fast, so the set drains almost immediately), so ordinary operation pays no
/// extra cost or behavior difference from the reused `outbox_model` logic.
///
/// **Per-subject FIFO (Codex R3 HIGH-2)**: a `committing` seq is not merely skipped — it also marks
/// its subject `seen`, head-of-line-blocking every LATER seq for that same subject this pass, even
/// once that later seq is itself durable. Without this, a subject with an earlier seq `N` still
/// committing and a later seq `N+1` already committed would have `N` skipped (still committing) and
/// then `N+1` claimed — delivering `N+1` before `N` is even durable, out of order. Skipping this
/// subject entirely for one pass is harmless: the scan runs again on the next tick, and `N` claims
/// (and unblocks `N+1`) as soon as its own commit lands.
fn earliest_pending_per_subject_skipping_committing(
    outbox: &BTreeMap<u64, OutboxEvent>,
    committing: &HashSet<u64>,
    limit: usize,
    respect_lease: bool,
    now: DateTime<Utc>,
) -> Vec<OutboxEvent> {
    if committing.is_empty() {
        return earliest_pending_per_subject(outbox, limit, respect_lease, now);
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (seq, e) in outbox.iter() {
        if committing.contains(seq) {
            seen.insert(e.subject.as_str());
            continue;
        }
        if e.delivery != DeliveryState::Pending {
            continue;
        }
        if !seen.insert(e.subject.as_str()) {
            continue;
        }
        if respect_lease && e.leased_until.is_some_and(|t| t > now) {
            continue;
        }
        out.push(e.clone());
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// Cap on how long [`AverinQueue::compact`]/[`AverinQueue::prune_delivered_prefix`] will wait on
/// [`AverinQueue::committing_cv`] for `committing` to drain (Codex R3 MEDIUM-4 — liveness). A commit
/// stuck in unbounded file I/O (or enough overlapping appends to keep the set perpetually nonempty)
/// must never wedge these — both are best-effort GC run synchronously from the periodic tick, so a
/// stalled waiter here stalls every later GC/delivery pass too. On timeout, the caller skips this
/// pass entirely (compacting/pruning nothing) and retries on the next tick, rather than blocking
/// forever; the happy path (fast-draining `committing`) is unaffected — it still proceeds the moment
/// the set empties, well under this cap.
const COMMITTING_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The averin USE queue's durable append-only journal (plan 088 D0). See the module doc for the
/// on-disk shape, crash-safety contract, and locking model.
pub struct AverinQueue {
    dir: PathBuf,
    master_key: Arc<MasterKey>,
    mem: Mutex<QueueMemory>,
    /// Paired with `mem`: signalled whenever `mem.lock().committing` becomes empty (see
    /// [`AverinQueue::publish_committed`]/[`AverinQueue::abort_committing`]). [`AverinQueue::compact`]/
    /// [`AverinQueue::prune_delivered_prefix`] wait on this before snapshotting/pruning — see
    /// [`AverinQueue::append`]'s doc for the incident this closes and the deadlock-freedom argument.
    committing_cv: Condvar,
    writer: Writer,
    /// The exclusive, process-lifetime ownership lock (`flock` on `<dir>/queue.owner.lock`). Held for
    /// the queue's entire lifetime so exactly one process operates this directory (see the module doc's
    /// "Cross-process safety" section). Declared AFTER `writer` so on drop the writer thread joins
    /// (flushing its last batch) BEFORE this lock releases — a sibling process can't take ownership
    /// until our writer has fully quiesced. Never read; its Drop is the whole point.
    _owner_lock: std::fs::File,
}

/// Acquire the EXCLUSIVE, process-lifetime ownership lock for a queue directory (Step 3a, Option A).
/// A raw non-blocking `flock(LOCK_EX|LOCK_NB)` on a held-open `<dir>/queue.owner.lock`: advisory,
/// auto-released when the returned `File` drops or the process dies (a crash never strands it). Returns
/// [`StorageError::AverinQueueBusy`] if another live process already owns the directory — the caller
/// (`FileStorage`) degrades that process to 087 async fail-open sealing rather than hanging or failing
/// startup. The lock file is opened read-write WITHOUT truncation (its bytes are irrelevant; only the
/// `flock` matters), `0600`.
fn acquire_owner_lock(dir: &Path) -> Result<std::fs::File, StorageError> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join("queue.owner.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        // truncate(false) is LOAD-BEARING and must stay explicit: this file is a pure flock
        // anchor shared with any other live process holding the directory. Truncating it on
        // open would be a write to a file another owner has open, and `.create(true)` without
        // a stated truncate policy is exactly what clippy::suspicious_open_options flags.
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    // rustix exposes the OS operation through a safe OwnedFd/BorrowedFd API, so
    // the library can enforce `forbid(unsafe_code)` without weakening the
    // process-lifetime advisory-lock semantics.
    match rustix::fs::flock(
        &file,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    ) {
        Ok(()) => Ok(file),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
            Err(StorageError::AverinQueueBusy(dir.display().to_string()))
        }
        Err(error) => Err(StorageError::Io(std::io::Error::from_raw_os_error(
            error.raw_os_error(),
        ))),
    }
}

impl AverinQueue {
    /// Open (creating if absent) the queue directory at `dir`, replaying the latest snapshot (if any)
    /// plus every delta segment above it to rebuild the live map, then start a FRESH delta segment for
    /// subsequent appends (never continue appending into a segment that might carry a torn tail —
    /// simpler and safer than truncating-then-reopening it).
    pub fn open(dir: PathBuf, master_key: Arc<MasterKey>) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&dir)?;
        // Claim exclusive process ownership BEFORE any replay/segment side effect (Option A — a busy
        // queue reports cleanly, never partially opens). Released when the returned struct drops.
        let owner_lock = acquire_owner_lock(&dir)?;
        let entries = list_segments(&dir)?;

        let snapshot_index = entries
            .iter()
            .rev()
            .find(|(_, _, is_snapshot)| *is_snapshot)
            .map(|(index, _, _)| *index);

        let mut cache = OutboxCache::default();
        let mut resolved_grants = HashMap::new();
        if let Some(index) = snapshot_index {
            let snap = read_snapshot(&dir.join(segment_name(index, true)), &master_key)?;
            cache = snap.cache;
            resolved_grants = snap.resolved_grants;
        }

        let base_index = snapshot_index.unwrap_or(0);
        let mut max_index = base_index;
        for (index, path, is_snapshot) in &entries {
            if *is_snapshot || *index <= base_index {
                continue;
            }
            let deltas = replay_segment(path, &master_key)?;
            for delta in deltas {
                apply_delta(&mut cache, &mut resolved_grants, delta);
            }
            max_index = max_index.max(*index);
        }

        // Best-effort hygiene: segments strictly below the chosen snapshot are superseded leftovers
        // from an interrupted compaction. Never required for correctness (they were never replayed
        // above), only cleanup.
        for (index, path, _) in &entries {
            if *index < base_index {
                let _ = std::fs::remove_file(path);
            }
        }

        let next_index = max_index + 1;
        let segment = SegmentWriter::create(&dir, next_index)?;
        fsync_parent_dir(&segment.path)?;
        let writer = Writer::spawn(dir.clone(), segment);

        Ok(Self {
            dir,
            master_key,
            mem: Mutex::new(QueueMemory {
                cache,
                resolved_grants,
                committing: HashSet::new(),
            }),
            committing_cv: Condvar::new(),
            writer,
            _owner_lock: owner_lock,
        })
    }

    /// Reserve a fresh monotonic sequence, build its [`OutboxEvent`], and publish it IMMEDIATELY into
    /// `mem.cache.outbox` (so [`Self::compact`]/[`Self::prune_delivered_prefix`] always observe it) —
    /// but mark its sequence `committing` (`QueueMemory::committing`) until [`Self::finish_append`]'s
    /// commit is confirmed durable. See [`Self::append`]'s doc for why publishing immediately (rather
    /// than the prior fix's deferred insert) is the correct fix here. Split out of `append` so a test
    /// can exercise the exact reserve/commit interleaving Codex flagged.
    fn reserve_for_append(
        &self,
        subject: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> (u64, OutboxEvent) {
        let mut mem = self.mem.lock();
        mem.cache.outbox_seq += 1;
        let seq = mem.cache.outbox_seq;
        let event = OutboxEvent {
            sequence: seq,
            subject: subject.to_string(),
            event_type: event_type.to_string(),
            payload,
            created_at: Utc::now(),
            delivery: DeliveryState::Pending,
            attempts: 0,
            leased_until: None,
            last_attempt_at: None,
            last_error: None,
            dedup_id: None,
        };
        mem.cache.outbox.insert(seq, event.clone());
        mem.committing.insert(seq);
        (seq, event)
    }

    /// Seal + durably commit `event`'s `Delta::Append`. `seq`/`event` were already published into
    /// `mem.cache.outbox` (marked `committing`) by [`Self::reserve_for_append`]; this call only
    /// settles that marker: [`Self::publish_committed`] on success, [`Self::abort_committing`] on
    /// failure (which also removes the optimistically-published event — a failed commit must leave no
    /// phantom entry with nothing durable backing it, same "burned sequence, nothing left to roll
    /// back but the map entry" contract as before).
    fn finish_append(&self, seq: u64, event: OutboxEvent) -> Result<u64, StorageError> {
        let delta = Delta::Append(event);
        let commit_result =
            seal_delta(&delta, &self.master_key).and_then(|frame| self.writer.commit(frame));
        match commit_result {
            Ok(()) => {
                self.publish_committed(seq);
                Ok(seq)
            }
            Err(e) => {
                self.abort_committing(seq);
                Err(e)
            }
        }
    }

    /// `seq`'s commit is now confirmed durable: clear it from `committing` and wake anything waiting
    /// on [`Self::committing_cv`] — most notably [`Self::compact`]/[`Self::prune_delivered_prefix`],
    /// which wait for `committing` to fully drain before snapshotting/pruning (see their docs, and
    /// [`Self::append`]'s doc for the incident this closes). The event itself needs no further
    /// mutation here — it was already published into `mem.cache.outbox` back in
    /// [`Self::reserve_for_append`].
    fn publish_committed(&self, seq: u64) {
        let mut mem = self.mem.lock();
        mem.committing.remove(&seq);
        drop(mem);
        self.committing_cv.notify_all();
    }

    /// `seq`'s commit FAILED: remove the optimistically-published event from `mem.cache.outbox`
    /// entirely (nothing durable backs it, so it must leave no phantom Pending record) and clear
    /// `committing`, then wake anything waiting on [`Self::committing_cv`] (a waiter must never block
    /// forever behind a commit that will never succeed).
    fn abort_committing(&self, seq: u64) {
        let mut mem = self.mem.lock();
        mem.cache.outbox.remove(&seq);
        mem.committing.remove(&seq);
        drop(mem);
        self.committing_cv.notify_all();
    }

    /// Append a new event. **The hot-path method** (D0's SLO target): one sealed frame, one durable
    /// commit.
    ///
    /// **History — three review passes on the same window, closed together by this fix:**
    ///
    /// 1. *Original bug (Codex HIGH-2, resurrection)*: the freshly reserved event was inserted into
    ///    `mem.cache.outbox` (making it claimable) BEFORE its `Delta::Append` had committed durably,
    ///    then rolled back on failure. A concurrent worker's [`Self::claim`] +
    ///    [`Self::record_delivery`] could commit `Lease`/`Delivered` deltas for the sequence before its
    ///    own `Append` landed on disk. If this call's commit then landed AFTER those (independent
    ///    commits queued to the same group-commit writer — nothing ordered them relative to each
    ///    other), the journal read `Lease`, `Delivered`, `Append` in that order; on replay,
    ///    `Lease`/`Delivered` were no-ops against a not-yet-inserted sequence (see [`apply_delta`]),
    ///    and the trailing `Append` then resurrected an already-delivered use as fresh, re-deliverable
    ///    `Pending` work — a real bug for a fail-closed metering/credential queue.
    /// 2. *First fix (deferred insert)*: reserve the sequence WITHOUT publishing it into
    ///    `mem.cache.outbox` at all, commit `Delta::Append` durably, and ONLY on success insert the
    ///    event. This closed the resurrection hole — but opened a NEW one (Codex re-review #2/#3):
    ///    between `writer.commit` returning `Ok` and the subsequent re-acquisition of `mem` to insert
    ///    the event, the event was durably committed on disk yet completely invisible to
    ///    `mem.cache.outbox`. A concurrent [`Self::compact`] (which snapshots `mem.cache` then DELETES
    ///    every segment its snapshot supersedes) running in that window would snapshot without ever
    ///    seeing the event, then delete the very segment holding its only durable copy — an
    ///    acknowledged, durably-committed event silently lost on the next crash. [`Self::
    ///    prune_delivered_prefix`] had a subtler shape of the same hole: a lower-numbered
    ///    committing-but-invisible sequence sitting behind an already-`Delivered` higher one let the
    ///    prefix scan compute a `Prune{upto_seq}` that, on replay, applied AFTER that lower sequence's
    ///    own `Append` — deleting a genuinely-`Pending` record that was never eligible for pruning.
    /// 3. *This fix (the `committing` set)*: publish the event into `mem.cache.outbox` IMMEDIATELY, in
    ///    [`Self::reserve_for_append`] under the same `mem` lock as the sequence bump — so `compact`/
    ///    `prune_delivered_prefix` always see it — but mark its sequence `committing`
    ///    (`QueueMemory::committing`) until [`Self::publish_committed`] clears it on a confirmed
    ///    durable commit ([`Self::abort_committing`] instead removes the event entirely on a failed
    ///    commit, preserving the "no phantom entry" contract). [`Self::claim`]/[`Self::deliverable`]
    ///    skip any sequence still `committing` (never claim/report a not-yet-durable event — the
    ///    original HIGH-2 hole stays closed), and [`Self::record_delivery`] refuses to act on one too.
    ///    Separately, [`Self::compact`]/[`Self::prune_delivered_prefix`] WAIT (on
    ///    [`Self::committing_cv`]) for `committing` to fully drain before snapshotting/pruning, so
    ///    every event they act on is either already durably committed (safe to include/prune around)
    ///    or not reserved at all yet (irrelevant to that pass). This closes both holes at once without
    ///    reintroducing the first.
    ///
    /// **Deadlock-freedom**: [`Self::finish_append`] never holds `mem` while blocked on
    /// `self.writer.commit` — it releases `mem` at the end of [`Self::reserve_for_append`], and only
    /// re-acquires it, briefly, in [`Self::publish_committed`]/[`Self::abort_committing`] AFTER the
    /// commit call has already returned. The writer thread ([`Writer::run`]) never touches
    /// `mem`/`committing` at all — only its own `WriterShared` queue and the segment file. So
    /// `compact`/`prune_delivered_prefix` waiting on `committing_cv` (which, per the `Condvar`
    /// contract, atomically releases `mem` for the duration of the wait) can never cycle with the
    /// writer: the one thing that needs `mem` back to clear `committing` (a `finish_append` whose
    /// commit already returned) is never itself waiting on the writer, and the writer never waits on
    /// `mem` — no lock/wait ordering cycle exists among `mem`, `committing_cv`, `WriterShared`'s queue
    /// lock, or any individual `JobResult`. `outbox_seq` is still intentionally left advanced on a
    /// genuine commit failure (a burned sequence number is preferable to reusing one under concurrency
    /// — see the module doc's locking-model note).
    pub fn append(
        &self,
        subject: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StorageError> {
        let (seq, event) = self.reserve_for_append(subject, event_type, payload);
        self.finish_append(seq, event)
    }

    /// Claim the earliest-pending event per subject for delivery, durably stamping a lease so a
    /// sibling worker won't double-deliver. Holds the in-memory lock for the full call (see the module
    /// doc's locking-model note) and rolls back any lease already applied in THIS call if a later one
    /// in the same batch fails to commit. Skips anything still `committing` (not yet durable — see
    /// [`Self::append`]'s doc): claiming it before its own `Delta::Append` has committed is the
    /// original Codex HIGH-2 resurrection hole.
    pub fn claim(&self, limit: usize, lease_secs: u64) -> Result<Vec<OutboxEvent>, StorageError> {
        let mut mem = self.mem.lock();
        let now = Utc::now();
        let claimed = earliest_pending_per_subject_skipping_committing(
            &mem.cache.outbox,
            &mem.committing,
            limit,
            true,
            now,
        );
        if claimed.is_empty() {
            return Ok(vec![]);
        }
        // Floor at 1s + clamp, never panic — mirrors `OutboxStore::claim`'s exact guard.
        let secs = lease_secs.clamp(1, 31_556_952) as i64;
        let lease_until = chrono::Duration::try_seconds(secs)
            .and_then(|d| now.checked_add_signed(d))
            .unwrap_or(now);

        let mut previous: Vec<(u64, Option<DateTime<Utc>>)> = Vec::with_capacity(claimed.len());
        for e in &claimed {
            let delta = Delta::Lease {
                seq: e.sequence,
                until: Some(lease_until),
            };
            let frame = seal_delta(&delta, &self.master_key)?;
            if let Err(err) = self.writer.commit(frame) {
                for (seq, prev) in previous {
                    if let Some(ev) = mem.cache.outbox.get_mut(&seq) {
                        ev.leased_until = prev;
                    }
                }
                return Err(err);
            }
            previous.push((e.sequence, e.leased_until));
            if let Some(stored) = mem.cache.outbox.get_mut(&e.sequence) {
                stored.leased_until = Some(lease_until);
            }
        }
        Ok(claimed
            .into_iter()
            .map(|mut e| {
                e.leased_until = Some(lease_until);
                e
            })
            .collect())
    }

    /// Record a delivery attempt's outcome (success/failure-with-backoff/dead-letter — the reused
    /// `record_delivery_transition` arithmetic, identical to `OutboxStore::record_delivery`). Holds the
    /// in-memory lock for the full call and rolls back to the pre-transition snapshot if the durable
    /// commit fails, so a caller's natural retry sees the SAME pre-transition state (never silently
    /// swallowed by a phantom in-memory-only transition). Refuses (no-op, `Ok(false)`) a sequence still
    /// `committing` — see [`Self::append`]'s doc for why.
    pub fn record_delivery(
        &self,
        sequence: u64,
        success: bool,
        error: Option<String>,
        max_attempts: u32,
    ) -> Result<bool, StorageError> {
        let mut mem = self.mem.lock();
        if mem.committing.contains(&sequence) {
            // Not yet durable — acting on it now (before its own `Delta::Append` has committed) is
            // exactly the toxic ordering Codex HIGH-2 flagged. Treat it as absent, same as a
            // genuinely-unknown sequence: a caller's natural retry sees it once it publishes.
            return Ok(false);
        }
        let Some(before) = mem.cache.outbox.get(&sequence).cloned() else {
            return Ok(false);
        };
        if before.delivery != DeliveryState::Pending {
            return Ok(false);
        }
        let (dead_lettered, dirty) =
            record_delivery_transition(&mut mem.cache.outbox, sequence, success, error, max_attempts);
        debug_assert!(dirty, "a Pending event always transitions");

        let after = mem
            .cache
            .outbox
            .get(&sequence)
            .cloned()
            .expect("record_delivery_transition mutated this sequence in place");
        let delta = match after.delivery {
            DeliveryState::Delivered => Delta::Delivered { seq: sequence },
            DeliveryState::DeadLettered => Delta::DeadLetter { seq: sequence },
            DeliveryState::Pending => Delta::Attempt {
                seq: sequence,
                attempts: after.attempts,
                backoff_until: after
                    .leased_until
                    .expect("a still-Pending outcome always sets a backoff lease"),
                attempted_at: after
                    .last_attempt_at
                    .expect("record_delivery_transition always stamps last_attempt_at"),
                error: after.last_error.clone(),
            },
        };
        let frame = match seal_delta(&delta, &self.master_key) {
            Ok(f) => f,
            Err(e) => {
                mem.cache.outbox.insert(sequence, before);
                return Err(e);
            }
        };
        if let Err(e) = self.writer.commit(frame) {
            // The outcome never durably happened — restore the pre-transition state so a retry is
            // not silently swallowed by the "already terminal/matches" guard.
            mem.cache.outbox.insert(sequence, before);
            return Err(e);
        }
        Ok(dead_lettered)
    }

    /// Read-only peek at the next deliverable events (earliest-pending per subject), no claim, no I/O.
    /// Skips anything still `committing` (not yet durable — see [`Self::append`]'s doc): reporting it
    /// as deliverable before its own `Delta::Append` has committed would let a caller act on it ahead
    /// of its durability.
    pub fn deliverable(&self, limit: usize) -> Vec<OutboxEvent> {
        let mem = self.mem.lock();
        earliest_pending_per_subject_skipping_committing(
            &mem.cache.outbox,
            &mem.committing,
            limit,
            false,
            Utc::now(),
        )
    }

    /// Record averin's grant resolution for `token_id` durably (plan 088 D3 — see [`Delta::GrantResolved`]).
    pub fn resolve_grant(
        &self,
        token_id: &str,
        grant_id: &str,
        capability: &str,
    ) -> Result<(), StorageError> {
        let mut mem = self.mem.lock();
        let delta = Delta::GrantResolved {
            token_id: token_id.to_string(),
            grant_id: grant_id.to_string(),
            capability: capability.to_string(),
        };
        let frame = seal_delta(&delta, &self.master_key)?;
        self.writer.commit(frame)?;
        mem.resolved_grants.insert(
            token_id.to_string(),
            ResolvedGrant {
                grant_id: grant_id.to_string(),
                capability: capability.to_string(),
            },
        );
        Ok(())
    }

    /// The `(grant_id, capability)` averin resolved for `token_id`, if its grant has delivered.
    pub fn resolved_grant(&self, token_id: &str) -> Option<(String, String)> {
        let mem = self.mem.lock();
        mem.resolved_grants
            .get(token_id)
            .map(|g| (g.grant_id.clone(), g.capability.clone()))
    }

    /// Compact the journal (D0: "the ONLY O(n) operation in this module, off the append hot path"):
    /// serialize the ENTIRE live map into one fresh snapshot segment, fsync it, atomically switch to
    /// it as the new replay base, then delete every segment it supersedes.
    ///
    /// **Cutover safety**: holds the in-memory lock for the WHOLE call, so no `append`'s durable-commit
    /// insert (which also needs this lock — see [`Self::finish_append`]) can race the snapshot capture
    /// — any event visible in the snapshot is exactly "every append whose in-memory mutation
    /// happened-before this call started".
    /// Before capturing the snapshot it asks the writer to [`Writer::roll`]: because the writer
    /// processes every job in the STRICT order it was enqueued, this guarantees every durable commit
    /// enqueued before this call acquired the lock has already landed in a segment at or below the
    /// returned index — the fresh segment the roll creates only ever receives commits enqueued AFTER
    /// (harmless if such a commit's event is ALSO in the snapshot: re-applying an `Append` for an
    /// already-present sequence is idempotent). Deletion happens only after the new snapshot is
    /// itself durable, so a crash mid-compaction leaves either the OLD generation intact or the NEW
    /// snapshot intact — never neither (mirrors the plan's proven generation-rekey discipline, D8).
    ///
    /// **Committing-set wait (Codex re-review #2/#3)**: before doing anything else, waits for
    /// `mem.committing` to fully drain (see [`Self::append`]'s doc for the incident and
    /// [`Self::committing_cv`]'s doc for the deadlock-freedom argument). Without this, a durably
    /// committed-but-still-`committing` event could be absent from the snapshot captured below while
    /// its ONLY durable copy (the segment holding its `Delta::Append`) gets deleted a few lines later
    /// — a silent loss on the next crash, since `committing`-ness has nothing to do with which segment
    /// a commit physically landed in, only with whether `mem.cache.outbox`'s in-memory reflection of
    /// it is confirmed-durable yet.
    ///
    /// **Bounded wait (Codex R3 MEDIUM-4)**: the wait above is capped at
    /// [`COMMITTING_DRAIN_TIMEOUT`] — a commit stuck in unbounded file I/O must never wedge this call
    /// forever, since the periodic GC tick awaits it synchronously. If `committing` hasn't drained by
    /// the deadline, this pass is skipped entirely (nothing compacted) rather than blocking; the next
    /// tick retries. Compaction is best-effort GC, so skipping a pass is safe — but the skip is logged
    /// at `warn` (Codex 4th-pass M4: sustained overlapping appends can keep `committing` non-empty
    /// across every tick, so a silent skip would let journal segments grow unalerted) rather than
    /// silently returning `Ok(())` indistinguishable from "nothing to do".
    pub fn compact(&self) -> Result<(), StorageError> {
        let mut mem = self.mem.lock();
        let timed_out = self
            .committing_cv
            .wait_while_for(
                &mut mem,
                |m| !m.committing.is_empty(),
                COMMITTING_DRAIN_TIMEOUT,
            )
            .timed_out();
        if timed_out {
            warn!(
                target: "averin_seal",
                timeout_secs = COMMITTING_DRAIN_TIMEOUT.as_secs(),
                "averin queue compaction skipped this tick: appends are continuously in-flight \
                 (the committing set did not drain within the timeout), so the snapshot/segment \
                 reclaim is deferred to a later tick; the journal may grow until append traffic \
                 quiesces"
            );
            return Ok(());
        }
        let new_index = self.writer.roll()?;
        let snapshot_index = new_index - 1;
        let snapshot = QueueSnapshot {
            cache: mem.cache.clone(),
            resolved_grants: mem.resolved_grants.clone(),
        };
        drop(mem); // the slow encrypt+write below doesn't need the cache lock any further
        write_snapshot(&self.dir, snapshot_index, &self.master_key, &snapshot)?;
        // The snapshot at `snapshot_index` supersedes EVERYTHING at or below it: the rolled-off delta
        // segment now sitting at `snapshot_index` (its records are all in the snapshot) and any older
        // segment/snapshot. Delete them all — but never the snapshot we just made durable, and never
        // the fresh delta at `new_index (> snapshot_index)` that is now taking live appends. Runs only
        // AFTER the new snapshot is durable, so a crash here leaves the new snapshot intact (reopen
        // rebuilds from it) — never a state with neither generation present.
        for (index, path, is_snapshot) in list_segments(&self.dir)? {
            if is_snapshot && index == snapshot_index {
                continue; // the snapshot just written — the new replay base
            }
            if index <= snapshot_index {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(())
    }

    /// The bounded-growth alarm carried over from `OutboxStore::gc` (D0): the count of events retained
    /// past `retention_secs` solely because they are undelivered. A persistently non-zero count means
    /// delivery is stalled and the journal (and its replay time) is growing — alertable, mirroring the
    /// existing stopgap's contract. Read-only; does not mutate or prune anything (pruning/GC is D4's
    /// dead-letter-quarantine-aware follow-on, not this Step).
    pub fn stuck_undelivered_count(&self, retention_secs: u64) -> usize {
        let secs = i64::try_from(retention_secs).unwrap_or(i64::MAX);
        let Some(cutoff) =
            chrono::Duration::try_seconds(secs).and_then(|d| Utc::now().checked_sub_signed(d))
        else {
            return 0;
        };
        let mem = self.mem.lock();
        mem.cache
            .outbox
            .values()
            .filter(|e| e.created_at < cutoff && e.delivery != DeliveryState::Delivered)
            .count()
    }

    /// GC: prune the durable CONTIGUOUS DELIVERED PREFIX from the live map (Codex HIGH-3 on plan 088 —
    /// nothing previously pruned a successfully-`Delivered` record; only a dead-lettered-then-
    /// reclaimed one ever left the map via [`Self::reclaim_dead_letter`], so every successful use's
    /// raw `params` were retained on disk, and re-replayed, forever). Mirrors `OutboxStore::gc`'s own
    /// prefix-prune semantics (`outbox_store.rs::gc`): walking the map in sequence order, the prefix
    /// stops at the first record that is NOT terminal-`Delivered` (a still-`Pending`/leased record, or
    /// a `DeadLettered` record whose [`Self::reclaim_dead_letter`] hasn't happened yet, both correctly
    /// block it — only a genuinely-terminal `Delivered` record is eligible) OR that is younger than
    /// `retention_secs` (by `created_at`, the same age basis `OutboxStore::gc` uses — this is the
    /// retention window so a just-delivered record isn't pruned instantly). The whole eligible run is
    /// dropped with ONE `Delta::Prune { upto_seq }` (which [`apply_delta`] already knows how to apply
    /// on replay). Returns the number of records pruned (`0` — no commit issued — if the prefix is
    /// empty). Holds the in-memory lock for the full call, same as [`Self::record_delivery`]/
    /// [`Self::reclaim_dead_letter`] — acceptable because this runs on the periodic GC tick, never the
    /// append hot path.
    pub fn prune_delivered_prefix(&self, retention_secs: u64) -> Result<usize, StorageError> {
        let secs = i64::try_from(retention_secs).unwrap_or(i64::MAX);
        let Some(cutoff) =
            chrono::Duration::try_seconds(secs).and_then(|d| Utc::now().checked_sub_signed(d))
        else {
            return Ok(0);
        };
        let mut mem = self.mem.lock();
        // Same committing-set wait as `Self::compact` (Codex re-review #2/#3 — see `Self::append`'s
        // doc for the full incident): without it, a lower-numbered committing-but-invisible-to-this-
        // scan sequence sitting behind an already-`Delivered` higher one would let `upto_seq` below be
        // computed past it, and the resulting `Delta::Prune` would, on replay, apply AFTER that lower
        // sequence's own `Append` — deleting a genuinely still-`Pending` record that was never
        // eligible for pruning.
        //
        // Bounded, same as `Self::compact` (Codex R3 MEDIUM-4): skip this pass (prune nothing) rather
        // than block forever if `committing` hasn't drained within `COMMITTING_DRAIN_TIMEOUT` — the
        // next GC tick retries. The skip is logged at `warn` (Codex 4th-pass M4), not silent — see
        // `Self::compact`'s doc for why a silent skip here is unsafe under sustained append traffic.
        let timed_out = self
            .committing_cv
            .wait_while_for(
                &mut mem,
                |m| !m.committing.is_empty(),
                COMMITTING_DRAIN_TIMEOUT,
            )
            .timed_out();
        if timed_out {
            warn!(
                target: "averin_seal",
                timeout_secs = COMMITTING_DRAIN_TIMEOUT.as_secs(),
                "averin queue delivered-prefix prune skipped this tick: appends are continuously \
                 in-flight (the committing set did not drain within the timeout), so delivered \
                 records' raw params are retained past the window until append traffic quiesces"
            );
            return Ok(0);
        }
        let upto_seq = mem
            .cache
            .outbox
            .iter()
            .take_while(|(_, e)| e.created_at < cutoff && e.delivery == DeliveryState::Delivered)
            .map(|(seq, _)| *seq)
            .last();
        let Some(upto_seq) = upto_seq else {
            return Ok(0);
        };
        let delta = Delta::Prune { upto_seq };
        let frame = seal_delta(&delta, &self.master_key)?;
        self.writer.commit(frame)?;
        let before = mem.cache.outbox.len();
        mem.cache.outbox.retain(|seq, _| *seq > upto_seq);
        Ok(before - mem.cache.outbox.len())
    }

    /// Look up a specific sequence's CURRENT record — a production analogue of the test-only
    /// [`Self::all_events`]. Plan 088 Step 3b's delivery worker uses this to read back the
    /// authoritative state [`Self::record_delivery`] just durably committed (its final `attempts`/
    /// `last_error`/terminal `delivery`) before moving a dead-lettered record into quarantine,
    /// rather than re-deriving `record_delivery_transition`'s arithmetic in the caller.
    pub fn get(&self, sequence: u64) -> Option<OutboxEvent> {
        let mem = self.mem.lock();
        mem.cache.outbox.get(&sequence).cloned()
    }

    /// D4's completeness fix (plan 088 Step 6a) — the true "MOVE": durably drop `sequence` from the
    /// live map now that it has been copied into the quarantine store. The caller (the averin worker's
    /// dead-letter path, `deliver_averin_outbox_once`) MUST call this ONLY after
    /// `AverinDeadLetterStore::quarantine` has already returned `Ok` for this exact record — never
    /// before, and never on a quarantine failure (the record then stays `DeadLettered` here, retried
    /// next pass, so the audit copy is never silently lost with nothing durable anywhere). A no-op
    /// (`Ok(())`, no commit) if `sequence` is absent or not (no longer) `DeadLettered` — defensive
    /// against a duplicate/late call (e.g. the worker retrying after it crashed between the quarantine
    /// write and this call: quarantine's own `quarantine()` upsert is idempotent, and calling this
    /// twice for an already-reclaimed sequence is harmless).
    ///
    /// Deliberately a SINGLE-sequence removal ([`Delta::Reclaimed`]), not [`Self::compact`]'s
    /// contiguous-prefix `Prune`: a mid-queue dead-letter must become reclaimable independent of
    /// whatever lower-numbered, still-genuinely-`Pending` events for OTHER subjects remain — exactly
    /// the "one subject's dead-letter must not freeze GC of later subjects" bug D4 exists to fix. Once
    /// removed here, the record is gone from every future snapshot ([`Self::compact`]) too — its raw
    /// `params` no longer exist in this store at all, only in the quarantine (which redacts them
    /// independently on its own retention window).
    pub fn reclaim_dead_letter(&self, sequence: u64) -> Result<(), StorageError> {
        let mut mem = self.mem.lock();
        match mem.cache.outbox.get(&sequence) {
            Some(e) if e.delivery == DeliveryState::DeadLettered => {}
            _ => return Ok(()),
        }
        let delta = Delta::Reclaimed { seq: sequence };
        let frame = seal_delta(&delta, &self.master_key)?;
        self.writer.commit(frame)?;
        mem.cache.outbox.remove(&sequence);
        Ok(())
    }

    /// Whether the live map holds a `Pending` (unclaimed OR leased — both are the `Pending` delivery
    /// state, see the module's reused `OutboxCache`) event for `subject` — plan 088 D2's
    /// `subject_has_live_use` predicate for `PopKeyStore::evict_resolved`'s cross-store query. A
    /// `Delivered`/`DeadLettered` event never counts (terminal — the seed's continued need, if any, is
    /// the quarantine's `subject_has_replayable_dead_letter` predicate's job to answer, not this one's).
    /// Cheap: an in-memory scan under the same lock every other read-only accessor here uses (no I/O,
    /// so — unlike [`Self::compact`]/[`Self::claim`]/[`Self::record_delivery`] — this never needs the
    /// worker's `run_averin_queue_blocking` blocking-thread dance).
    pub fn has_pending_for_subject(&self, subject: &str) -> bool {
        let mem = self.mem.lock();
        mem.cache
            .outbox
            .values()
            .any(|e| e.subject == subject && e.delivery == DeliveryState::Pending)
    }

    /// Every currently `DeadLettered` event still sitting in the live map — i.e. one whose D4
    /// quarantine-move and/or [`Self::reclaim_dead_letter`] has not (yet) succeeded. A terminal
    /// `DeadLettered` record is never re-claimed by [`Self::claim`] (only `Pending` events are), so
    /// this is the ONLY way a periodic GC tick can find a record whose dead-letter transition
    /// happened but whose move to quarantine didn't complete in the same worker pass (a transient
    /// quarantine-store I/O error, or a crash between the two writes) — the retry-sweep this method
    /// backs (plan 088 Step 6a). Cheap in-memory scan; expected to normally be empty or near-empty.
    pub fn dead_lettered_events(&self) -> Vec<OutboxEvent> {
        let mem = self.mem.lock();
        mem.cache
            .outbox
            .values()
            .filter(|e| e.delivery == DeliveryState::DeadLettered)
            .cloned()
            .collect()
    }

    /// EVERY event in the live map regardless of delivery/subject state (test-only introspection).
    /// [`Self::deliverable`] deliberately returns only ONE (the earliest-pending) event per subject —
    /// exactly right for the delivery worker, wrong for asserting "how many records actually survived
    /// replay" in a test that reuses one subject for several events.
    #[cfg(test)]
    fn all_events(&self) -> Vec<OutboxEvent> {
        let mem = self.mem.lock();
        mem.cache.outbox.values().cloned().collect()
    }

    /// The path of the segment currently receiving new appends (test-only introspection: used to
    /// exercise the torn-trailing-record crash-recovery contract by truncating it mid-record).
    #[cfg(test)]
    fn current_segment_path(&self) -> PathBuf {
        // Ask the writer to roll first is NOT needed here: appends always target whatever segment the
        // writer currently holds open, and tests call this right after their own appends have already
        // been confirmed committed (so the writer is idle and its `segment` field is stable) — but the
        // writer's segment isn't exposed directly, so instead derive it from the highest-indexed
        // `.delta` file on disk, which is always the currently-active one (Step 1 never continues
        // appending into an old segment after a roll or a reopen).
        list_segments(&self.dir)
            .unwrap()
            .into_iter()
            .rfind(|(_, _, is_snapshot)| !is_snapshot)
            .map(|(_, path, _)| path)
            .expect("at least one delta segment always exists after open()")
    }

    // ---- offline vault re-key (FileStorage::rekey delegates the queue half here; plan 088 D8) ----

    /// D8: prepare the queue's half of an offline vault re-key. Captures the FULL current live state
    /// (the reused `OutboxCache` map + the `resolved_grants` side map) under the in-memory lock —
    /// the SAME snapshot-capture discipline [`Self::compact`] uses — and re-encrypts it as ONE fresh
    /// snapshot, written to a `.rekey.tmp` path and fsynced, but NOT YET renamed into the live segment
    /// sequence. This collapses the queue's entire history into a single new-key snapshot, which is
    /// acceptable OFFLINE (D8: "so the O(n) rewrite is acceptable" — rekey is a one-shot `vultrino
    /// rekey` run, never the `/execute` hot path). The OLD (still old-key) delta/snapshot segments are
    /// left in place on disk; [`Self::rekey_commit`] never deletes them itself. They are harmless
    /// (never read again once a HIGHER-indexed snapshot exists — [`Self::open`]'s replay always starts
    /// from the highest-indexed snapshot) and are swept by `open`'s own existing best-effort hygiene
    /// the next time this directory is opened — mirrors the spike's proven "prepare a full new
    /// generation, switch one pointer, GC the old generation after" protocol (plan 088's header,
    /// INCREMENT-3). On any error the live queue is left completely untouched (fail-closed).
    pub(super) fn rekey_prepare(&self, new_key: &MasterKey) -> Result<QueueRekeyStaged, StorageError> {
        let mem = self.mem.lock();
        let snapshot = QueueSnapshot {
            cache: mem.cache.clone(),
            resolved_grants: mem.resolved_grants.clone(),
        };
        drop(mem); // the slow encrypt+write below doesn't need the cache lock any further

        // Choose an index strictly ABOVE every existing segment (delta or snapshot) so that, once
        // committed, this new-key snapshot is the ONLY segment `open()` will use as its replay base
        // (mirrors `compact`'s "one snapshot at the highest index wins" contract) — the queue's whole
        // history collapses into it. `.rekey.tmp` (below) is not a recognized segment extension
        // (`parse_segment_name` only knows `.delta`/`.snapshot`), so a stale leftover from a PRIOR
        // interrupted rekey attempt never perturbs this computation, and a retried `rekey_prepare`
        // deterministically recomputes (and overwrites) the same tmp path.
        let existing = list_segments(&self.dir)?;
        let new_index = existing
            .iter()
            .map(|(index, _, _)| *index)
            .max()
            .map_or(0, |m| m + 1);

        let data = serde_json::to_vec(&snapshot)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt(&data, new_key)?;
        let file = SnapshotFile {
            version: SNAPSHOT_FILE_VERSION, // PRESERVED — key changes, format does not
            data: encrypted,
        };
        let content =
            serde_json::to_string(&file).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let final_path = self.dir.join(segment_name(new_index, true));
        let tmp_path = self.dir.join(format!("{:020}.rekey.tmp", new_index));
        // fsync the tmp BEFORE returning, same discipline as `write_snapshot`/`OutboxStore::rekey_prepare`:
        // the eventual rename gives crash-atomicity, only `sync_all` gives crash-DURABILITY of the bytes.
        {
            let f = create_private_file(&tmp_path)?;
            use std::io::Write;
            let mut w = std::io::BufWriter::new(f);
            w.write_all(content.as_bytes())?;
            w.flush()?;
            w.into_inner()
                .map_err(|e| StorageError::Io(e.into_error()))?
                .sync_all()?;
        }
        Ok(QueueRekeyStaged { tmp_path, final_path })
    }

    /// Commit the queue's half of an offline vault re-key (D8): atomically rename the prepared
    /// new-key snapshot from [`Self::rekey_prepare`] into place as a real segment — by construction
    /// the highest-indexed one, so it becomes the ONLY segment a fresh [`Self::open`] replays from —
    /// and fsync the parent directory. This is the queue's analog of `OutboxStore::rekey_commit`; see
    /// `FileStorage::rekey_blocking`'s crash-ordering doc for why this (and the other averin stores)
    /// must be committed BEFORE the vault.
    pub(super) fn rekey_commit(&self, staged: &QueueRekeyStaged) -> Result<(), StorageError> {
        std::fs::rename(&staged.tmp_path, &staged.final_path)?;
        fsync_parent_dir(&staged.final_path)?;
        Ok(())
    }
}

/// The staged (prepared-but-not-yet-committed) output of [`AverinQueue::rekey_prepare`]: the new-key
/// snapshot's tmp path (already written + fsynced) and the real segment path [`AverinQueue::rekey_commit`]
/// will atomically rename it to.
pub(super) struct QueueRekeyStaged {
    tmp_path: PathBuf,
    final_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet as StdHashSet;

    fn queue(dir: &Path) -> AverinQueue {
        let key = Arc::new(MasterKey::from_bytes(vec![11u8; 32]).unwrap());
        AverinQueue::open(dir.to_path_buf(), key).unwrap()
    }

    fn reopen(dir: &Path) -> AverinQueue {
        let key = Arc::new(MasterKey::from_bytes(vec![11u8; 32]).unwrap());
        AverinQueue::open(dir.to_path_buf(), key).unwrap()
    }

    #[test]
    fn append_replay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        let s1 = q.append("tok-a", "averin.use", serde_json::json!({"n": 1})).unwrap();
        let s2 = q.append("tok-b", "averin.use", serde_json::json!({"n": 2})).unwrap();
        let s3 = q.append("tok-a", "averin.use", serde_json::json!({"n": 3})).unwrap();
        assert_eq!((s1, s2, s3), (1, 2, 3));
        drop(q);

        let q2 = reopen(dir.path());
        let all: Vec<u64> = q2.deliverable(100).iter().map(|e| e.sequence).collect();
        // per-subject ordering: tok-a's 2nd event (seq 3) is withheld behind seq 1.
        let mut seen: StdHashSet<u64> = StdHashSet::new();
        seen.extend(&all);
        assert_eq!(seen, StdHashSet::from([1, 2]));

        // A new append after reopen continues monotonically, no seq reuse.
        let s4 = q2.append("tok-c", "averin.use", serde_json::json!({})).unwrap();
        assert_eq!(s4, 4);
    }

    #[test]
    fn torn_trailing_record_is_discarded_prior_records_survive() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        for i in 0..5u32 {
            q.append("subj", "t", serde_json::json!({"n": i})).unwrap();
        }
        let segment_path = q.current_segment_path();
        drop(q); // close the writer thread + file handles before truncating on disk

        let full = std::fs::read(&segment_path).unwrap();
        assert!(!full.is_empty(), "segment should have 5 records");
        // Truncate into the middle of the LAST frame (simulate a crash mid-write): cut roughly half
        // of the trailing record's bytes off the end.
        let cut_len = full.len() - (full.len() / 10).max(1);
        std::fs::write(&segment_path, &full[..cut_len]).unwrap();

        let q2 = reopen(dir.path());
        let recovered = q2.all_events();
        assert_eq!(
            recovered.len(),
            4,
            "the torn 5th record is discarded; the first 4 survive"
        );
        let seqs: StdHashSet<u64> = recovered.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, StdHashSet::from([1, 2, 3, 4]));

        // A torn record never reached `apply_delta` during replay, so `outbox_seq` never advanced
        // past 4 in this FRESH process — the next append correctly reuses 5 (no gap here: the
        // original process's in-memory sequence bump was itself never durable, so replay simply never
        // saw it happen; the "burned sequence, never reused" case is the OTHER scenario this module
        // documents — a LIVE process's own `append()` call getting a real I/O error back and NOT
        // rolling back `outbox_seq`, see `AverinQueue::append`'s doc).
        let next = q2.append("subj2", "t", serde_json::json!({})).unwrap();
        assert_eq!(next, 5);
    }

    #[test]
    fn kill_then_reopen_rebuilds_the_identical_map() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        let a = q.append("A", "t", serde_json::json!({"x": 1})).unwrap();
        let b = q.append("B", "t", serde_json::json!({"x": 2})).unwrap();
        let _c = q.append("A", "t", serde_json::json!({"x": 3})).unwrap(); // withheld behind `a`
        let claimed = q.claim(10, 60).unwrap();
        assert_eq!(claimed.len(), 2, "one per subject (A, B)");
        assert!(!q.record_delivery(a, true, None, 8).unwrap());
        assert!(!q.record_delivery(b, false, Some("boom".into()), 8).unwrap());
        drop(q); // simulate a process kill (no explicit close/flush call exists — every commit already
                 // fsynced before returning, so a bare `drop` is exactly "the process died here")

        let q2 = reopen(dir.path());
        // `a` delivered -> subject A's head advances to its withheld 2nd event (seq 3). `b` failed
        // once (still `Pending`, just backed off) -> `deliverable` (a read-only peek, matching
        // `OutboxStore::deliverable`'s own `respect_lease = false`) still reports it: a lease governs
        // *claim*, not this peek. So both subjects show up, each at the event the crashed process's
        // last durable state implies.
        let deliverable = q2.deliverable(10);
        assert_eq!(deliverable.len(), 2, "A's 2nd event + B's still-pending (backed off) event");
        let by_subject: std::collections::HashMap<&str, u64> = deliverable
            .iter()
            .map(|e| (e.subject.as_str(), e.sequence))
            .collect();
        assert_eq!(by_subject.get("A"), Some(&3), "A's head advanced past the delivered seq 1");
        assert_eq!(by_subject.get("B"), Some(&2), "B's failed attempt is still Pending, just leased");

        // The recovered map matches exactly what was committed before the kill: 3 events total, `a`
        // durably Delivered, `b` durably recorded as one failed attempt (Pending, backoff lease set).
        let all = q2.all_events();
        assert_eq!(all.len(), 3);
        let a_ev = all.iter().find(|e| e.sequence == a).unwrap();
        assert_eq!(a_ev.delivery, DeliveryState::Delivered);
        let b_ev = all.iter().find(|e| e.sequence == b).unwrap();
        assert_eq!(b_ev.delivery, DeliveryState::Pending);
        assert_eq!(b_ev.attempts, 1);
        assert!(b_ev.leased_until.is_some(), "the backoff lease survived the kill+reopen");
    }

    #[test]
    fn on_disk_bytes_are_ciphertext_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        let marker = "PLAINTEXT_MARKER_averin_7f2a";
        q.append("subj", "t", serde_json::json!({"secretish": marker}))
            .unwrap();
        let segment_path = q.current_segment_path();
        let raw = std::fs::read(&segment_path).unwrap();
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "event payload leaked in plaintext on disk"
        );
        // ...but decrypting it back (via a normal reopen) recovers the event.
        drop(q);
        let q2 = reopen(dir.path());
        let got = q2.deliverable(10);
        assert_eq!(got[0].payload["secretish"], marker);
    }

    #[test]
    fn compact_supersedes_delta_segments_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        for i in 0..20u32 {
            q.append("subj", "t", serde_json::json!({"n": i})).unwrap();
        }
        q.resolve_grant("tok-1", "grant-1", "cap-1").unwrap();
        q.compact().unwrap();

        // Only a snapshot (+ possibly a fresh empty delta segment) remains; no stale delta segments
        // from before compaction linger.
        let remaining = list_segments(dir.path()).unwrap();
        assert!(
            remaining.iter().any(|(_, _, is_snap)| *is_snap),
            "a snapshot segment must exist after compaction"
        );

        drop(q);
        let q2 = reopen(dir.path());
        assert_eq!(q2.all_events().len(), 20, "all 20 events survive compaction");
        assert_eq!(
            q2.resolved_grant("tok-1"),
            Some(("grant-1".to_string(), "cap-1".to_string()))
        );

        // Appends after compaction continue monotonically and are themselves durable/replayable.
        let next = q2.append("subj2", "t", serde_json::json!({})).unwrap();
        assert_eq!(next, 21);
        drop(q2);
        let q3 = reopen(dir.path());
        assert_eq!(q3.all_events().len(), 21);
    }

    #[test]
    fn segment_rolls_at_the_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        // A payload chosen so a modest number of records crosses SEGMENT_ROLL_BYTES quickly for a
        // fast test, without hardcoding the cap's exact value here.
        let big = "x".repeat(4096);
        let mut n = 0u32;
        while list_segments(dir.path())
            .unwrap()
            .iter()
            .filter(|(_, _, is_snap)| !is_snap)
            .count()
            < 2
        {
            q.append("subj", "t", serde_json::json!({"pad": big, "n": n}))
                .unwrap();
            n += 1;
            assert!(n < 10_000, "should have rolled well before this many records");
        }
        drop(q);
        let q2 = reopen(dir.path());
        assert_eq!(q2.all_events().len(), n as usize);
    }

    #[test]
    #[ignore] // run explicitly: cargo test --release averin_enqueue_bench -- --ignored --nocapture
    fn averin_enqueue_bench() {
        // Growing-backlog benchmark (Step 1's go/no-go primitive gate, plan 088 D0). The contract
        // under test is O(1): a single durable append's latency must NOT grow with how many records
        // are already retained (nothing drains, so the live map grows 10 -> 1k -> 10k -> 100k). We
        // measure the primitive HONESTLY = one producer, one append at a time, timing each individual
        // append at each backlog depth (the exact thing the plan's spike measured: "durable single-
        // append latency is FLAT across backlog"). We fill to each depth CONCURRENTLY (fast: group-
        // commit amortizes the fsync so 100k lands in seconds instead of the ~400s a solo fill of
        // 100k * ~4ms fsyncs would take), but the LATENCY SAMPLE at each depth is strictly solo — so
        // it reflects the append cost, not queuing behind other producers under saturation.
        use std::sync::atomic::AtomicU64;
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![42u8; 32]).unwrap());
        let q = Arc::new(AverinQueue::open(dir.path().join("queue"), key).unwrap());

        const FILL_THREADS: usize = 16;
        const SOLO_SAMPLE: usize = 300; // solo appends timed at each checkpoint

        // Concurrent fill (fast, group-commit amortized), no latency collected — just get the live
        // map to `count` more retained records as quickly as this machine can fsync-batch them.
        fn fill(q: &Arc<AverinQueue>, count: usize, counter_start: u64) {
            if count == 0 {
                return;
            }
            let next = Arc::new(AtomicU64::new(counter_start));
            let end = counter_start + count as u64;
            std::thread::scope(|scope| {
                for t in 0..FILL_THREADS {
                    let q = Arc::clone(q);
                    let next = Arc::clone(&next);
                    scope.spawn(move || loop {
                        let n = next.fetch_add(1, Ordering::Relaxed);
                        if n >= end {
                            break;
                        }
                        q.append("bench", "t", serde_json::json!({"n": n, "t": t}))
                            .unwrap();
                    });
                }
            });
        }

        // Solo latency sample: one thread, one append at a time — this isolates the O(1) primitive.
        fn solo_sample(q: &Arc<AverinQueue>, count: usize, counter_start: u64) -> Vec<Duration> {
            let mut lat = Vec::with_capacity(count);
            for i in 0..count {
                let t0 = Instant::now();
                q.append("bench", "t", serde_json::json!({"solo": counter_start + i as u64}))
                    .unwrap();
                lat.push(t0.elapsed());
            }
            lat
        }

        fn pct(sorted: &[Duration], q: f64) -> Duration {
            let idx = ((sorted.len() as f64) * q) as usize;
            sorted[idx.min(sorted.len() - 1)]
        }

        let checkpoints = [10usize, 1_000, 10_000, 100_000];
        let mut appended = 0u64;
        let mut results: Vec<(usize, Duration, Duration)> = Vec::new();

        for &target in &checkpoints {
            let target_u64 = target as u64;
            if appended < target_u64 {
                fill(&q, (target_u64 - appended) as usize, appended);
                appended = target_u64;
            }
            let mut latencies = solo_sample(&q, SOLO_SAMPLE, appended);
            appended += SOLO_SAMPLE as u64;
            latencies.sort();
            let p50 = pct(&latencies, 0.50);
            let p99 = pct(&latencies, 0.99);
            println!(
                "backlog={:>7} retained  solo append  p50={:>9.3?}  p99={:>9.3?}  ({} samples)",
                target,
                p50,
                p99,
                latencies.len()
            );
            results.push((target, p50, p99));
        }

        // Supporting evidence for WHY group-commit is the taken fallback: a concurrent burst's
        // amortized per-record cost. Nothing asserted here — informational throughput only.
        let burst = 20_000usize;
        let t0 = Instant::now();
        fill(&q, burst, appended);
        let elapsed = t0.elapsed();
        let per_record_us = elapsed.as_micros() as f64 / burst as f64;
        println!(
            "\ngroup-commit throughput sidebar: {burst} concurrent appends ({FILL_THREADS} threads) \
             in {:?} = {:.1} us/record ({:.0} rec/s amortized) — one fsync serves many records, \
             which is why the durable group-commit fallback (D0 ladder tier 1) was taken here",
            elapsed,
            per_record_us,
            1_000_000.0 / per_record_us
        );

        let base_p99 = results[0].2;
        println!(
            "\nO(1) contract check: solo-append p99 at each backlog depth vs. the 10-record baseline \
             ({:?}):",
            base_p99
        );
        let mut worst_ratio = 1.0f64;
        for (depth, _p50, p99) in &results {
            let ratio = p99.as_secs_f64() / base_p99.as_secs_f64().max(1e-9);
            worst_ratio = worst_ratio.max(ratio);
            println!("  depth {depth:>7}: p99={:?}  ratio={:.2}x", p99, ratio);
        }
        let worst_p99 = results.iter().map(|(_, _, p99)| *p99).max().unwrap();
        println!(
            "\noverall worst solo-append p99 = {:?} across all depths. The REPRODUCIBLE result is the \
             FLAT ratio above (O(1) — append cost does not grow with backlog). The ABSOLUTE p99 is \
             machine-load-dependent (~5-6ms idle = the raw APFS fsync floor, up to ~10-35ms while the \
             box is busy, because a solo append also pays a cross-thread writer wakeup). The plan's \
             p99 <= 5ms is a Linux-NVMe SLO (sub-ms fdatasync), a deployment-target property, not a \
             dev-Mac guarantee — see the module doc.",
            worst_p99
        );
        // The O(1) CONTRACT is flatness: a solo append's cost must not grow with retained-record
        // count. A real O(n) regression (e.g. reusing `OutboxStore`'s whole-file rewrite) would show
        // orders-of-magnitude growth from 10 to 100k; fsync jitter shows as sub-2x noise. The plan's
        // illustrative "+/-20%" is an ideal-conditions figure — this gate uses a 2x ceiling so it
        // catches a genuine linear regression without flaking on shared-machine fsync jitter.
        assert!(
            worst_ratio < 2.0,
            "solo-append p99 grew {worst_ratio:.2}x from the 10-record baseline to the worst later \
             checkpoint — that is the O(n)-per-append regression this benchmark exists to catch"
        );
    }

    #[test]
    fn a_second_open_reports_busy_and_reopen_succeeds_after_the_owner_drops() {
        let dir = tempfile::tempdir().unwrap();
        let key = || Arc::new(MasterKey::from_bytes(vec![21u8; 32]).unwrap());

        // First open takes exclusive process ownership.
        let q1 = AverinQueue::open(dir.path().to_path_buf(), key()).unwrap();
        q1.append("s", "averin.use", serde_json::json!({"n": 1})).unwrap();

        // A SECOND live open on the SAME directory must fail-closed with AverinQueueBusy — never hang,
        // never corrupt (Option A: single-writer-PROCESS ownership). `flock` mutually excludes even
        // across two fds within one process, so this holds in-process too.
        match AverinQueue::open(dir.path().to_path_buf(), key()) {
            Err(StorageError::AverinQueueBusy(_)) => {}
            Err(e) => panic!("expected AverinQueueBusy while the owner is held, got a different error: {e:?}"),
            Ok(_) => panic!("expected AverinQueueBusy while the owner is held, but a second open SUCCEEDED"),
        }

        // Once the owner drops (releasing the flock), a fresh open on the same dir succeeds AND sees the
        // durably-appended record — ownership is transferable, only never SHARED.
        drop(q1);
        let q2 = AverinQueue::open(dir.path().to_path_buf(), key()).unwrap();
        assert_eq!(q2.all_events().len(), 1, "the reopened owner replays the prior record");
        drop(q2);
    }

    // ---- D4 completeness (plan 088 Step 6a): the true "MOVE" ----

    #[test]
    fn reclaim_dead_letter_removes_a_deadlettered_record_and_its_params_from_the_live_map() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        let seq = q
            .append("tok-a", "averin.use", serde_json::json!({"params": "SECRET_PARAMS"}))
            .unwrap();
        q.claim(10, 60).unwrap();
        // max_attempts=1: the first failed attempt dead-letters immediately.
        let dead_lettered = q.record_delivery(seq, false, Some("boom".into()), 1).unwrap();
        assert!(dead_lettered, "the single allowed attempt must dead-letter");
        assert_eq!(q.get(seq).unwrap().delivery, DeliveryState::DeadLettered);

        // Reclaim (simulating the worker's post-quarantine-success MOVE): the record — and its raw
        // params — are GONE from the live map entirely, not merely re-tagged.
        q.reclaim_dead_letter(seq).unwrap();
        assert!(q.get(seq).is_none(), "the dead-lettered record must leave the live map");
        assert!(
            q.all_events().is_empty(),
            "no trace of the record (or its params) survives in the live map"
        );

        // The removal is itself durable: a reopen must NOT resurrect the reclaimed record.
        drop(q);
        let q2 = reopen(dir.path());
        assert!(
            q2.all_events().is_empty(),
            "the reclaim must survive a crash/reopen, not just live in memory"
        );
    }

    #[test]
    fn reclaim_dead_letter_survives_compaction_the_record_never_reappears_in_a_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        let a = q.append("A", "averin.use", serde_json::json!({"params": "p"})).unwrap();
        let b = q.append("B", "averin.use", serde_json::json!({"params": "p"})).unwrap();
        q.claim(10, 60).unwrap();
        assert!(q.record_delivery(a, false, Some("boom".into()), 1).unwrap());
        assert!(!q.record_delivery(b, true, None, 1).unwrap());
        q.reclaim_dead_letter(a).unwrap();

        // Compact (the periodic GC tick's snapshot rewrite, D0): only B survives into the snapshot —
        // A's reclaim already dropped it, so it never reappears via compaction either.
        q.compact().unwrap();
        drop(q);
        let q2 = reopen(dir.path());
        let remaining = q2.all_events();
        assert_eq!(remaining.len(), 1, "only B survives compaction: {remaining:?}");
        assert_eq!(remaining[0].sequence, b);
    }

    #[test]
    fn reclaim_dead_letter_is_a_noop_on_a_still_pending_or_delivered_or_unknown_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        let pending = q.append("A", "averin.use", serde_json::json!({})).unwrap();
        let delivered = q.append("B", "averin.use", serde_json::json!({})).unwrap();
        q.claim(10, 60).unwrap();
        assert!(!q.record_delivery(delivered, true, None, 8).unwrap());

        // Never reclaim a still-Pending or a Delivered record — reclaim is D4's dead-letter-only MOVE.
        q.reclaim_dead_letter(pending).unwrap();
        q.reclaim_dead_letter(delivered).unwrap();
        assert_eq!(q.get(pending).unwrap().delivery, DeliveryState::Pending);
        assert_eq!(q.get(delivered).unwrap().delivery, DeliveryState::Delivered);

        // An unknown sequence is a harmless no-op too (defensive against a duplicate/late call).
        q.reclaim_dead_letter(9999).unwrap();
    }

    #[test]
    fn has_pending_for_subject_reflects_only_the_pending_delivery_state() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        assert!(!q.has_pending_for_subject("A"), "unknown subject has no live use");

        let a = q.append("A", "averin.use", serde_json::json!({})).unwrap();
        assert!(q.has_pending_for_subject("A"), "a fresh Pending event is live");

        q.claim(10, 60).unwrap();
        assert!(q.record_delivery(a, false, Some("boom".into()), 1).unwrap()); // -> DeadLettered
        assert!(
            !q.has_pending_for_subject("A"),
            "a terminal DeadLettered record is not a live use (D2's predicate is Pending-only)"
        );

        let b = q.append("B", "averin.use", serde_json::json!({})).unwrap();
        q.claim(10, 60).unwrap(); // leases B — still `Pending`, just leased
        assert!(
            q.has_pending_for_subject("B"),
            "a leased-but-Pending event still counts as live (per the module's Pending model)"
        );

        assert!(!q.record_delivery(b, true, None, 8).unwrap()); // -> Delivered
        assert!(!q.has_pending_for_subject("B"), "a Delivered record is not a live use");
    }

    // ---- Codex HIGH-2 (append-ordering resurrection) ----

    #[test]
    fn a_reservation_is_not_claimable_or_deliverable_until_its_append_commits_no_resurrection() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());

        // Reserve sequence N WITHOUT yet committing its `Delta::Append` durably — this mirrors the
        // exact interleaving Codex flagged: a concurrent worker's `claim` + `record_delivery` racing
        // this call's own durability wait. `reserve_for_append` publishes the event into
        // `mem.cache.outbox` IMMEDIATELY (the committing-set fix, so `compact`/
        // `prune_delivered_prefix` always see it) but marks it `committing`.
        let (seq, event) = q.reserve_for_append("tok-a", "averin.use", serde_json::json!({"n": 1}));
        assert_eq!(seq, 1);

        // Attempt EXACTLY the toxic interleaving BEFORE the reservation's Append is durable: claim,
        // then deliver. Post-fix this must be a complete no-op in both directions — `claim`/
        // `deliverable`/`record_delivery` all treat a still-`committing` sequence as not-yet-durable,
        // proving the vulnerability's precondition (committing Lease/Delivered for a sequence whose
        // own Append hasn't committed yet) is now structurally unreachable through the public API —
        // even though `get` (an internal/introspection accessor) already sees the published event.
        assert!(
            q.deliverable(10).is_empty(),
            "an uncommitted (still-committing) reservation must not be deliverable"
        );
        let claimed = q.claim(10, 60).unwrap();
        assert!(claimed.is_empty(), "an uncommitted reservation must not be claimable");
        let delivered = q.record_delivery(seq, true, None, 8).unwrap();
        assert!(!delivered, "record_delivery on a still-committing sequence must be a no-op");
        assert_eq!(
            q.get(seq).unwrap().delivery,
            DeliveryState::Pending,
            "the reservation is published (compact/prune must see it) though not yet claimable"
        );

        // NOW let the append actually commit + publish (mirrors `finish_append`, the second half of
        // the real `append()`).
        let committed_seq = q.finish_append(seq, event).unwrap();
        assert_eq!(committed_seq, seq);

        // The sequence is now genuinely Pending, deliverable, and claimable — nothing was lost or
        // resurrected by the earlier no-op attempt.
        assert_eq!(q.get(seq).unwrap().delivery, DeliveryState::Pending);
        assert_eq!(q.deliverable(10).len(), 1);
        let claimed = q.claim(10, 60).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].sequence, seq);
        assert!(q.record_delivery(seq, true, None, 8).is_ok());
        assert_eq!(q.get(seq).unwrap().delivery, DeliveryState::Delivered);

        // Drop + reopen: replay must show the event exactly as it genuinely happened — Delivered —
        // and must NEVER regress back to Pending (the actual regression Codex HIGH-2 flagged: a
        // Lease/Delivered pair committed before their event's own Append resurrected it as fresh
        // Pending work on replay).
        drop(q);
        let q2 = reopen(dir.path());
        let ev = q2.get(seq).expect("the committed, delivered append survives replay");
        assert_eq!(
            ev.delivery,
            DeliveryState::Delivered,
            "a genuinely delivered record must never come back as Pending after replay (resurrection)"
        );
    }

    #[test]
    fn a_concurrent_claimant_never_observes_an_unpublished_reservation() {
        // A second angle on the same fix under real concurrency: reserve N on this thread, run a
        // worker that hammers claim+deliver while N is reserved-but-uncommitted (committing), and
        // STOP+JOIN that worker BEFORE publishing N — so the whole window the worker runs in is
        // exactly "N reserved, its Append not yet durable". Post-fix, `claim` treats a still-
        // `committing` sequence as unclaimable (its `assert_ne` never fires) even though the
        // committing-set fix means N IS already published into `mem.cache.outbox` (so
        // `compact`/`prune_delivered_prefix` can see it) — the two properties are independent. N only
        // becomes genuinely claimable — still Pending — after `finish_append` clears `committing`.
        let dir = tempfile::tempdir().unwrap();
        let q = Arc::new(queue(dir.path()));

        let (seq, event) = q.reserve_for_append("tok-a", "averin.use", serde_json::json!({"n": 1}));

        let q_bg = Arc::clone(&q);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        let bg = std::thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                let claimed = q_bg.claim(10, 60).unwrap();
                for e in claimed {
                    assert_ne!(e.sequence, seq, "the unpublished reservation must never be claimed");
                    let _ = q_bg.record_delivery(e.sequence, true, None, 8);
                }
                // A small yield keeps this a genuine concurrency probe without a lock-starving spin.
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });

        // Let the worker run against the not-yet-published reservation, then stop + join it BEFORE
        // publishing — the assertion window closes with the reservation still uncommitted.
        std::thread::sleep(std::time::Duration::from_millis(30));
        stop.store(true, Ordering::Relaxed);
        bg.join().unwrap();

        // The reservation was never claimed during the whole window (the background worker's own
        // `assert_ne!` above already proved that) — it's published (visible via `get`) but still
        // marked `committing` until its Append actually commits.
        assert_eq!(
            q.get(seq).unwrap().delivery,
            DeliveryState::Pending,
            "published but still committing — never claimed during the worker's whole window"
        );
        let committed_seq = q.finish_append(seq, event).unwrap();
        assert_eq!(committed_seq, seq);
        assert_eq!(q.get(seq).unwrap().delivery, DeliveryState::Pending);
    }

    // ---- Codex re-review #2/#3 (committing-set fix: durable-but-unpublished compact/prune race) ----
    //
    // The FIRST fix above (deferred insert) closed the HIGH-2 resurrection hole but opened a NEW one:
    // a window where an event is durably committed to disk but not yet reflected in `mem.cache.outbox`
    // at all. A concurrent `compact`/`prune_delivered_prefix` running in that window could snapshot/
    // prune without ever seeing the event, then delete its only durable copy — an acknowledged,
    // already-fsynced event silently lost on the next crash. See `AverinQueue::append`'s doc for the
    // full incident; these two tests reproduce the exact race the committing-set fix closes.

    #[test]
    fn compact_waits_for_an_in_flight_commit_before_snapshotting_no_lost_durable_event() {
        let dir = tempfile::tempdir().unwrap();
        let q = Arc::new(queue(dir.path()));

        // Reserve + durably commit seq A's `Delta::Append` directly (the frame is written+fsynced),
        // but do NOT yet call `publish_committed` — simulates the publish step being delayed while a
        // concurrent `compact` runs: durably on disk, still `committing`.
        let (seq, event) = q.reserve_for_append("A", "averin.use", serde_json::json!({"x": 1}));
        let frame = seal_delta(&Delta::Append(event.clone()), &q.master_key).unwrap();
        q.writer.commit(frame).unwrap();

        let q_bg = Arc::clone(&q);
        let compact_done = Arc::new(AtomicBool::new(false));
        let compact_done_bg = Arc::clone(&compact_done);
        let bg = std::thread::spawn(move || {
            q_bg.compact().unwrap();
            compact_done_bg.store(true, Ordering::SeqCst);
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !compact_done.load(Ordering::SeqCst),
            "compact must block on the committing condvar while A's Append is still committing"
        );
        // Compact is still blocked — it has not rolled, snapshotted, or deleted anything yet, so A's
        // original delta segment is fully intact and no snapshot exists. This is the direct assertion
        // that compact does NOT delete A's data while it is committing.
        let segs_while_blocked = list_segments(dir.path()).unwrap();
        assert!(
            !segs_while_blocked.iter().any(|(_, _, is_snap)| *is_snap),
            "compact must not have written (or deleted anything toward) a snapshot while A is still \
             committing"
        );

        // Let A's publish proceed exactly as `finish_append` would on commit success.
        q.publish_committed(seq);
        bg.join().unwrap();
        assert!(compact_done.load(Ordering::SeqCst));

        // The snapshot compact produced must include A: nothing is lost even though its Append had
        // already committed durably before compact observed it as safe to snapshot.
        let q = Arc::try_unwrap(q).unwrap_or_else(|_| panic!("bg thread's Arc clone should be gone"));
        drop(q);
        let q2 = reopen(dir.path());
        assert_eq!(q2.all_events().len(), 1, "A must survive compaction, not be lost");
        assert_eq!(q2.get(seq).unwrap().sequence, seq);
    }

    #[test]
    fn prune_delivered_prefix_waits_for_an_in_flight_commit_a_committing_seq_is_never_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let q = Arc::new(queue(dir.path()));

        // seq1 ("A"): reserve + durably commit its `Delta::Append` directly, but do NOT yet call
        // `publish_committed` — simulates the exact race Codex flagged: durably on disk, still
        // `committing`.
        let (seq1, event1) = q.reserve_for_append("A", "averin.use", serde_json::json!({}));
        let frame1 = seal_delta(&Delta::Append(event1.clone()), &q.master_key).unwrap();
        q.writer.commit(frame1).unwrap();

        // seq2 ("B"): a normal, fully-published, already-`Delivered` event — the scenario Codex
        // described precisely: "seq 1 is committing-but-unpublished while seq 2 is delivered".
        let seq2 = q.append("B", "averin.use", serde_json::json!({})).unwrap();
        let claimed = q.claim(10, 60).unwrap();
        assert_eq!(claimed.len(), 1, "seq1 is still committing and must not be claimed alongside seq2");
        assert_eq!(claimed[0].sequence, seq2);
        assert!(!q.record_delivery(seq2, true, None, 8).unwrap());

        // `prune_delivered_prefix` must WAIT (not prune) while seq1 is still committing — spawn it in
        // the background and confirm it has not returned yet.
        let q_bg = Arc::clone(&q);
        let done = Arc::new(AtomicBool::new(false));
        let done_bg = Arc::clone(&done);
        let bg = std::thread::spawn(move || {
            let pruned = q_bg.prune_delivered_prefix(0).unwrap();
            done_bg.store(true, Ordering::SeqCst);
            pruned
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!done.load(Ordering::SeqCst), "prune must wait while seq1 is still committing");

        // Now let seq1 actually publish (mirrors `finish_append`'s success tail).
        q.publish_committed(seq1);
        let pruned = bg.join().unwrap();

        // seq1 is now genuinely Pending (never delivered) — it correctly BLOCKS the whole prefix
        // (mirrors the existing "a still-pending record blocks the prefix" contract), so a committing
        // seq is never pruned, and nothing else is pruned out of sequence order either.
        assert_eq!(pruned, 0, "a just-published, still-Pending seq1 blocks the prefix entirely");
        assert_eq!(q.get(seq1).unwrap().delivery, DeliveryState::Pending);
        assert!(q.get(seq2).is_some(), "seq2 must not be pruned past the still-Pending seq1");

        // Durability check: replay must agree — seq1 (Pending) and seq2 (Delivered) both survive.
        let q = Arc::try_unwrap(q).unwrap_or_else(|_| panic!("bg thread's Arc clone should be gone"));
        drop(q);
        let q2 = reopen(dir.path());
        assert_eq!(q2.all_events().len(), 2);
        assert_eq!(q2.get(seq1).unwrap().delivery, DeliveryState::Pending);
        assert_eq!(q2.get(seq2).unwrap().delivery, DeliveryState::Delivered);
    }

    // ---- Codex R3 HIGH-2 (claim skipped a committing seq without blocking its subject) ----
    //
    // The `committing` set stops `claim`/`deliverable` from acting on a not-yet-durable seq, but the
    // scan just `continue`d past it — it never marked the seq's SUBJECT as blocked. So a LATER,
    // already-committed seq for the SAME subject could still be claimed while the earlier one was
    // still committing: a per-subject FIFO violation (a later bounded-reuse use reaching averin before
    // an earlier same-subject grant/use was even durable). The fix marks the whole subject `seen` the
    // moment any of its sequences is found `committing`, head-of-line-blocking every later seq for that
    // subject until the committing one drains and delivers in order.

    #[test]
    fn claim_head_of_line_blocks_a_subject_with_an_earlier_committing_seq_from_a_later_one() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());

        // N: reserved but deliberately left `committing` (never finished) — nothing durable backs it.
        let (seq_n, event_n) = q.reserve_for_append("S", "averin.use", serde_json::json!({"n": 1}));
        // N+1: same subject, reserved AND fully committed — durable and genuinely Pending.
        let seq_n1 = q.append("S", "averin.use", serde_json::json!({"n": 2})).unwrap();
        assert_eq!(seq_n1, seq_n + 1, "N+1 must immediately follow N in sequence order");

        // While N is still committing, claim() must return NOTHING for subject S — not N+1 ahead of
        // it. This is the exact interleaving Codex R3 HIGH-2 flagged.
        let claimed = q.claim(10, 60).unwrap();
        assert!(
            claimed.is_empty(),
            "S has an earlier committing seq (N); N+1 must not be claimed ahead of it, got {claimed:?}"
        );

        // Let N actually commit durably (mirrors `finish_append`'s success tail).
        assert_eq!(q.finish_append(seq_n, event_n).unwrap(), seq_n);

        // N is now durable and Pending — it, not N+1, is the earliest claimable event for S.
        let claimed = q.claim(10, 60).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].sequence, seq_n, "N claims first, in order");
        assert!(!q.record_delivery(seq_n, true, None, 8).unwrap());

        // N has delivered — S is unblocked, and N+1 is now (and only now) claimable.
        let claimed = q.claim(10, 60).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].sequence, seq_n1, "N+1 claims only after N delivers, still in order");
    }

    // ---- Codex R3 MEDIUM-4 (unbounded compact/prune wait on a stuck committing seq — liveness) ----
    //
    // `compact`/`prune_delivered_prefix` waited on `committing_cv` with NO timeout. A writer stuck in
    // unbounded file I/O (or sustained overlapping appends) could leave `committing` nonempty forever,
    // wedging both GC passes permanently — and since the periodic GC/delivery worker awaits `compact()`
    // synchronously, that stalls every later tick too. The fix bounds the wait at
    // `COMMITTING_DRAIN_TIMEOUT` and skips the pass (best-effort — retried next tick) on timeout.

    #[test]
    fn compact_and_prune_skip_their_pass_instead_of_hanging_when_committing_never_drains() {
        let dir = tempfile::tempdir().unwrap();
        let q = Arc::new(queue(dir.path()));

        // Reserve a seq and never finish/publish/abort it — `committing` never drains for the rest of
        // this test, exactly the stuck-writer scenario Codex R3 MEDIUM-4 flagged.
        let (seq, _event) = q.reserve_for_append("S", "averin.use", serde_json::json!({}));

        // Run both waiters concurrently so this test's wall-clock cost is ~one timeout, not two.
        let q1 = Arc::clone(&q);
        let compact_thread = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            q1.compact().unwrap();
            start.elapsed()
        });
        let q2 = Arc::clone(&q);
        let prune_thread = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let pruned = q2.prune_delivered_prefix(0).unwrap();
            (start.elapsed(), pruned)
        });

        // Joining is itself the "does not hang" assertion: pre-fix, both would have blocked forever.
        let compact_elapsed = compact_thread.join().unwrap();
        let (prune_elapsed, pruned) = prune_thread.join().unwrap();

        let margin = COMMITTING_DRAIN_TIMEOUT + std::time::Duration::from_secs(5);
        assert!(
            compact_elapsed < margin,
            "compact must give up within a bounded margin of COMMITTING_DRAIN_TIMEOUT, took \
             {compact_elapsed:?}"
        );
        assert!(
            prune_elapsed < margin,
            "prune_delivered_prefix must give up within a bounded margin of \
             COMMITTING_DRAIN_TIMEOUT, took {prune_elapsed:?}"
        );

        // Best-effort skip, not a partial pass: nothing pruned, and no snapshot was ever written
        // (compact bailed before touching disk) — the queue is unchanged, ready to retry next tick.
        assert_eq!(pruned, 0, "prune must skip (not prune) while committing never drains");
        let segs = list_segments(dir.path()).unwrap();
        assert!(
            !segs.iter().any(|(_, _, is_snap)| *is_snap),
            "compact must not have written a snapshot on a skipped pass"
        );

        // `seq` itself is untouched: still published (visible) but still committing/Pending — never
        // lost, never resurrected, never pruned.
        assert_eq!(q.get(seq).unwrap().delivery, DeliveryState::Pending);
    }

    // ---- Codex HIGH-3 (delivered records retained forever / unbounded growth) ----

    #[test]
    fn prune_delivered_prefix_drops_delivered_records_and_their_params_but_never_a_still_pending_one() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());

        let a = q.append("A", "averin.use", serde_json::json!({"params": "SECRET_A"})).unwrap();
        let b = q.append("B", "averin.use", serde_json::json!({"params": "SECRET_B"})).unwrap();
        let c = q.append("C", "averin.use", serde_json::json!({"params": "SECRET_C"})).unwrap(); // stays Pending

        q.claim(10, 60).unwrap();
        assert!(!q.record_delivery(a, true, None, 8).unwrap());
        assert!(!q.record_delivery(b, true, None, 8).unwrap());
        // `c` is deliberately never claimed/delivered — it must survive the prune untouched.

        // retention_secs = 0: every already-`created_at`-stamped record instantly qualifies by age,
        // isolating the test to the delivery-state gate this fix adds.
        let pruned = q.prune_delivered_prefix(0).unwrap();
        assert_eq!(pruned, 2, "both delivered records (A, B) are pruned");

        assert!(q.get(a).is_none(), "A's delivered record (and its raw params) must be gone");
        assert!(q.get(b).is_none(), "B's delivered record (and its raw params) must be gone");
        let remaining = q.get(c).expect("C, still Pending, must survive the prune");
        assert_eq!(remaining.delivery, DeliveryState::Pending);
        assert_eq!(q.all_events().len(), 1, "only the still-Pending record C remains live");

        // The prune is itself durable: a reopen must not resurrect A or B.
        drop(q);
        let q2 = reopen(dir.path());
        assert_eq!(q2.all_events().len(), 1);
        assert!(q2.get(a).is_none());
        assert!(q2.get(b).is_none());
        assert_eq!(q2.get(c).unwrap().delivery, DeliveryState::Pending);
    }

    #[test]
    fn prune_delivered_prefix_is_blocked_by_a_still_pending_record_even_if_a_later_one_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());

        // Two different subjects so both can be independently claimed in one pass, but `a` (lower
        // sequence) is left Pending while `b` (higher sequence) delivers — the prefix scan must stop
        // AT `a`, never skip over it to prune `b` out of sequence order (mirrors `OutboxStore::gc`'s
        // own prefix semantics: a blocking record freezes the WHOLE prefix from that point on).
        let a = q.append("A", "averin.use", serde_json::json!({})).unwrap();
        let b = q.append("B", "averin.use", serde_json::json!({})).unwrap();
        q.claim(10, 60).unwrap();
        assert!(!q.record_delivery(b, true, None, 8).unwrap());
        // `a` is left Pending (never delivered).

        let pruned = q.prune_delivered_prefix(0).unwrap();
        assert_eq!(pruned, 0, "the still-Pending `a` blocks the prefix even though `b` delivered");
        assert!(q.get(a).is_some());
        assert!(q.get(b).is_some(), "b survives too: the prefix never reaches past the blocker");
    }

    #[test]
    fn prune_delivered_prefix_respects_the_retention_window_a_just_delivered_record_is_not_pruned_instantly() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        let a = q.append("A", "averin.use", serde_json::json!({})).unwrap();
        q.claim(10, 60).unwrap();
        assert!(!q.record_delivery(a, true, None, 8).unwrap());

        // A large retention window (well past "just now") must NOT prune a just-delivered record.
        let pruned = q.prune_delivered_prefix(24 * 3600).unwrap();
        assert_eq!(pruned, 0, "a just-delivered record must survive within the retention window");
        assert!(q.get(a).is_some());

        // retention_secs = 0 (no window) prunes it immediately, proving the ONLY thing that withheld
        // it above was the window, not some other gate.
        let pruned = q.prune_delivered_prefix(0).unwrap();
        assert_eq!(pruned, 1);
        assert!(q.get(a).is_none());
    }

    // ---- Codex HIGH-5 (interior corruption misclassified as torn-tail) ----

    #[test]
    fn interior_frame_length_corruption_fails_closed_instead_of_being_treated_as_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        for i in 0..3u32 {
            q.append("subj", "t", serde_json::json!({"n": i})).unwrap();
        }
        let segment_path = q.current_segment_path();
        drop(q); // close the writer thread + file handle before mutating bytes on disk

        let mut bytes = std::fs::read(&segment_path).unwrap();
        // Locate the SECOND frame (an interior frame, not the last) using the real header layout, and
        // flip a bit in ITS length field — Codex HIGH-5's exact scenario: a corrupted interior length
        // that (pre-fix) could claim more bytes than remain and be silently treated as a torn tail,
        // dropping that record and every later one.
        let first_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let second_frame_start = FRAME_HEADER_LEN + first_len;
        assert!(
            second_frame_start + FRAME_HEADER_LEN <= bytes.len(),
            "need at least 2 frames for this test"
        );
        let len_field_offset = second_frame_start + 4;
        bytes[len_field_offset] ^= 0x40; // flip a bit in the second frame's claimed length

        std::fs::write(&segment_path, &bytes).unwrap();

        let key = Arc::new(MasterKey::from_bytes(vec![11u8; 32]).unwrap());
        let result = AverinQueue::open(dir.path().to_path_buf(), key);
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!(
                "a corrupted interior frame length must fail closed, never silently truncate"
            ),
        };
        assert!(
            msg.contains("CRC mismatch") || msg.contains("bad magic"),
            "expected a fail-closed frame-corruption error, got: {msg}"
        );
    }

    #[test]
    fn final_frame_payload_corruption_with_an_intact_header_fails_closed_not_torn() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        for i in 0..3u32 {
            q.append("subj", "t", serde_json::json!({"n": i})).unwrap();
        }
        let segment_path = q.current_segment_path();
        drop(q);

        let mut bytes = std::fs::read(&segment_path).unwrap();
        // Flip the very last byte of the file: it lands inside the LAST frame's sealed payload, well
        // past its 12-byte header, which stays fully intact (magic + length + length-CRC all still
        // match). Codex HIGH-5's other sub-case: a corrupted-but-complete-length last record must NOT
        // be silently discarded as a "torn tail" — it must fail closed instead.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&segment_path, &bytes).unwrap();

        let key = Arc::new(MasterKey::from_bytes(vec![11u8; 32]).unwrap());
        let result = AverinQueue::open(dir.path().to_path_buf(), key);
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!(
                "a corrupted-but-complete-length final record must fail closed, never be discarded \
                 as torn"
            ),
        };
        assert!(
            msg.contains("not a torn tail"),
            "expected a fail-closed authentication error, got: {msg}"
        );
    }

    #[test]
    fn genuinely_torn_trailing_write_with_an_intact_header_is_still_discarded_as_torn() {
        let dir = tempfile::tempdir().unwrap();
        let q = queue(dir.path());
        for i in 0..5u32 {
            q.append("subj", "t", serde_json::json!({"n": i})).unwrap();
        }
        let segment_path = q.current_segment_path();
        drop(q);

        let full = std::fs::read(&segment_path).unwrap();
        // Walk frames (using the real header layout) to find the LAST frame's start, so we can
        // truncate INSIDE its payload while leaving its 12-byte header fully intact — the genuine
        // "process died mid-write" shape the torn-tail path exists for, as distinct from the
        // interior-corruption cases above.
        let mut pos = 0usize;
        let mut last_frame_start = 0usize;
        while pos < full.len() {
            let len = u32::from_be_bytes(full[pos + 4..pos + 8].try_into().unwrap()) as usize;
            last_frame_start = pos;
            pos += FRAME_HEADER_LEN + len;
        }
        let last_len =
            u32::from_be_bytes(full[last_frame_start + 4..last_frame_start + 8].try_into().unwrap())
                as usize;
        assert!(last_len > 4, "need a payload with a few bytes to truncate mid-record");
        let cut_len = last_frame_start + FRAME_HEADER_LEN + (last_len / 2).max(1);
        assert!(cut_len < full.len(), "must actually truncate something");
        std::fs::write(&segment_path, &full[..cut_len]).unwrap();

        let q2 = reopen(dir.path());
        let recovered = q2.all_events();
        assert_eq!(recovered.len(), 4, "the torn 5th record is discarded; the first 4 survive intact");
        let seqs: StdHashSet<u64> = recovered.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, StdHashSet::from([1, 2, 3, 4]));
    }
}
