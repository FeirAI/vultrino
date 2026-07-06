# Design: move the signed outbox OUT of the encrypted vault (storage v6 → v7)

Status: **IMPLEMENTED + adversarially reviewed (2026-06-25).** D1–D4 locked and built; see
"As-built + post-review hardening" at the end for what shipped vs. this original design (the §3
SQLite plan is SUPERSEDED — D2 note). Scope: vultrino storage layer (`src/storage/file.rs`,
`src/storage/outbox_store.rs`, `src/outbox.rs`, `src/server/mod.rs`, `src/main.rs`). Companion §12 item.

> CLARIFICATION (what this does NOT do): the **credentials never leave the encrypted vault and are
> never exposed**. "Out of the vault" moves only the *signed event log* (budget/approval/lifecycle
> events — agent-safe: credential *aliases*/metadata, never secret values) into its own store, so
> appending an event stops rewriting the whole secrets file (the O(vault-size) cliff). Per D2 that
> store is **also encrypted** — nothing sits in plaintext.

## Resolved decisions (the implementation contract)
- **D1 = intent-staging.** Split the outbox into its own store; keep state↔event atomic by staging a
  bounded intent record in the vault under the same lock, draining it to the outbox store after the
  vault commit, and reconciling undrained intents on startup. (Not pure-reconcile.)
- **D2 = encrypt the outbox store** with the existing master key, fresh nonce per write — the event
  metadata never sits in plaintext. IMPLEMENTATION NOTE: realized NOT as SQLite/per-row but as a
  separate `outbox.enc` file reusing the vault's proven AES-256-GCM whole-cache serialize+encrypt +
  fd-lock + tmp+atomic-rename+fsync machinery (no new dep on the secrets plane; `OUTBOX_FILE_VERSION=1`
  envelope). "Encrypt the log" (D2's intent) is fully met; "per-row" was a recommendation, not a
  locked requirement. The §3 SQLite schema below is SUPERSEDED by this choice. Trade-off: append is
  O(retention-bounded-outbox) not O(1) — but it's fully decoupled from the (large) SECRETS vault size,
  which IS the cliff; keep retention short if append latency under a deep backlog ever matters.
- **D3 = sharded per tenant.** The outbox is partitioned by tenant (per-tenant monotonic seq +
  per-tenant cursor), which is one-outbox-per-vultrino in the per-tenant-shard deployment (P5). A
  *shared* multi-tenant vultrino would additionally need per-tenant broker cursors on the govder
  side (small cross-plane follow-on; NOT required for the sharded path).
- **D4 = automatic, no explicit command.** Since nothing is deployed (no v6 vault with an in-vault
  outbox exists in the wild), v7 is effectively *the* format; the only migration code is a
  best-effort "drain an old v6 vault's in-vault outbox on first open" for dev/test vaults. Fresh
  installs start clean at v7. A `--check` dry-run is optional, not required.

## 1. Problem — the O(vault-size) throughput cliff

The signed outbox lives **inside** the encrypted secrets vault. `StorageCache` (`src/storage/file.rs:189`)
holds, in one serialized blob, both the secrets (`credentials`, `api_keys`, `use_tokens`, `policies`,
`capabilities`, …) and the event log (`outbox: BTreeMap<u64, OutboxEvent>`, `outbox_seq`). The vault is
one file: `StorageFile { version, salt, data }` where `data = AES-256-GCM(serde_json(StorageCache))`
(`write_cache_to_disk_sync`, `src/storage/file.rs:395`).

Two hot paths pay O(vault-size) because of this coupling:

1. **Append** (`append_event`, `:1060` → `locked_mutate_blocking`, `:458`): take the exclusive
   cross-process fd-lock → **read + decrypt the entire vault** → push one event → **re-encrypt + rewrite
   the entire vault** (tmp + rename). Every emitted event rewrites every secret.
2. **Poll/read** (`list_events_after`, `:1074` → `reload`, `:506` → `reload_blocking`, `:490`): take the
   **same** exclusive fd-lock → **read + decrypt the entire vault** → replace the in-memory cache. Every
   broker poll decrypts every secret.

The outbox is the **only per-request-growing term** in the vault (secrets/policies/tokens are bounded by
tenant/capability count; the event log grows with traffic). So as traffic accrues, both append and poll
costs rise with the event backlog, and — because the fd-lock serializes the web and MCP processes
(`lock_file_exclusive`, `:444`) — the whole PEP's write/read throughput is gated by vault size. Retention
(`gc_outbox`, `:1198`, 7-day default) caps the backlog but the cap is large and GC itself rewrites the
vault.

**Goal:** the secrets vault becomes small and rarely-written (only on credential/policy/token/approval
mutations); the event log moves to an append-optimized store whose append and read cost are independent of
the secrets vault size. This subsumes the interim "read-cache `list_events_after`" win (see §8).

## 2. The hard part — cross-store atomicity

Today, a state mutation and its event are written in **one** vault rewrite, so they are atomic. Example:
deciding an approval updates `approvals[id].status` **and** appends the V9 `approval.*` event in the same
`locked_mutate` closure → one encrypt+rename. Move the outbox to a separate store and that single-file
atomicity is gone: a crash between "vault committed" and "event appended" (or vice versa) can leave the
two stores inconsistent.

The two failure orderings are NOT symmetric:

- **Event-first, then vault** → a crash can emit an event for a state change that never committed
  (a **phantom** event). Consumers (govder broker → vultrino installs / leria seals) act on something that
  didn't happen. **Unacceptable.**
- **Vault-first, then event** → a crash can commit a state change whose event was never emitted (a
  **missing** event). Consumers don't see it until a reconcile re-derives it. Recoverable.

This is the **same atomicity class** as the leria `ApplyPolicyChange` persist-then-signal residual
(documented in `leria/internal/budget/engine.go`). We adopt the same resolution: **commit the
authoritative state first, then emit; back it with a reconciler.**

### 2a. Recommended ordering + backstop

1. Allocate the monotonic sequence and stage the event **inside** the vault `locked_mutate` closure, as a
   tiny **intent** (just `{seq, event_id, subject, type, payload-hash}` — bounded, not the whole backlog),
   committed atomically with the state change.
2. After the vault write commits, write the full event to the outbox store and mark the intent drained.
3. On startup and on a periodic tick, a **drainer** replays any undrained intents into the outbox store
   (idempotent on `seq`/`event_id`). This closes the vault-first→missing-event gap deterministically.

The intent is bounded (only *undrained* events, normally zero), so the vault stays small — we are NOT
re-introducing the backlog into the vault. This is a transactional-outbox pattern with the durable log
externalized and a WAL-style intent kept in the authoritative store.

> Open decision **D1**: accept the simpler "vault-first, emit, reconcile-on-divergence" (no intent
> column; the reconciler re-derives missing events purely from vault state diffs) vs the intent-staging
> above. Intent-staging is deterministic and seq-stable; pure-reconcile is less code but must re-derive
> seq and can only recover events that are re-derivable from current state (lifecycle events that have
> since been superseded are unrecoverable). **Recommendation: intent-staging** (deterministic, matches
> the gap-free cursor contract).

## 3. The new outbox store

**Recommendation: SQLite**, consistent with the rest of the OS (leria's `SQLiteOutboxStore` and the
durable `SQLitePolicyStore` use the pure-Go modernc driver; vultrino would use `rusqlite`/`libsqlite3`
or `sqlx`). Rationale over a hand-rolled append log:

- WAL mode gives concurrent append (writer) + poll (reader) without the writer blocking readers — directly
  removes the poll-blocks-on-write coupling.
- Retention is a cheap `DELETE … WHERE created_at < cutoff` (gap-free prefix prune, as `gc_outbox` does
  today), not a full-file rewrite.
- Monotonic gap-free `seq` via an explicit sequence row (not AUTOINCREMENT, which can leave gaps on
  rollback) keeps the cursor-replay contract.
- Cross-process concurrency (web + MCP) is handled by SQLite's own locking + `busy_timeout`, replacing the
  bespoke fd-lock for the outbox (the vault keeps its fd-lock for secrets).

Schema sketch (NOT final):

```sql
CREATE TABLE outbox_events (
    seq         INTEGER PRIMARY KEY,         -- monotonic, gap-free (allocated under the vault lock at intent time)
    subject     TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    event_id    TEXT NOT NULL UNIQUE,        -- idempotency / de-dupe on drain
    payload     BLOB NOT NULL,               -- see D2 (encrypted or plaintext)
    created_at  TEXT NOT NULL,               -- RFC3339Nano; retention prune key
    delivery    TEXT NOT NULL,               -- Pending|Leased|Delivered|DeadLetter
    attempts    INTEGER NOT NULL DEFAULT 0,
    leased_until TEXT, last_attempt_at TEXT, last_error TEXT DEFAULT ''
);
CREATE INDEX idx_outbox_created  ON outbox_events (created_at);     -- retention
CREATE INDEX idx_outbox_delivery ON outbox_events (subject, seq);  -- per-subject ordering + claim
```

> Open decision **D2 — outbox-at-rest encryption.** The code comments call outbox payloads "agent-safe"
> (no raw secrets), but they DO carry metadata: credential *aliases*, action names, approver identity,
> approval summaries (`approval_event_payload`, `src/storage/file.rs:131`). Options:
> - **(a) App-level AES-256-GCM per row** with the existing `master_key` (defense-in-depth, matches the
>   vault's posture; the per-row nonce + encrypt is cheap and append-friendly). **Recommended.**
> - **(b) SQLCipher** (whole-DB encryption) — simplest mental model, adds a C dep + key handling.
> - **(c) Plaintext, rely on the encrypted PVC** — fastest, but drops vultrino's app-level at-rest
>   guarantee for approval metadata. Not recommended for the secrets plane.
> Recommendation: **(a)**.

> Open decision **D3 — one store or per-subject sharding.** A single `outbox.db` is simplest and matches
> leria. Sharding by subject/tenant would parallelize append but complicates the gap-free global cursor.
> **DECIDED: sharded per tenant (D3).** Partition the outbox by tenant — per-tenant monotonic seq +
> per-tenant cursor. In the P5 per-tenant-shard deployment this is one outbox per vultrino (clean); a
> shared multi-tenant vultrino then needs per-tenant broker cursors on the govder side (follow-on).

Location: a sibling file `outbox.db` in the same data dir (`$HOME/.local/share/vultrino/`), on **its own
PVC** in k8s (separate from the vault PVC), mirroring leria's separate-PVC-per-SQLite-store rule.

## 4. Storage version bump v6 → v7 + migration

`STORAGE_VERSION` (`src/storage/file.rs:38`) goes `6 → 7`. `check_version` (`:144`) already refuses to open
a vault written by a **newer** binary (`found > supported`), so:

- A **v7 binary** opening a **v6 vault**: `found=6 <= supported=7` → allowed. On first open, run a one-time
  migration: drain the in-vault `outbox` BTreeMap into the new `outbox.db` (preserving `seq`/state),
  carry `outbox_seq` into the store's sequence row, then write the vault back **as v7 without the outbox
  fields**. Idempotent + crash-safe: do the drain into `outbox.db` first (the events are durable there),
  then the vault rewrite drops them; a crash before the vault rewrite just re-drains (de-duped on
  `event_id`).
- A **v6 binary** opening a **v7 vault**: `found=7 > supported=6` → **refused** (`UnsupportedVersion`).
  This is the desired safety: an old binary must not silently run against a vault whose outbox now lives
  elsewhere (it would see an empty outbox and stop emitting). Operators roll forward only.

> Open decision **D4 — migration trigger.** (a) automatic on first v7 open (zero operator action, but the
> first open does a one-time O(old-outbox-size) drain) vs (b) an explicit `vultrino migrate-outbox`
> subcommand gated behind a flag. **Recommendation: automatic**, with a loud log line + a dry-run
> `vultrino migrate-outbox --check`. The drain is one-time and bounded by the existing (retention-capped)
> backlog.

## 5. Code touch-points (for the implementation PR, not now)

- `src/storage/file.rs`: remove `outbox`/`outbox_seq` from `StorageCache`; add the intent column (D1);
  `append_event` writes intent-under-lock + drains to the store; `list_events_after` reads the store (no
  vault reload); `gc_outbox` deletes from the store; `claim_deliverable_events`/`record_delivery` move to
  the store; `STORAGE_VERSION = 7` + the migration in the open path.
- `src/outbox.rs`: the `OutboxEvent` type is reused; add the store handle + WAL/busy_timeout config.
- New `src/storage/outbox_store.rs` (the SQLite outbox store + its tests).
- `src/server/mod.rs`: the `deliver_outbox_once` loop reads/claims from the store; the GC cadence stays.
- Config: `[outbox] db_path`, `retention_secs` (already exists), `at_rest_encryption` (D2).
- k8s (`feir-os`): AS-BUILT, `outbox.enc` is written ALONGSIDE `credentials.enc` in vultrino's data dir
  (`outbox_path = vault.with_file_name("outbox.enc")`), so it rides the EXISTING `vault` PVC — no new
  PVC. The "dedicated outbox PVC" recommended here was considered and DROPPED: the cliff fix is FILE
  separation (an append re-encrypts only `outbox.enc`, never the secrets vault), which is independent of
  PVC layout; a separate PVC would only isolate disk IOPS while adding the immutable-`volumeClaimTemplates`
  `--cascade=orphan` recreate runbook. Retention GC bounds `outbox.enc` on the shared PVC.

## 6. What this does NOT change

- The secrets vault stays AES-256-GCM + fd-lock + atomic rename. Credential/token/approval **state**
  mutations are unchanged and still atomic within the vault.
- The signed-event format, the per-subject ordering contract, and the gap-free cursor semantics are
  preserved (govder's broker cursor keeps working).
- vultrino stays a single-replica node-isolated singleton; this is a per-node throughput fix, not
  horizontal scaling.

## 7. Acceptance gate

Per the §12 plan: gate vultrino capacity on an **aged-vault admitted-LLM load test** — measure
append-event p99 and `list_events_after` p99 against a vault aged to N days of events, BEFORE vs AFTER, to
prove the O(vault-size) term is gone. Target: append/poll latency flat as the event backlog grows.

## 8. Relationship to the interim self-contained wins (shipped separately)

Two smaller §12 wins land first WITHOUT this format change (reversible, no migration):

- **read-path reload-skip**: `list_events_after`/`reload` skip the full-vault decrypt when the on-disk
  vault is unchanged (mtime+len guard) — cuts redundant decrypts on idle polls. **Subsumed** by this
  migration once the outbox reads from its own store, but valuable until then.
- **retention as an operator knob**: expose `retention_secs` so operators can cut the backlog (and thus
  the per-rewrite cost) today.

These are stopgaps; this migration is the structural fix.

## Decisions — RESOLVED (2026-06-25; see the header for the binding statements)
- **D1** = intent-staging (state↔event kept atomic across the two files).
- **D2** = per-row AES-256-GCM on the outbox store (nothing in plaintext).
- **D3** = sharded per tenant (per-tenant seq + cursor; one-per-vultrino in the shard deployment).
- **D4** = automatic, no explicit command (no v6 vault deployed → v7 is the format; best-effort
  drain of an old dev/test v6 vault on first open).

## As-built + post-review hardening (2026-06-25)

What shipped differs from the §3 SQLite sketch (D2 note): the outbox is a separate **`outbox.enc`**
file (`src/storage/outbox_store.rs`) reusing the vault's whole-cache AES-256-GCM + fd-lock +
tmp+atomic-rename machinery (`OUTBOX_FILE_VERSION=1`), NOT SQLite. Intent-staging (D1) is realized as
`StorageCache.pending_events: Vec<StagedEvent{dedup_id,subject,event_type,payload}>` staged in the
vault `locked_mutate`, drained via `OutboxStore::append_deduped` (idempotent on `dedup_id`).

A multi-lens adversarial review of the S2+S3 wiring (11 confirmed findings) drove these fixes:

- **Periodic drainer (the §2a "periodic tick" half).** Originally only the *startup* reconcile + the
  inline post-commit drain existed; an inline drain that failed on a long-lived process with no further
  approval traffic orphaned the event until restart. Now `drain_pending_events_periodically`
  (`server/mod.rs`, `PENDING_DRAIN_SECS`) is spawned in both `run_mcp_server` and `run_web_server` via
  the `StorageBackend::reconcile_pending_events` trait method (default no-op; FileStorage delegates to
  `drain_pending_events`). This bounds an orphaned intent's lifetime to one tick.
- **Post-commit drain is best-effort.** `decide_approval` / `poll_refresh_approval` /
  `sweep_approval_lifecycle` committed the decision/transition **and** the intent atomically, then
  drained with `?` — so a transient `outbox.enc` I/O error reported a *committed* approval as "not
  recorded" to the human approver (and suppressed sweep escalation notifications). The post-commit
  drain now logs-and-continues (returns Ok with the committed result); the periodic/startup reconciler
  delivers the staged event.
- **Crash-DURABILITY of the rename.** Both write paths (`outbox_store::write_to_disk`,
  `file::write_cache_to_disk_sync`) fsync the **parent directory** after the atomic rename — rename is
  crash-atomic but the new dir entry is only crash-durable once the dir is fsynced (best-effort;
  ignored on filesystems without dir fsync).
- **Migration reserves the sequence range up front.** `migrate_v6_outbox` uses
  `OutboxStore::insert_events_preserving_seq` (one locked write that bumps `outbox_seq` to the batch
  max **before** inserting), so the out-of-scope multi-process-open-of-a-v6-vault case can't let a
  concurrent append grab a not-yet-migrated seq (an `or_insert` no-op = silent legacy-event drop).
- **Literal-v6 read test.** `migrates_a_literal_version6_on_disk_vault` hand-writes a genuine
  `version:6` file (in-vault outbox, no `dedup_id`, no `pending_events` key) and asserts the
  downgrade-read + serde-default contract + sequence-preserving migration — the prior test only
  round-tripped v7 bytes.

**Considered and consciously NOT done — O(1) dedup index.** `append_deduped` scans the live outbox for
a matching `dedup_id` (O(retention-bounded-outbox)) on each coupled-emit drain. An index would make
that lookup O(1), but every drain already re-encrypts + rewrites the whole `outbox.enc` (also O(n)),
so the scan is never the dominant term — an index would not change the path's asymptotic cost and would
add cache state to keep consistent. The periodic drainer (above) keeps an intent's lifetime far below
the outbox retention window, so the dedup memory (the live outbox rows) cannot be GC-pruned out from
under a still-staged intent in practice — closing the dedup-vs-GC duplicate window without an index.
