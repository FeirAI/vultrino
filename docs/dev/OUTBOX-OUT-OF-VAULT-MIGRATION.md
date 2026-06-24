# Design: move the signed outbox OUT of the encrypted vault (storage v6 → v7)

Status: **DESIGN — for review before implementation.** No code in this document is implemented.
Scope: vultrino storage layer (`src/storage/file.rs`, `src/outbox.rs`). Companion §12 deployment item.

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
> **Recommendation: single store** (revisit only if the load test in §7 shows append contention).

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
- k8s (`muntin`): a dedicated outbox PVC for the vultrino StatefulSet (mirrors leria's per-store PVC rule);
  StatefulSet `volumeClaimTemplates` are immutable → an already-deployed vultrino needs the
  `--cascade=orphan` recreate runbook (same caveat we hit for leria's 3rd PVC).

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

## Open decisions to confirm before implementation
- **D1** event/state atomicity: intent-staging (recommended) vs pure-reconcile.
- **D2** outbox at-rest: app-level AES-GCM per row (recommended) vs SQLCipher vs plaintext-on-PVC.
- **D3** single store (recommended) vs per-subject sharding.
- **D4** migration trigger: automatic on first v7 open (recommended) vs explicit subcommand.
