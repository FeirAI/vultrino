# averin sealing — the fourth contract (vultrino → averin per-use grant/use)

> **Design doc for plans 086 + 087 (feir-os).** §§0–9 are the plan-086 DESIGN +
> SPIKE and its go/no-go; **§10 is the plan-087 production-ready posture** (async
> fail-open, off the hot path, bounded fan-out, alarm). This resolves the
> load-bearing decisions the mapped design left to implementation. The production
> default stays **byte-identical to today**: the seal-client is behind
> `[averin] enabled = false` and, off, vultrino's `/execute` and `/token-mint`
> paths are unchanged.
>
> **Sources this refines** (read them first — this doc does not re-derive them):
> - `averin/docs/vultrino-integration.md` — the committed design note (R2
>   role-separation, two-phase `--uses N` → `bounded_reuse`, the fail-open sink,
>   the 5-step build order). This doc RESOLVES its open implementation choices.
> - `govder/docs/_meta/vultrino-averin-contract.md` — the full working field map.
> - `govder/docs/14-ecosystem-operating-system.md:104,106,110,247` — the
>   architecture constraints: the fourth contract "does not pass through govder
>   at all"; "vultrino holds no averin signing keys"; keep the high-frequency
>   seal off the decision path.

## 0. What this contract is

averin already seals **decisions** (approvals, kills, budget verdicts, grants).
It does **not** yet seal the **data-plane use** of a credential: a routine
allowed `/execute` is enforced and metered (and, after plan 085, *visible*) but
not individually **sealed** into the tamper-evident DAG. This contract closes
that: vultrino becomes the PRODUCER for two averin endpoints that already exist
on the RECEIVING side —

| vultrino event | averin endpoint | averin record |
|---|---|---|
| use-token **mint** | `POST /v2/grants` | a signed `gateway_enforced` grant (record-before-issue) |
| credentialed **`/execute`** | `POST /v2/use` | a resource-signed one-phase use receipt |

vultrino gains only a **thin seal-client**. averin needs **no new code** — it is
already the receiver (verified: `averin/server/internal/api/server.go` route
table wires `POST /v2/grants → handleGrant` and `POST /v2/use → handleUse`; a
fresh in-memory averin with broker+resource enabled answers both with a 400 on a
bad body, i.e. the routes are live, not 501).

## 1. Trust model — who holds which key (R2, verified)

The whole point of routing this OUTSIDE govder and keeping vultrino key-free is
that **the evidence is signed by averin's own role-separated keys, not by
vultrino**. Verified against `averin-server` startup
(`server/cmd/averin-server/main.go`) and the option guards
(`server/internal/api/server.go` `WithBroker`/`WithResource`):

| Key | Held by | Signs | Disjointness enforced |
|---|---|---|---|
| server/core **signing** key (`AVERIN_SIGNING_SEED`) | averin | every sealed record; the grant's `gateway_enforced` evidence | — |
| **broker issuing** key (`AVERIN_BROKER_ISSUING_SEED`) | averin | the minted capability descriptor | ≠ resource key (`WithBroker` panics on overlap; `main.go` fatals) |
| **resource recording** key (`AVERIN_RESOURCE_SEED`) | averin | the use receipt's authority evidence | ≠ signing key AND ≠ broker key (R2; `WithResource` panics; `main.go` fatals) |
| **agent PoP** key (`cnf`) | **vultrino (the seal-client)** | the grant `agent_sig` and the use `use_sig` | this is the ONLY non-averin key in the flow (`14-ecosystem:106`) |

**vultrino holds no averin signing key.** It generates an ephemeral Ed25519
**agent/PoP keypair per grant** and proves possession of it — exactly the
"sender-constrained capability" model. Averin's three keys stay disjoint-or-fatal
and none of them ever leaves averin. This satisfies the STOP condition in the
plan: `/v2/use` does **not** require a key vultrino would hold — it requires the
averin-minted `capability` (opaque to vultrino) plus a PoP signature under the
agent key vultrino itself created. If a future change made `/v2/use` demand an
averin key on the caller side, that would contradict the trust model and must
STOP — it does not today.

## 2. Mint → `POST /v2/grants` (record-before-issue) — the easy half

Lower frequency (one grant per token mint), no hot path. Fully specified:

1. On a successful `store_use_token` in `api_create_token`, the seal-client (when
   enabled) does a best-effort `POST /v2/grants`.
2. **Deterministic `grant_id`.** averin derives `grant_id =
   uuidV5(averin.grant.id.v1, project_id, idempotency_key)`
   (`server.go:deterministicGrantID`). The seal-client sends `idempotency_key =
   token.id` (the stable `vut_…`/`ut_…` id), so a lost-response retry collapses
   to the same grant and never mints a second live credential
   (`handleGrant` requires the idempotency key for exactly this reason).
3. **PoP-key binding.** The client generates an Ed25519 keypair, sends
   `agent_pubkey` (base64url-no-pad, raw 32 bytes) and `agent_sig` = Ed25519 over
   the broker PoP challenge (see §5). averin binds the pubkey's kid as the
   capability's `cnf` — the use later must prove possession of the same key.
4. **Scope class.** A vultrino token minted with `--uses 1` maps to
   `single_operation`; a token with `--uses N` (N>1) maps to averin's
   `bounded_reuse` with `use_limit = N` (ADR 0005 M1). The spike ships
   `single_operation`; `bounded_reuse` field wiring is specified but is Phase-2
   (see §7). vultrino's `credential_scope`/`action_scope` map to the grant's
   `scope`/`action`; the grant `resource` is the configured averin `resource_id`
   (the audience the use receipt validates against).
5. **Record-before-issue is averin's, not vultrino's.** averin seals the grant
   record BEFORE returning the capability (`handleGrant` docstring), under its
   ingest lock, with a gapless `broker_seq`. vultrino just stores the returned
   `{capability, grant_id}` (keyed by `token.id`) alongside the PoP private key it
   generated, for the later use.

Mint-seal fail-mode is **fail-open, always**: a token is a vultrino artifact; its
existence must not depend on averin's availability. A failed grant seal is logged
(and, in production, must raise an operator alarm — `vultrino-integration.md §5`)
but never blocks the mint.

## 3. Execute → `POST /v2/use` — the crux (sync vs async + fail-mode)

This is the decision the mapped design deferred. On `/execute`, vultrino consumes
the use token fail-closed "just before the side effect… the point of no return"
(`src/server/mod.rs run_action`, between `consume_use_token` and
`plugin.execute`). The seal can go in one of three shapes:

### 3.1 The three shapes

- **(A) Synchronous, fail-closed.** `POST /v2/use` and **await it before**
  `plugin.execute`; if averin is unreachable or rejects, **fail the action**.
  This is the strict Level-3 consume-before-act guarantee: no credentialed side
  effect ever occurs without a durable, anchored, resource-signed receipt.
- **(B) Synchronous, fail-open (proceed-and-flag).** `POST /v2/use` and await it,
  but on averin failure **log + alarm and proceed** with `plugin.execute`. This is
  the "fail-open sink" the integration note describes as the default posture.
- **(C) Asynchronous.** After the consume, **`tokio::spawn` the seal** and let
  `plugin.execute` proceed without waiting. Closes the *visibility* gap (the same
  gap plan 085 closes) but NOT the synchronous consume-before-act proof: a crash
  or averin outage between the act and the seal leaves the action done with no
  receipt.

### 3.2 Two independent costs, and why (A) is structurally disqualified as a default

**Cost 1 — per-call latency.** A synchronous seal adds the averin round-trip to
every governed `/execute`. Measured on localhost against an in-memory averin (the
spike, §6): the added synchronous cost is small in absolute terms (single-digit
milliseconds), because the crypto and the in-memory ledger consume are cheap. In
production this becomes network RTT + averin's real (Postgres) ledger consume on
top. As a fraction of a typical credentialed action (an outbound HTTP call or a DB
query, tens-to-hundreds of ms), a few ms is a <10% happy-path overhead — **not**,
by itself, budget-blowing.

**Cost 2 — fleet-wide serialization (the real blocker).** averin's `/v2/use`
enforcement path runs its whole `RecordByIdem → ValidateUse → buildUseRecord →
seal → PutRecord` critical section under a **single process-global mutex**
(`ingestMu`; `averin/docs/dev/LIMITATIONS.md` "Ingest is serialized by a
process-global mutex"). `ValidateUse` performs the consume-before-act ledger
writes (two ~10s-bounded Postgres consumes) **while holding `ingestMu`**. So:

- averin's sealed throughput is **one in-flight seal at a time, across every
  project** — a single-writer ceiling.
- **Making the seal synchronous on every `/execute` funnels the entire governed
  fleet through that one lock.** Tail latency on any `/execute` becomes bound to
  averin's *slowest* dependency (a stuck Postgres consume stalls ALL ingest for up
  to the ~tens-of-seconds timeout). This is precisely the high-frequency latency
  the architecture deliberately kept off govder's decision path
  (`14-ecosystem:104,110`), reintroduced on a different axis.

The **latency budget** we set is therefore two-part, and (A)-as-default fails the
second part regardless of the first:
- **Per-call:** added `/execute` p50 ≤ ~10 ms, p99 ≤ ~50 ms (a resource whose own
  action is ≥100 ms can absorb this).
- **Throughput/coupling:** the seal must **not** make the fleet's governed-action
  throughput a function of averin's single-writer ingest rate, and must **not**
  bind `/execute` availability to averin's. Synchronous-on-every-execute violates
  both.

### 3.3 Fail-mode × the product's fail-closed posture

vultrino is a fail-closed enforcement plane, but "fail-closed" means *don't
perform the action when **enforcement** is unmet* — where enforcement =
policy/approval/metering/injection. **Evidence sealing is not enforcement.**
Conflating them ((A), fail-closed on a missing *seal*) means an averin outage
**halts every credentialed action** — it inverts the architecture: the in-path
enforcer becomes strictly less available than the offline evidence plane it feeds.
That is the wrong trade for the general case.

(B) keeps the strong ordering on the happy path but, on averin outage, the action
proceeds with **no receipt** — so the Level-3 "every use is provable" claim has a
hole precisely when averin is down. Honest, but it means the guarantee is
conditional on averin's uptime, which the copy must not overstate.

(C) never couples `/execute` to averin at all, and the crash/outage window is
recorded honestly as "no receipt for this use" — the same honest residual the
integration note already states for the two-phase crash window.

### 3.4 Decision

- **Default (both `enabled=false` today, and the recommended production default
  when it flips): asynchronous (C), fail-open.** It closes the visibility gap
  without coupling `/execute` latency or availability to averin, and without
  funneling the fleet through `ingestMu`.
- **Offer synchronous consume-before-act (A/B) as an opt-in strict mode
  (`mode = require_evidence`) scoped to a narrow set of high-assurance
  resources** whose operators explicitly accept the availability coupling and the
  single-writer throughput ceiling for those resources. Never fleet-wide.
- The **spike implements the synchronous path (B)** on purpose — that is the only
  way to *measure* the worst-case added latency (Cost 1) and to exercise the real
  crypto/ledger cost. The go/no-go (§8) uses that measurement plus the `ingestMu`
  structural argument to recommend the async default.

## 4. The grant ↔ use join and `bounded_reuse`

The offline verifier joins a use receipt to its grant by `grant_id` (the
capability's `jti` == the grant record's id) and re-runs the PoP under the `cnf`
key carried on the receipt (`averin/docs/dev/LIMITATIONS.md`,
`server/internal/resourceshim`). For `bounded_reuse`, each exercise carries a
1-based `use_sequence_number` in `[1, use_limit]`, deduped per `(grant_id,
use_sequence_number)` — the natural target for a vultrino `--uses N` token, where
vultrino already tracks `uses`/`max_uses`. The spike uses `single_operation`
(`use_sequence_number` omitted); mapping vultrino's `uses` counter onto averin's
`use_sequence_number` is a small, well-defined Phase-2 extension.

## 5. The PoP preimages (byte-exact — the seal-client must match averin)

These are a cross-language binding averin keeps in
`averin/spec/golden-vectors/broker-preimages.json`; the seal-client
(`src/averin/pop.rs`) reproduces them and is unit-tested against those vectors.

- **Grant PoP** (`agent_sig`): Ed25519 over the JSON object with keys in
  alphabetical order — `{"action","agent_id","agent_pubkey","resource","scope","tag"}`,
  `tag = "averin.broker.pop.v1"` (matches Go's sorted-key `json.Marshal`;
  `broker.Request.Challenge`). ASCII field values only (base64url pubkey, dotted
  action/scope) so serde's non-sorting, non-HTML-escaping output is byte-identical.
- **Use PoP** (`use_sig`): Ed25519 over the 32-byte digest
  `SHA256( LP(tag) ‖ LP(grant_id) ‖ LP(resource_id) ‖ LP(action) ‖
  LP(params_commitment) ‖ LP(credential_binding) ‖ LP(nonce) )`,
  `tag = "averin.broker.use.pop.v1"`, `LP(x)=uint32_be(len(x))‖x`
  (`resourceshim.usePoPChallenge`).
- **`params_commitment`**: `"sha256:"+hex( SHA256( LP("averin.commit.v1") ‖
  LP("input") ‖ LP(nonce32) ‖ LP(value) ) )`, `nonce32` = hex-decoded
  `params_nonce` (64 lowercase hex), `value` = raw `params` bytes
  (`core/src/commit.rs`).
- **`credential_binding`**: `"sha256:"+hex( SHA256( base64url_decode(payload) ) )`
  where `payload` is the part of the `capability` before the first `.`
  (`resourceshim.credentialBinding`).

### 5a. Params retention — raw vs commitment (resolved)

The `/v2/use` body sends the **raw `params`** (the agent's `/execute` payload)
alongside `params_nonce`. This is **required, not a footgun**: averin does not
accept a `params_commitment` field on the wire — it **recomputes** the
commitment server-side (`Commit("input", raw_params, params_nonce)`,
`server/internal/api/server.go handleUsePhase`) and rejects the seal if it does
not match the commitment the `use_sig` PoP was signed over
(`resourceshim.ValidateUse` → `ed25519.Verify`). This is averin's
**recompute-or-reject** integrity property: "the agent cannot bind params
different from those it sends." Dropping raw params would make averin recompute
the commitment over empty bytes → mismatch → HTTP 400 → the seal breaks.

Crucially, raw params do **not** enter averin's permanent, signed,
hash-chained record body. `buildUseRecord` seals **only the hiding commitment**
into the signed body (`input_commit.commitment`); the raw bytes are stored in
averin's **erasable content store** as a `DisclosureSecret` —
AES-256-GCM-encrypted per-tenant (`EncryptedFSStore`) and **retention-purged**
after `AVERIN_RAW_RETENTION_DAYS`, after which the record still verifies from
its commitment alone (`averin/docs/dev/SECURITY.md §"Data retention & erasure"`).
So the privacy posture is: **permanent = commitment only (a hiding hash);
raw params = encrypted + time-boxed + erasable disclosure**. When the async
production build lands (per the go/no-go), keep this two-tier split — never seal
raw params into the permanent body, and honor the retention window.

## 6. What the spike proves (and the honest capstone gap)

The spike (flag ON) drives a real `vut_`-authenticated `/execute` and shows, via
`GET /v2/export` from a **real** averin, a sealed `use` record carrying
`resource_trust: "assumed_truthful"` and joined to its grant. Flag OFF →
byte-identical to today (the hooks are `None`).

**Honest correction to the plan's deliverable wording.**
`attested_complete_over_brokered_surface` is **not** a field stamped on a use
record — it is the offline verifier's **D8 capstone** over a whole bundle
(`averin/core/src/verify.rs ActionCompleteness`). Reaching it requires the FULL
stack: a **two-phase** use (`/v2/use-intent` + `/v2/use-outcome`, NOT a one-phase
`/v2/use`), a `coverage_manifest` (`WithCoverageManifest`), a
`deployment_attestation` (`WithAttestation`), an anchored checkpoint, and a signed
taxonomy — all pinned at verify time. A **thin single-phase seal-client
(deliverable 2's explicit shape) provably cannot reach that capstone**;
`resource_trust: "assumed_truthful"`, by contrast, is emitted unconditionally on
any bundle with a resource gateway. So the spike asserts the achievable, honest
facts (a real sealed one-phase `use` record + `resource_trust: assumed_truthful`
+ the grant↔use join) and records that the capstone is **Phase-2** work
(two-phase + manifest + attestation + taxonomy), not something a thin client
delivers. Upgrading the spike's claim to the capstone would be dishonest to the
bound.

## 7. Phase split

- **Phase 1 (this spike, flag-gated, default off):** the seal-client —
  `mint → /v2/grants`, `execute → /v2/use` (one-phase), PoP, the in-memory
  `token.id → {capability, grant_id, pop_key}` map, latency measurement.
- **Phase 2 (not in scope here):** two-phase `use-intent`/`use-outcome` mapped to
  vultrino's `committed`/`terminal`/`retryable` taxonomy; `bounded_reuse`
  `use_sequence_number`; approvals → `human_signed`/`policy_engine_signed`
  authority evidence; revocation; `coverage_manifest` + attestation to unlock the
  D8 capstone; durable token→PoP persistence (the spike keeps it in-memory,
  restart-losable, matching the seal's best-effort posture).

## 8. Go / No-Go (see the spike's measured numbers in `RESULTS`)

- **Ship synchronous per-use seal fleet-wide: NO.** It funnels every governed
  action through averin's process-global `ingestMu` (one in-flight seal at a time,
  tail latency bound to averin's slowest Postgres consume), reintroducing the
  high-frequency latency the architecture kept off the decision path — and its
  fail-closed variant makes an averin outage halt all credentialed actions.
- **Ship asynchronous seal as the default (when the flag flips): YES-eventually.**
  Closes the data-plane visibility gap (with plan 085 as its regression detector)
  without coupling `/execute` to averin. This is the recommended production shape.
- **Synchronous consume-before-act (strict `require_evidence`): opt-in, per-
  resource only** — for the narrow high-assurance case whose operator accepts the
  coupling and the single-writer ceiling. Never the default.
- **Net recommendation: HOLD the synchronous path; do not flip any production
  default in plan 086.** Land the async visibility path as the eventual default;
  keep sync strict mode as an explicit opt-in. The measured latency (below)
  confirms the per-call cost is modest, but the `ingestMu` fleet-serialization is
  the decisive, measurement-independent reason not to make sync the default.

## 9. Measured results (spike, flag ON, `tests/averin_spike.rs`)

Against a REAL averin-server (in-memory store + ledger, broker + resource
enabled), driven by the seal-client. Both tests pass — which, because averin
`400`s a wrong PoP preimage, is itself the byte-exactness proof that
`src/averin/pop.rs` reproduces averin's grant + use PoP and params-commitment
exactly.

**Sealed use record (`sealed_use_record_appears_in_averin_export`).** A
`vut_`-keyed `seal_grant` → `POST /v2/grants` then `seal_use` → `POST /v2/use`
produced a sealed use receipt `use-fcd47ff2-…` present in `GET /v2/export`. The
`GET /v2/verify` self-report showed:
- `resource_trust: "assumed_truthful"` — as expected, unconditional.
- `grant_total: 1, grant_verified: 1, grant_accountability: "complete"`; two
  `record_trust` entries — a `broker_role:"broker"` grant and a
  `broker_role:"resource"` use receipt — BOTH `integrity_ok:true`,
  `signature_ok:true`, `authority:"verified"`, `trust:"integrity_proven"`.
  The use receipt is genuinely sealed and its resource signature verifies.
- `action_completeness: "not_claimed"` — **confirming §6's honest capstone
  gap**: a thin single-phase `/v2/use` does not reach
  `attested_complete_over_brokered_surface`.
- `ok: false`, because the spike created **no checkpoint** (`"no checkpoints: a
  non-empty run must be checkpoint-committed"`). Checkpointing is a separate
  periodic averin operation, not part of the per-use seal; the individual grant
  and use records are nonetheless sealed and individually proven
  (`records_proven: 2/2`). A real deployment checkpoints on averin's cadence.

**Added `/execute` latency (`measure_added_execute_latency`, N=50, localhost +
in-memory averin — a FLOOR):**

| | seal ON (sync `POST /v2/use`) | seal OFF |
|---|---|---|
| min | 1.87 ms | ~0 (call skipped) |
| p50 | **1.95 ms** | ~0 |
| mean | 1.97 ms | ~0 |
| p90 | 2.05 ms | ~0 |
| p99 | **2.12 ms** | ~0 |
| max | 2.12 ms | ~0 |

**Reading the numbers against the budget (§3.2).** The per-call cost (~2 ms p50
on this floor) is comfortably inside the ~10 ms p50 / ~50 ms p99 per-call budget
— even allowing several ms of production network RTT and averin's Postgres
consume on top. So **Cost 1 does not, by itself, disqualify a synchronous seal.**
The disqualifier is **Cost 2**, which no latency measurement can soften: every
synchronous seal serializes through averin's process-global `ingestMu` (one
in-flight seal fleet-wide; tail latency bound to averin's slowest Postgres
consume, ~tens of seconds). Making sync the default would make the whole
governed fleet's throughput a function of averin's single-writer ingest rate.

**Go/No-Go (final): HOLD synchronous-as-default.** Ship the **async, fail-open**
seal as the eventual default (closing the plan-085 visibility gap without
coupling `/execute` to averin); offer **synchronous `require_evidence`** as an
explicit, per-resource opt-in for the narrow high-assurance case whose operator
accepts the availability coupling and the single-writer ceiling. **Do not flip
any production default in plan 086** — the seal-client stays `enabled = false`.

## 10. Plan 087 — production-ready async posture (what "enabled=true" now means)

Plan 086 landed the seal-client + the go/no-go above but seals SYNCHRONOUSLY (to
measure Cost 1). Plan 087 makes the seal **production-ready** by implementing the
§8 recommendation, while keeping the **default OFF and the default-off build
byte-identical** (`self.averin == None` → both hooks skipped; verified: the only
new code runs when `[averin] enabled = true`).

**The execute seal is now async fail-open, off the hot path.** In `Observe` mode
(the default), `run_action` calls `AverinClient::spawn_use_seal` instead of
awaiting `on_execute`: it `tokio::spawn`s the `POST /v2/use` and returns
immediately, so `plugin.execute` NEVER waits on averin. An averin outage cannot
stall or fail a governed action — it only leaves an unsealed use (the honest §3.1
(C) residual), which **plan 085** independently detects and reconciles.
`require_evidence` is unchanged: still synchronous-by-design (await + block on
failure), carrying its documented consume-before-seal caveat (the vut_ token is
consumed before the seal, so a strict block burns it — out of scope here; that
caveat is UNREACHABLE in the async Observe default because it never blocks).

**The async fan-out is bounded — the one discipline that matters.** A sustained
averin outage under high `/execute` load must not pile up unbounded spawned tasks
→ OOM. `spawn_use_seal` claims a permit from a `tokio::sync::Semaphore`
(`[averin] max_inflight_seals`, default **256**) WITHOUT blocking
(`try_acquire_owned`); the permit is held for the seal's whole lifetime and frees
a slot on completion. On saturation the seal is **DROPPED fail-open** — never
blocking `/execute`, never growing unboundedly — becoming an 085-detected gap.
Drop-vs-block is deliberately **drop**: blocking would reintroduce exactly the
`/execute`↔averin coupling §3.2 rejects. The bound does not apply to
`require_evidence` (that path already blocks `/execute`, so it is naturally
back-pressured).

**Fail-open failures/drops/timeouts alarm.** Each of {seal HTTP failure, timeout,
fan-out drop} bumps a per-process counter (`sealed`/`failed`/`dropped`, surfaced
on `GET /api/v1/metrics` as `averin_seal`, present only when enabled) AND emits a
distinct greppable line — `AVERIN-SEAL-FAILED` / `AVERIN-SEAL-DROPPED` — carrying
token id + `project_id` context but **never a secret or the raw params** (params
are never logged). This is the operator alarm §2/§8 require; it pairs with plan
085's govder-side reconciliation of the unsealed actions.

**Mint stays synchronous (Step 4, deliberately).** The grant record + PoP entry
must be on record before the token is handed back, or the agent's first
`/execute` could race ahead of the grant seal and hit `NoGrant`. Mint is the
control plane, not the `/execute` hot path, so its averin round-trip does not
touch action latency; it remains fail-open (a token never depends on averin).

### What `enabled = true` now gives — and does NOT give

- **Gives:** every brokered `/execute` (Observe) gets a sealed averin `/v2/use`
  receipt, **asynchronously and fail-open**, with a **bounded** fan-out and an
  **alarm** on the residual — safe to enable per deployment, with no `/execute`
  latency or availability coupling to averin, and no fleet serialization through
  `ingestMu` (one async seal per action, shed under overload).
- **Does NOT give:** at-least-once durability (a crash/outage/drop window leaves
  an unsealed use — detected by **085**, made durable by **plan 088**, which
  reuses vultrino's `outbox_store` for at-least-once `/v2/use` delivery +
  durable token→PoP persistence); and **not** the D8 capstone
  `attested_complete_over_brokered_surface` (that needs two-phase
  use-intent/outcome + coverage manifest + attestation + anchored checkpoint —
  **plan 089**, separate, needs averin-side validation). The in-memory pop map is
  still unevicted (flagged for 088).
- **Unchanged:** the production default is `enabled = false`. Plan 087 makes
  enabling SAFE and READY; it does not flip the switch on any deployment.

## 11. Plan 087 hardening — the six adversarial-review fixes

An adversarial review of the §10 landing found six issues (all verified against
the code). All six are fixed on `advisor/087-async-seal`, and all stay **behind
the existing `Some(av)` / `av.mode()` guards** — `enabled = false` remains
byte-identical to today. Summary of the resulting behavior:

- **Streaming is now sealed (FIX 1, was CRITICAL).** The execute seal previously
  lived ONLY in the buffered `run_action`; `run_action_streaming` consumed the use
  token and streamed WITHOUT any `/v2/use` seal — so a `stream: true` request had
  no receipt and, in `require_evidence`, proceeded even with averin down (a
  strict-mode fail-OPEN hole). The mode-dependent hook is now ONE shared helper,
  `VultrinoServer::seal_after_consume`, called from BOTH paths after the token
  consume and before `plugin.execute*`. On the streaming path in
  `require_evidence` the seal is **awaited and a failure DENIES before the SSE body
  opens** (fails CLOSED); in `Observe` it is spawned off the hot path exactly like
  the buffered path. Tests: `observe_streaming_execute_proceeds_and_spawns_seal`,
  `require_evidence_streaming_denies_when_seal_fails`
  (`tests/averin_streaming_seal_integration.rs`).

- **Mint coverage is centralized (FIX 2, was MAJOR).** Only the JSON admin API
  called `on_mint`; the web console and workload exchange issued usable tokens
  WITHOUT a grant, so their first `/execute` sealed `NoGrant` (Observe: a fail-open
  logged gap; `require_evidence`: consume-then-deny that burns the token). All
  **in-process** mint surfaces now call the same `VultrinoServer::seal_mint`
  (JSON API `api_create_token`, web-console token create, workload-exchange MCP +
  per-channel model tokens). Test:
  `seal_mint_records_grant_so_first_execute_seals_not_nogrant`.
  **CLI limitation (explicit):** `vultrino token create` mints in a **separate
  process** and cannot populate the serving process's in-memory PoP map, so it
  CANNOT record the in-process grant. Rather than silently issue a token whose
  first `/execute` seals `NoGrant`, the CLI **warns** (to stderr) when `[averin]
  enabled = true`. Durable, cross-process token→PoP persistence (which would let
  the CLI seal a grant the server can use) is **plan 088** — until then, mint via
  an in-process surface when averin is enabled.

- **The fan-out is bounded in BYTES, not just task count (FIX 3, was MAJOR).** A
  permit caps the task COUNT, not the bytes each retains, so large payloads could
  pin gigabytes. New `[averin] max_seal_params_bytes` (default **128 KiB**,
  operator-tunable): params larger than the cap are **not sealed** — in `Observe`
  the seal is DROPPED fail-open (counted, `AVERIN-SEAL-DROPPED-oversize`); in
  `require_evidence` the action is DENIED with a bounded `ParamsTooLarge` error,
  **never transmitting the oversize body**. There is no "seal the commitment only"
  option: averin **recomputes** the params commitment from the raw bytes (§5a
  recompute-or-reject), so a fixed-size commitment cannot be sealed without the raw
  body — hence oversize = drop/deny, not truncate. Also: the seal now **moves** the
  params buffer into the task instead of re-copying it, and the averin **response
  read is capped** (`MAX_AVERIN_RESPONSE_BYTES`, 64 KiB) instead of an unbounded
  `resp.text()`.

- **Alarm lines never carry a response body (FIX 4, was MAJOR).** `AverinError::
  Status`'s `Display` (what the alarm logs via `error = %e`) now carries ONLY the
  endpoint + status code. The upstream body (possible PII/secret) is emitted once
  at a **debug-only** channel at the `post` site and is not carried on the error at
  all — no `AVERIN-SEAL-*` line can leak a body, capability, params, or secret.
  Test: `status_error_display_excludes_response_body`.

- **The drop log is rate-limited (FIX 5, was MAJOR).** Every saturated drop still
  bumps the counter synchronously (cheap, lock-free), but the `AVERIN-SEAL-DROPPED`
  **log line** is emitted at most once per 5 s (and always on the first drop, with
  a running `dropped_total`), so a sustained averin outage under load can't turn
  every dropped seal into a synchronous `warn!` on the `/execute` hot path. Test:
  `drop_log_is_rate_limited_after_the_first`.

- **`in_flight` is RAII-guarded (FIX 6, was MINOR).** A small `InflightGuard`
  decrements the `in_flight` gauge on `Drop`, so a panicking/cancelled seal task no
  longer overstates it; an abnormal exit also counts a `failed` (the lost seal is
  reflected, not silently dropped). Tests:
  `inflight_guard_releases_and_counts_failure_on_abnormal_drop`,
  `inflight_guard_normal_completion_counts_no_failure`.
