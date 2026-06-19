# Vultrino Dev Handoff — V13: Emit Usage Meter Events (for the leria metering plane)

**Status of vultrino:** V1–V12 built + reviewed (370 tests green); the 6 review residuals (R1–R6) and the dev's
own adversarial passes are landed on `fix/policy-engine`. **This handoff is the one remaining cross-plane ask** —
a *new* capability the metering plane (**leria**) depends on. It does **not** touch the existing enforcement
contract.

**Authoritative spec (read this — it's verified against vultrino source, with file:line):**
[`/Users/dzcodes/Projects/leria/docs/_meta/vultrino-integration-handoff.md`](/Users/dzcodes/Projects/leria/docs/_meta/vultrino-integration-handoff.md).
This doc is the vultrino-team summary; that doc is the detail.

## Why

leria is the OS's metering/FinOps plane (`govder decides · vultrino enforces · feir proves · leria meters`). Its
single durable book-of-record needs a **real-time** spend signal, and the earliest one is what vultrino already
sees in-path on `/execute`. Today vultrino surfaces none of it as telemetry. **vultrino is leria's
`gateway-observed` cost source** — the fast (but estimate-grade) input its reconciliation kernel anchors on.

## The ask — split into V13a (real now) and V13b (gated)

The headline "parse `usage.total_tokens`" is **greenfield in vultrino** (verified: `src/plugins/http.rs` buffers
with `.text().await`, **no SSE/streaming anywhere in `src/`**), so it's split:

- **V13a — emit `meter.observed` `{asset:api-calls, amount:1}` per admitted action.** Trivial–moderate, **buildable
  now**, no body parsing. Onto the existing **V9 signed outbox**, async/off the `/execute` latency path. Payload:
  `principal` (the V4 `agent_label`), `correlation_id` (the `/execute` request id), `cost_source:gateway-observed`,
  `dims` (`tenant`/`credential`/`model` if known), HMAC-signed. **No secrets/PII** (ids + a count only).
- **V13b — parse observed token counts** → a second event `{asset:tokens, amount:<count>}`. **Significant + gated**
  on: (i) vultrino gaining SSE/streaming awareness (else streamed LLM calls break and the `usage` block is absent
  without `stream_options.include_usage`); (ii) the read occurring **before `scrub_response`** (`src/server/mod.rs`
  redacts the body — emitting at the natural post-action hook reads redacted bytes → silent under-count); (iii)
  non-streaming-only as a stated v1 limit.
- **Outbox fan-out (or leria polls).** The V9 outbox is **single-subscriber** today (one `[outbox] url` + secret,
  already govder's). leria can't also push-subscribe — so either add **per-consumer/per-topic fan-out** (a real
  addition) or leria **polls** `GET /api/v1/events?after=N` (accept the latency). Decide + state which.

## What is explicitly leria's, not vultrino's

Pricing/rate-cards, `tokens→usd` conversion, the ledger, budgets, reconciliation, **any cumulative spend state**
(the windowed `SpendCap` you stripped in R1/V3 stays stripped — leria owns all cumulative accounting). vultrino
emits the raw real-time observation; that is the whole ask.

## Acceptance (per the authoritative spec)

1. Every **admitted** `/execute` emits one signed `meter.observed` event (`asset=api-calls, amount=1`, correct
   `principal`, `correlation_id`=request id, `cost_source=gateway-observed`); a denied action emits none; a replay
   dedups.
2. The emit is **off the latency path**; a leria/outbox outage does not fail `/execute`.
3. No body/prompt/secret in the event; the HMAC verifies; a tampered event is rejectable.
4. Multi-tenant: the event carries the correct `tenant`; never crosses tenants.
5. (V13b) a non-streamed LLM response with a `usage` block emits `asset=tokens`; the read precedes `scrub_response`.
6. The outbox-subscriber decision (fan-out vs poll) is implemented + documented.

## Note: enforcement needs NO new vultrino work

The budget-exhaustion `Deny` is authored by **govder** through your existing **V1** (config-write) + **V4**
(principal) — leria never calls vultrino directly. V13 is purely the telemetry-emit side.

---

## V13a — LANDED (branch `feat/v13a-leria-metering`)

**What shipped.** On every **admitted** `/execute` (policy allow + credential injection happened), `run_action`
emits exactly **one** `meter.observed` event onto the existing V9 signed outbox, on the same best-effort post-
`scrub_response` hook the `credential.rotated` emit uses. A **denied** action emits none (the emit is on the
post-admission path a denial never reaches). The emit covers **both** execution paths — the immediate path and the
post-approval `resume_approved` path both funnel through `run_action`, so an admitted action is metered exactly once
however it was admitted.

- **Event type constant:** `crate::outbox::EVENT_METER_OBSERVED = "meter.observed"`.
- **Payload builder:** `crate::outbox::meter_observed_payload(...)` — one place that fixes the MeterEvent shape
  (fields `snake_case`, enum values `kebab-case`): `event_id` = `correlation_id` = the `/execute`
  `request_id`; `principal` = the V4 `agent_label` (→ `vk_`/`vut_` id → credential alias fallback);
  `asset="api-calls"`, `amount=1` (integer minor units); `cost_source="gateway-observed"`; `confidence="low"`;
  `occurred_at` = the action timestamp; `dims` = `{ tenant (V11), credential alias, model if known }` with absent
  keys omitted (no phantom dims). `model` is always omitted for V13a — it does not parse the body.
- **No body bytes read:** a count of `1`. The V13b scrub-order hazard does **not** apply; emitting after scrub is
  safe.
- **Off the latency path / fail-open:** reuses `Self::emit_event`, which swallows outbox-append failures
  (`warn!`, "never fails the calling operation"). A leria/outbox outage does **not** block or fail `/execute`.
- **No secrets/PII:** the event carries ids + a count only — never the request/response body, prompt, or the
  injected credential secret (test-asserted: the credential secret string and the echo body never appear in the
  serialized event).

**Acceptance — all met (tests in `tests/approval_token_integration.rs`, `test_v13a_*`):**
admitted→one signed event with the right fields; denied→none; replay/distinct-call key semantics; outage doesn't
fail `/execute`; no secret + HMAC verifies + tamper detected; correct `dims.tenant` and never crosses tenants
(plus a cross-tenant-denial→no-event case); retrievable via the poll path with monotonic gap-free cursor + signed
delivery envelope. Plus a `meter_observed_payload` shape unit test in `src/outbox.rs`.

### Outbox subscriber decision — **Option B (leria POLLS)** for v1

The V9 outbox is **single-subscriber** (one `[outbox] url`+`hmac_secret`, already govder's). **No push fan-out is
built.** leria polls **`GET /api/v1/events?after=N&limit=M`** (`api_list_events` → `storage.list_events_after`).
`meter.observed` events are persisted into the **same** monotonic event log `api_list_events` serves — `emit_event`
→ `append_event` → `push_event` writes `cache.outbox`, and `list_events_after` reads `cache.outbox`; the sequence is
assigned under the lock, gap-free. So leria polls them gap-free by sequence (verified end-to-end by
`test_v13a_meter_observed_retrievable_via_poll_path`). The poll path returns the same `delivery_body` +
`Govder-Signature` envelope a push delivery carries, so leria verifies a replayed event exactly like a pushed one.

**Latency floor leria must model:** push delivery cadence `OUTBOX_DELIVERY_SECS = 5` plus the poll interval. The
fail-open `emit_event` means a dropped meter event is **silent** → leria needs the monotonic-`sequence` gap detector
on its poll feed (leria-side work, called out in the integration handoff).

**Contract note (leria ingest):** vultrino emits the dedup key as **`event_id`** (= the `/execute` `request_id`),
matching leria's canonical MeterEvent wire field (`WireEvent.event_id`, deduped `(authenticated_source_id,
event_id)`). An earlier draft of this handoff called it `idempotency_key`; that was drift — leria's ingest decoder
is strict (`DisallowUnknownFields`) and would 400 on an `idempotency_key` key, so the canonical contract §3.1 + the
leria code are authoritative and vultrino now emits `event_id` directly (caught by the integration watcher,
Wave 1).

### Residuals status on this branch

V13a is the only must. The R3/R4/V11/V12 residual work (`emit_policy_denied` detect events, `tenant` on approvals,
`ApprovalRequest::visible_to_tenant`, `EVENT_CREDENTIAL_REVOKED` + `propagate_revoke`, V10 inbound SVID/OIDC
resolvers) was **already landed** on `fix/policy-engine` before this branch and remains green; V13a needed no further
residual work because the V11 tenant tag is reachable at the emit site (the credential's `tenant` metadata) and the
V4 principal (`agent_label`/id) is on the `RequestContext`. **V13b is untouched (still gated).**
