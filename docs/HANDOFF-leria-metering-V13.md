# Vultrino Dev Handoff — V13: Emit Usage Meter Events (for the leria metering plane)

**Status of vultrino:** V1–V12 built + reviewed (370 tests green); the 6 review residuals (R1–R6) and the dev's
own adversarial passes are landed on `fix/policy-engine`. **This handoff is the one remaining cross-plane ask** —
a *new* capability the metering plane (**leria**) depends on. It does **not** touch the existing enforcement
contract.

**Authoritative spec (read this — it's verified against vultrino source, with file:line):**
the leria repo's `docs/_meta/vultrino-integration-handoff.md` (`<workspace>/leria/docs/_meta/vultrino-integration-handoff.md`
in a four-plane workspace checkout).
This doc is the vultrino-team summary; that doc is the detail.

## Why

leria is the OS's metering/FinOps plane (`govder decides · vultrino enforces · averin proves · leria meters`). Its
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

**Latency floor leria must model:** push delivery cadence `OUTBOX_DELIVERY_SECS = 5` plus the poll interval.

**Meter-loss control — be precise (the gap detector does NOT cover everything).** The fail-open `emit_event`
(`src/server/mod.rs:1257`) swallows an `append_event` failure, so a dropped meter event is **silent**. There are two
distinct loss modes and they need **different** controls:

- **Lost-in-transit delivery → leria's sequence-gap detector catches it.** A minted event whose *delivery* is lost
  leaves a hole in the gap-free replayed sequence; leria detects the hole and raises a stale signal.
- **Swallowed `append_event` → the gap detector CANNOT see it.** The monotonic sequence is minted **inside**
  `append_event` → `push_event` (`src/storage/file.rs`), i.e. **only on success**. A swallowed append mints **no**
  sequence, so the stored stream stays **contiguous** — there is no hole to detect. Sequence-gap detection is
  therefore **not** the compensation for a swallowed append. (An earlier draft of this handoff implied it was; that
  was an overclaim, corrected here and in leria's `vultrino-integration-handoff.md` / `06-integration-architecture.md`.)

The swallowed-append / sustained-outage case is mitigated **leria-side** by **`on_meter_stale=deny`
stale-detection** (now the author-time DEFAULT for leria's real-time soft `usd`/`tokens` budgets): vultrino keeps
admitting actions while leria's meter watermark freezes → leria signals a **precautionary Deny**. An **occasional**
drop is reconciled later by the authoritative source (invoice / `period_complete`). None of this makes the fail-open
emit "closed": an out-of-band meter permits a **bounded overshoot** that an outage widens — only `hard`-ceiling mode
(in-path tokens, **v1-deferred** on the leria side) is zero-overshoot. The fail-open emit stays correct for
`/execute` availability; leria **mitigates**, it does not eliminate the bounded window.

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
V4 principal (`agent_label`/id) is on the `RequestContext`.

---

## V13b — LANDED (non-streaming-only v1) — branch `feat/v13a-leria-metering`

**What shipped.** For an **admitted, non-streamed** `/execute` whose response carries a parseable provider usage
block, `run_action` now emits a **second** `meter.observed` event — the token-count observation leria prices into
usd — alongside the V13a `api-calls=1` event for the same call. A response with **no** parseable usage block (a
streamed response without a usage trailer, or any non-LLM action) emits **only** the V13a event.

### The shape — what leria PRICES (not the handoff's literal `asset=tokens`)

Reconciled against leria's **actual code**, not prose:

- `internal/ingest/pipeline.go` `WireEvent`: `Tokens *TokenSplit` "when present on a gateway-observed event with
  **asset=usd**, requests rate-card pricing; **dims.model_ref** selects the card."
- `internal/ingest/pipeline.go` `resolveAmount`: a `Tokens`-bearing event must have `asset == usd`, must **not**
  carry an `amount` (else `ambiguous_amount` rejection), and is priced via the rate card (leria mints the usd-micros
  + pins `rate_card_version`).
- `internal/ratecard/ratecard.go` `TokenUsage{InputTokens, OutputTokens}` is the priced input.

So vultrino emits the token event as (`crate::outbox::meter_tokens_payload`):

- `asset = "usd"` (the pricing trigger — **NOT** `tokens`; `asset:tokens` would skip pricing),
- `tokens = { input_tokens, output_tokens }` as **integers** (the counts; vultrino sends counts, NOT dollars),
- **no `amount`** key (a priced token event must not carry one; leria mints it),
- `dims.model_ref = <model>` (selects the rate card),
- the **same** `correlation_id` (the `/execute` `request_id`) as the V13a event — the occurrence handle that threads
  both observations onto the same call — but a **DISTINCT** `event_id` of `<request_id>:tokens`. The two events share
  the credential (so the same dedup `source_id`); a colliding `event_id` carrying a different resolved amount (the
  V13a event is `amount=1`, the token event is priced usd) would be classified a **dup-mismatch (disputed)** by
  leria's namespaced `(source_id, event_id)` dedup and **dropped** — so the token event MUST use a distinct `event_id`,
- `cost_source = "gateway-observed"`, `confidence = "low"`, `dims.tenant` (V11) + `dims.credential`,
- **no `currency`** (usd is leria's single-base default; a non-usd value is rejected).

leria converts `(input,output) → usd-micros` via its `RateCard` and pins the version; **no pricing logic enters
vultrino** (the V3 boundary — vultrino holds no cumulative/usd state).

### Parsing — RAW body, BEFORE scrub (Gate 2)

The usage read (`crate::outbox::parse_token_usage`) runs in `run_action` **immediately after `plugin.execute`** and
**before `crate::egress::scrub_response`**, on the **raw** `response.body`. Scrub redacts / withholds / replaces the
body; reading post-scrub would see redacted bytes and **under-count** — the dangerous direction (a low count keeps
leria's cumulative ceiling below its limit → budgets never fire → unbounded spend). The **emit** still happens
post-scrub at the existing V13a hook; only the *read* is moved earlier. Two provider shapes are recognized, both
nested under top-level `usage`:

- **OpenAI-style:** `usage.{prompt_tokens, completion_tokens, total_tokens}` → input=`prompt_tokens`,
  output=`completion_tokens`.
- **Anthropic-style:** `usage.{input_tokens, output_tokens}` → input/output direct.

`model` is taken from the response body (`model`, the model the provider actually served), falling back to a `model`
field in the request params; if neither is present the token event still emits, just without `dims.model_ref` (leria
then fails the usd pricing closed for that call). Best-effort, off the latency path, **counts + model only** — no
prompt/body/secret is read or retained.

### v1 LIMITATION — non-streaming-only (stated)

vultrino buffers response bodies whole and has **no SSE/streaming awareness** (Gate 1), and OpenAI omits the `usage`
object from a *streamed* completion unless the client sets `stream_options.include_usage` — which vultrino neither
requires nor injects. So **token-level gateway-observed confidence is non-streaming-only**: a streamed LLM call
emits only the V13a `api-calls=1` event, and leria must fall back to a lower-confidence source
(provider-usage-api / invoice) for that call's token count. Gates 1a (SSE handling) and 1b (the
`stream_options.include_usage` injection decision) remain open and are the prerequisites for streamed-token support;
they are **out of scope** for this v1.

**Acceptance — all met** (`tests/approval_token_integration.rs`, `test_v13b_*`; plus `src/outbox.rs` unit tests
`test_parse_token_usage_*`, `test_extract_model_*`, `test_meter_tokens_payload_*`): OpenAI-style usage emits a 2nd
`meter.observed` with `asset=usd` + `tokens{input,output}` + `dims.model_ref` + `correlation_id` == the V13a event;
Anthropic-style usage parsed; no usage block → only the V13a event; the token read is from the **raw** body (an
egress redact rule that rewrites the agent-visible digits still yields the correct count — the pre-scrub read);
denied action → no events; and the emitted shape decodes into a strict mirror of leria's `WireEvent` token path
(`asset=usd`, `amount=0`, `tokens` split, `dims.model_ref`).
