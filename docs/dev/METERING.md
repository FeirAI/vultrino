# Usage Metering Emit (V13a / V13b)

Vultrino emits `meter.observed` usage events onto its signed event outbox so a
metering/FinOps consumer can see real-time, gateway-observed spend. This is the
emit side only: **Vultrino holds no cumulative spend state, no pricing, and no
budgets** — it emits raw observations (ids + counts). Verified against
`src/outbox.rs` (payload builders + parsing) and `src/server/mod.rs` (`run_action`
emit sites).

This capability is **standalone-useful**: any consumer that polls
`GET /api/v1/events` (or receives the push delivery) gets a signed, ordered,
gap-free stream of per-call usage. The cross-plane integration with the leria
metering plane is described in [INTEGRATION.md](INTEGRATION.md); the wire shape is
the same either way.

## When it fires

On every **admitted** `/execute` (policy allow + credential injection happened and
the action executed), `run_action` emits exactly **one** V13a `meter.observed`
event. A **denied** action emits none (the emit is on the post-admission path a
denial never reaches). Both the immediate path and the post-approval
`resume_approved` path funnel through `run_action`, so an admitted action is
metered exactly once however it was admitted.

The emit is **off the latency path and fail-open**: it rides `emit_event`, which
swallows outbox-append failures (logs a `warn!`, "never fails the calling
operation"). A consumer/outbox outage does **not** block or fail `/execute`.

The event carries **no secrets/PII** — ids + a count only. It is test-asserted
that the credential secret string and the response body never appear in the
serialized event.

## V13a — the per-call `api-calls` observation

Built by `crate::outbox::meter_observed_payload`. Event type constant:
`EVENT_METER_OBSERVED = "meter.observed"`. The payload (snake_case fields,
kebab-case enum values):

```json
{
  "event_id": "<request_id>",
  "correlation_id": "<request_id>",
  "principal": "agent_refund_bot_v3",
  "asset": "api-calls",
  "amount": 1,
  "cost_source": "gateway-observed",
  "confidence": "low",
  "occurred_at": "2026-06-20T12:00:00Z",
  "dims": { "tenant": "acme", "credential": "github-api" }
}
```

| Field | Source |
|-------|--------|
| `event_id` | The `/execute` request id — the producer-supplied dedup key (a replay of the same request dedups). |
| `correlation_id` | The same request id — the per-occurrence join handle. |
| `principal` | The V4 `agent_label`, falling back to the `vk_`/`vut_` principal id, then the credential alias. |
| `asset` / `amount` | Constant `api-calls` / `1` (an integer — one metered call). |
| `cost_source` | Constant `gateway-observed` (Vultrino's tier). |
| `confidence` | Constant `low` (the gateway-observed data-quality band). |
| `occurred_at` | The action's request timestamp. |
| `dims` | `tenant` (V11) + `credential` alias; absent keys omitted (no phantom dims). `model` is **always omitted** for V13a — it does not parse the body. |

V13a reads **no body bytes** (a count of 1), so it emits *after* `scrub_response`
safely.

## V13b — the token-count observation

For an admitted `/execute` (buffered) or LLM-proxy stream whose response carries a
parseable provider usage block, the metering path emits a **second** `meter.observed`
event (the token observation) alongside the V13a event for the same call, via the
shared `emit_meter`. A response with no parseable usage block (a streamed response
whose client suppressed the usage trailer, a truncated/halted stream, or any non-LLM
action) emits **only** the V13a event.

Built by `crate::outbox::meter_tokens_payload`:

```json
{
  "event_id": "<request_id>:tokens",
  "correlation_id": "<request_id>",
  "principal": "agent_refund_bot_v3",
  "asset": "usd",
  "tokens": { "input_tokens": 120, "output_tokens": 34 },
  "cost_source": "gateway-observed",
  "confidence": "low",
  "occurred_at": "2026-06-20T12:00:00Z",
  "dims": { "tenant": "acme", "credential": "github-api", "model_ref": "gpt-4o" }
}
```

Key facts (each load-bearing for the consumer's pricing):

- `asset = "usd"` with a `tokens` split — **not** `asset = "tokens"`. Vultrino
  sends the **counts**, never dollars; the consumer mints the usd amount from the
  counts via its rate card. (`asset:tokens` would skip pricing.)
- **No `amount` key** — a priced token event must not carry one (the consumer
  mints it from the tokens). Its absence decodes to 0.
- `event_id` is `<request_id>:tokens` — a **distinct** dedup key from the V13a
  event (which uses `<request_id>`), so the two are not a dup-mismatch under a
  namespaced `(source, event_id)` dedup. They share the same `correlation_id` (the
  occurrence handle threading both observations onto the same call).
- `dims.model_ref` selects the rate card. Omitted (no phantom dim) when the model
  is unknown — the token event still emits, just without `model_ref`.
- No `currency` field (usd is the consumer's single-base default).

### Parsing — RAW body, BEFORE scrub

`crate::outbox::parse_token_usage` runs in `run_action` **immediately after
`plugin.execute` and before `egress::scrub_response`**, on the raw response bytes.
Scrub redacts/withholds/replaces the body; reading post-scrub would see redacted
bytes and **under-count** — the dangerous direction (a low token count keeps a
cumulative ceiling below its limit → budgets never fire → unbounded spend). The
*emit* still happens post-scrub at the V13a hook; only the *read* is moved earlier.

Two provider shapes are recognized (both nested under top-level `usage`):

- **OpenAI-style:** `usage.{prompt_tokens, completion_tokens}` → input/output.
- **Anthropic-style:** `usage.{input_tokens, output_tokens}` → input/output.

Negative/float/oversized counts are rejected (`as_u64`), and a body missing a
recognized count pair yields no token event. The `model` is taken from the
response body's `model` (the model the provider served), falling back to a `model`
field in the request params.

### Streamed token metering

A `{"stream": true}` LLM-proxy call is metered too. The streaming adaptor tees each
RAW (pre-scrub) SSE chunk to a `crate::outbox::UsageAccumulator`, which line-buffers
across chunk boundaries and reads the token counts + model from the **top level** of
each recognized `data:` event (never a substring scan, so a prompt that literally
contains a `usage` object can't forge a count). On a **clean** end the parsed split
is emitted as the V13b token event — identical shape to the buffered path. Three
wire shapes are recognized:

- **OpenAI chat** (`stream_options.include_usage`): a terminal `data:` event with
  top-level `usage.{prompt_tokens, completion_tokens}` and `choices: []`. To make the
  provider emit it, vultrino injects `stream_options.include_usage = true` when the
  request streams and the client did **not** set it (an explicit client value — true
  OR false — is honored). Gated by `[llm_proxy] inject_stream_usage` (default on).
- **OpenAI responses**: `response.completed` carries `response.usage.{input_tokens,
  output_tokens}`.
- **Anthropic messages**: `message_start` → `message.usage.input_tokens`;
  `message_delta` → `usage.output_tokens` (**cumulative** → last value wins, never
  summed). Anthropic / responses report usage natively, so no injection is done.

**Honest bound:** V13a `api-calls=1` always fires (including on a halt or client
disconnect). V13b fires only on a clean end with a parsed usage split — a client that
sets `include_usage:false`, or a truncated/halted stream, meters V13a only (emitting
partial counts would under-count, the dangerous direction). A capability with an
operator `block`/`redact_patterns` egress rule, or a compressed response, is served
buffered (the incremental scrubber can't honor whole-body regex/block), so its
metering follows the buffered path.

## Consuming the feed: poll or push

The outbox is **single-subscriber for push** — one `[outbox] url` + `hmac_secret`.
There is **no push fan-out**. A second consumer (e.g. a metering plane that isn't
the push target) **polls** `GET /api/v1/events?after=N&limit=M` (admin-gated). The
`meter.observed` events live in the same monotonic event log the replay endpoint
serves — appended under the storage lock, gap-free by `sequence` — so a poller
reads them gap-free, and the poll path returns the same `delivery_body` +
`Govder-Signature` envelope a push delivery carries (so a replayed event is
verified exactly like a pushed one).

**Latency floor to model:** push delivery cadence `OUTBOX_DELIVERY_SECS = 5` plus
your poll interval.

## Honest bounds of the meter-loss guarantee

There are **two distinct loss modes**, and the gap detector covers only one:

- **Lost-in-transit delivery** → a minted event whose *delivery* is lost leaves a
  hole in the gap-free replayed sequence; a consumer's sequence-gap detector
  catches it.
- **Swallowed `append_event`** → the fail-open emit swallows an append failure.
  The monotonic sequence is minted **inside** the append (only on success), so a
  swallowed append mints **no** sequence and the stored stream stays contiguous —
  **there is no hole to detect.** Sequence-gap detection is therefore **not** the
  compensation for a swallowed append.

The swallowed-append / sustained-outage case must be mitigated **consumer-side**
(e.g. stale-watermark detection that fires a precautionary `Deny` when the meter
freezes), and reconciled later by the authoritative source (invoice). None of this
makes the fail-open emit "closed": an out-of-band meter permits a **bounded
overshoot** that an outage widens — only an in-path hard ceiling (not built in
Vultrino's v1) is zero-overshoot. The fail-open emit stays correct for `/execute`
availability; the consumer **mitigates** but does not eliminate the bounded window.

## What stays out of Vultrino (the boundary)

Pricing/rate-cards, `tokens → usd` conversion, the ledger, budgets,
reconciliation, and **any cumulative spend state** are **not** Vultrino's — they
belong to the metering plane. Budget enforcement comes *back* to Vultrino as a
pushed `Deny` policy via the admin API (V1) targeting a credential/principal — the
existing enforcement path, no new metering code. Vultrino emits the raw real-time
observation; that is the whole of its metering responsibility.
