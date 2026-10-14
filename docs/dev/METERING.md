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

The emit is **off the latency path and fail-open**: a failed outbox append (logs a
`warn!`) never fails the calling operation, and a consumer/outbox outage does **not**
block or fail `/execute`. A failed append is **counted**, though: see "Failed appends
are counted and announced" below.

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
shared `emit_meter`. A buffered response with no parseable usage block (or any non-LLM
action) emits **only** the V13a event. A streamed LLM call whose usage block never
arrives (a truncated or halted stream, a cap hit, an NVIDIA tool stream) is charged an
**estimate** instead, marked `dims.estimated = "true"` (see below).

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
is emitted as the V13b token event - identical shape to the buffered path. A stream
whose usage block was not final (see below) is charged an estimate instead. Three
wire shapes are recognized:

- **OpenAI chat** (`stream_options.include_usage`): a terminal `data:` event with
  top-level `usage.{prompt_tokens, completion_tokens}` and `choices: []`. To make the
  provider emit it, vultrino injects `stream_options.include_usage = true` when the
  request streams (a client `false` is **overwritten**: the flag is gateway-owned, so a
  client cannot opt out of token metering). Gated by `[llm_proxy] inject_stream_usage`
  (default on).
- **OpenAI responses**: `response.completed` carries `response.usage.{input_tokens,
  output_tokens}`.
- **Anthropic messages**: `message_start` → `message.usage.input_tokens`;
  `message_delta` → `usage.output_tokens` (**cumulative** → last value wins, never
  summed). Anthropic / responses report usage natively, so no injection is done.

**What is charged when the stream does not finish cleanly (VUL-01).** V13a
`api-calls=1` always fires. V13b is always attempted too:

- **Client hangs up before the trailer.** The producer keeps reading the upstream,
  forwarding nothing, until the final usage block arrives, under the same idle, total
  and byte caps as a live stream. The charge is then the provider's exact count.
- **Anthropic's provisional count.** `message_start` carries `input_tokens` and a
  provisional `output_tokens`; only the final `message_delta` count is treated as
  complete. A stream that stops before it is charged an estimate, never the
  provisional 1.
- **No trailer at all** (the drain hit a cap, a truncated stream, an upstream error,
  NVIDIA tool streams, a halted agent). The charge is an **estimate** and the token
  event carries `dims.estimated = "true"`: input is the provider's count if one was
  parsed, else the request body size over 3 bytes per token; output is the larger of
  the provider's partial count and the generated text received over 3 bytes per
  token (at least 1), capped by the request's own `max_tokens`-style limit. Three
  bytes per token over-estimates typical text on purpose. leria ingests and prices an
  estimated event like any other and keeps the marker on the ledger entry; the
  authoritative bill still reconciles it.
- **A halt does not drain, before or after a hang-up.** A halted agent's upstream is
  closed, which stops generation, and the call is charged an estimate. This holds
  when the halt lands while the producer is still forwarding and also when it lands
  while the producer is draining after the client left: the drain watches the
  session's abort signal first and stops at once.
- **Bounds of the estimate.** Output is counted from text under `delta` keys, so a
  provider that streams text elsewhere (for example Gemini `candidates[].content.parts`)
  estimates low, hidden reasoning tokens are not in the byte count, and a provider
  that reports a cumulative usage block on every chunk is read as complete on the
  first one. OpenAI and Anthropic shapes are covered; today only requests with
  `stream: true` take this path.
- **No request model.** A token event needs a model to select leria's rate card, so a
  stream with no model in the request or the stream meters V13a only.

A capability with an operator `block`/`redact_patterns` egress rule, or a compressed
response, is served buffered (the incremental scrubber can't honor whole-body
regex/block), so its metering follows the buffered path.

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
- **Failed `append_event`** → the fail-open emit does not fail the action. The
  monotonic sequence is minted **inside** the append (only on success), so a failed
  append mints **no** sequence and the stored stream stays contiguous - **there is no
  hole to detect.** Sequence-gap detection is therefore **not** the compensation for
  a failed append; the `meter.lost` marker below is.

### Failed appends are counted and announced (VUL-02)

Every failed outbox append increments an in-memory counter and remembers the first
and last failure time and the event type. The counters are on `GET /api/v1/health`
(`meter_lost_total`, `meter_gap_pending`), `GET /api/v1/ready` (`meter_gap_pending`)
and `GET /api/v1/posture` (`meter.*`). On the **next successful append** the outbox
writes one `meter.lost` event right after it, with payload
`{lost_count, first_lost_at, last_lost_at, event_types}` (no body, no secret); if that
marker append itself fails the counts are kept and it is retried on the following
success. While failures are still pending, `GET /api/v1/events` also reports the
pending count as `meter_gap_pending` on the response envelope (next to `events` and
`next_cursor`), so a poller can tell an idle feed from one that is dropping events
during the outage itself; leria freezes its `as_of` watermark while it is non-zero, and
govder's activity feed reads the same count and treats its watched agents as acting, so the
meter-stale Deny can fire during the outage (a frozen `as_of` alone cannot: no activity is
reported while appends fail). The envelope is not signed. A consumer that meters from the feed
treats the marker as "usage may be missing": leria (`gatewaypoll`) freezes its `as_of` watermark
for a hold-down period so govder's meter-stale Deny stays in force through the recovery. The counters live in memory: if the process
dies before an append succeeds again, no marker is written, and only a stale watermark
remains as the signal.

An out-of-band meter still permits a **bounded overshoot** that an outage widens -
only an in-path hard ceiling (not built in Vultrino's v1) is zero-overshoot. The
fail-open emit stays correct for `/execute` availability; the consumer **mitigates**
but does not eliminate the bounded window, and the authoritative source (invoice)
reconciles the rest.

## What stays out of Vultrino (the boundary)

Pricing/rate-cards, `tokens → usd` conversion, the ledger, budgets,
reconciliation, and **any cumulative spend state** are **not** Vultrino's — they
belong to the metering plane. Budget enforcement comes *back* to Vultrino as a
pushed `Deny` policy via the admin API (V1) targeting a credential/principal — the
existing enforcement path, no new metering code. Vultrino emits the raw real-time
observation; that is the whole of its metering responsibility.
