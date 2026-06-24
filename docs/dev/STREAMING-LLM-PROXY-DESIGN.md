# Vultrino SSE / Streaming LLM-Proxy — Design & Phased Implementation Plan

> **Status:** Proposed (design only, not yet implemented). Produced 2026-06-23 from a
> multi-lens design workshop (transport · incremental egress · streamed metering · API
> compatibility · adversarial security · testing) + an adversarial critic pass, each
> grounded against the real code. All lens contradictions and the critic's must-resolve
> items are decided below with a definitive call; where a call overrides a lens, the
> one-line "why" follows it.

**Scope guard (DECIDED):** `GET /v1/models`, inbound query-string forwarding, and
multi-capability-as-error are **OUT of scope** for the streaming PR — each is an
independent behavior/security change that inflates the review surface. Tracked as a
follow-up (§10). The one compatibility fact the streaming PR must *honor* is per-provider
request-header injection (Anthropic `x-api-key` + `anthropic-version` vs OpenAI `Bearer`) —
verified as a precondition in P0 (§7), not changed here.

---

## 1. Goal & product UX

**Drop-in promise:** an app points any OpenAI/Anthropic-compatible client's `base_url` at
vultrino's `/llm` endpoint and uses a vultrino key (`vut_…` use-token or `vk_…` API key) as
its API key. Vultrino injects the real provider credential server-side; the agent never sees
it. Streaming completions now flow through **incrementally** (true SSE passthrough), not
buffered-then-dumped.

**Trigger (DECIDED):** streaming engages purely on the wire flag `request_body["stream"] ==
true`, and the **global default is ON** (one operator kill-switch `[llm_proxy]
streaming_enabled`, default `true`). *Why:* the headline goal is "point a client at vultrino
and it streams"; a default-off switch would silently buffer an SSE upstream into one delayed
mega-frame and break SDK parsers — worse than not shipping. There is **no per-capability
opt-in** (the capability already scopes which provider the key reaches). When
`streaming_enabled=false`, a `stream:true` request must still *work*: strip the stream flags
so the upstream returns JSON, then take the buffered path.

**Supported endpoints/paths (v1):** `POST` only, host+prefix-contained by the capability's
`provider_base`, exactly as today. Streaming applies to whichever of these the provider
frames as `text/event-stream`:
- OpenAI `POST /v1/chat/completions` (and `/v1/completions`)
- OpenAI `POST /v1/responses`
- Anthropic `POST /v1/messages`

Embeddings / model-list / non-stream calls keep the existing buffered path + V13b metering
verbatim.

**Client config snippets:**

```python
# OpenAI Python SDK
from openai import OpenAI
client = OpenAI(base_url="https://gw.example.com/llm/v1", api_key="vut_…")
for chunk in client.chat.completions.create(
        model="gpt-4o", stream=True,
        messages=[{"role":"user","content":"hi"}]):
    print(chunk.choices[0].delta.content or "", end="")
```

```python
# Anthropic Python SDK
from anthropic import Anthropic
client = Anthropic(base_url="https://gw.example.com/llm", api_key="vut_…")
with client.messages.stream(model="claude-3-5-sonnet-20241022",
        max_tokens=256, messages=[{"role":"user","content":"hi"}]) as s:
    for text in s.text_stream: print(text, end="")
```

```yaml
# LiteLLM (proxy config or SDK)
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_base: https://gw.example.com/llm/v1
      api_key: vut_…
# stream=True on the completion call flows through unchanged.
```

> Note on the `/v1` convention: the OpenAI SDK appends `/v1/...` only if `base_url` does not
> already end in `/v1`. Point it at `…/llm/v1` for OpenAI; the Anthropic SDK appends
> `/v1/messages` to a bare `…/llm`. The capability's `provider_base` must contain the matching
> prefix.

---

## 2. Architecture

### 2.1 Gate/run split — reuse `execute_gated` verbatim

`execute_gated` (`src/server/mod.rs` ~375) does **all** gating before anything runs and is
**not** duplicated. We add a sibling tail, not a second gate.

- Refactor `execute_gated`'s gating body into a private `gate(&self, req, auth) ->
  Result<GateDecision, …>` returning `{credential, plugin, action, needs_approval,
  meter_attribution, secret_material}`. Both `execute_gated` (buffered) and the new
  `execute_gated_streaming` call **the same `gate()`**. Approval → `Pending` returns
  identically *before any byte is fetched* (the streaming branch must never open an SSE body
  before the gate decision is known).
- `run_action_streaming` mirrors `run_action`'s preamble **verbatim** up to the plugin call:
  `validate_params` preflight (no token burn) → `consume_use_token` (fail-closed,
  exactly-once **point of no return, stays before the first byte**) → capture
  `meter_principal`/`meter_occurred_at`/`meter_tenant`/`credential_alias`/`request_id` →
  `SessionGuard begin`. Only the post-plugin half differs.

**Why a new plugin method, not a web-layer streaming reqwest:** every irreversible
side-effect (token consume, SessionGuard, vault credential injection, OAuth-refresh persist,
V13a emit, SSRF guarded client) must stay inside one server-owned gated execution.
Re-opening a reqwest call in `llm_proxy.rs` would reimplement all of these — the classic
bypass surface. Rejected.

### 2.2 Plugin trait change

Add **one** default method to the `Plugin` trait (`src/plugins/mod.rs`):

```rust
async fn execute_streaming(&self, request: PluginRequest)
    -> Result<StreamingResponse, PluginError> {
    // default: buffer via execute(), wrap as a single-chunk stream
    let r = self.execute(request).await?;
    Ok(StreamingResponse::from_buffered(r))
}
```

A default impl means hmac/ecdsa/ssh/postgres and the existing test `MockLlmPlugin` compile
untouched (backward-compat). Only `HttpPlugin` overrides it.

### 2.3 `StreamingResponse` and the http plugin

```rust
pub struct StreamingResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, PluginError>> + Send>>,
    pub updated_credential: Option<CredentialData>,
}
```

`HttpPlugin::execute_streaming` uses the **same** `build_guarded_client()` (redirect::none,
`SsrfGuardResolver`, `validate_url_ssrf`, `force_client_managed_encoding`, credential
injection). After `.send().await`, status + headers + `updated_credential` are known
**before** the body — so a pre-stream non-2xx JSON error (content-type `application/json`,
not event-stream) is detected and buffered with the correct status. The body becomes
`response.bytes_stream()` (requires reqwest `stream` feature) mapped to `PluginError`. *No new
connection is opened per chunk → no new DNS-rebinding window; the connect-time
`SsrfGuardResolver` and redirect::none still apply (explicit test in P1).*

### 2.4 SessionGuard spans the stream (critic blocker #2 — DECIDED)

The `SessionGuard` (`src/session.rs:112`, today drops at `run_action`'s frame end) is **moved
into the returned stream adaptor's state**, so its `Drop` fires at last-byte / error /
client-disconnect / abort — exactly when in-flight stream work ends. The V6 registry then
reflects genuinely live streams.

**Per-session abort is NEW plumbing** (the lenses assumed it exists; it does not — halt leg 3
is a global fire-and-forget `Vec<Arc<dyn HaltCallback>>` over `for_halt_target`'s returned
`Vec<SessionEntry>`, with no way to cancel a specific `session_id`). We add:

- `SessionEntry` gains an `abort: Arc<tokio::sync::Notify>` (chosen over
  `tokio_util::CancellationToken` to avoid a new dep; over `watch` for ergonomic `notified()`
  in `select!`).
- `SessionRegistry::begin` returns `(SessionGuard, Arc<Notify>)`.
- New `SessionRegistry::signal_halt(target: &str)`: for each entry matched by the **existing**
  `for_halt_target` predicate, call `entry.abort.notify_waiters()`.
- `halt_agent` (`src/server/mod.rs:1558`) calls `self.sessions.signal_halt(label)` **in
  addition to** the existing `HaltCallback` fire (coexist — the callbacks serve external
  harness integrations; do not replace).

The stream adaptor `select!`s between the next upstream chunk and `abort.notified()`. On
abort: stop pulling upstream, emit one terminal generic SSE `error` event, run the
**V13a-only** finalizer (§4), drop the guard. Cancellation latency is bounded by one chunk.

### 2.5 The stream adaptor & metering emit (critic blocker #1 — DECIDED)

**"Emit from `Drop`" is mechanically impossible:** `emit_event` is `pub async fn
emit_event(&self, …)` (`src/server/mod.rs:1268`) — async, borrows `&self` (server/outbox);
`SessionGuard` holds only `Arc<SessionRegistry>`. A sync `Drop` cannot await it.

**Resolution:**
1. Refactor the emit block (`src/server/mod.rs:877–937`) into a **free async fn**
   `emit_meter(outbox: Arc<Outbox>, attr: MeterAttribution, usage: Option<TokenUsage>, model:
   Option<String>)` that calls the **same** `meter_observed_payload` / `meter_tokens_payload`
   builders. Both `run_action` (buffered) and the stream finalizer call it → the two paths
   cannot drift.
2. `run_action_streaming` captures `MeterAttribution { request_id, meter_principal,
   meter_occurred_at, meter_tenant, credential_alias }` **plus a cheap `Arc` clone of the
   outbox handle**, and moves them into the stream adaptor.
3. The adaptor is a `futures::Stream` whose **poll-completion** (upstream `Ready(None)`, error,
   or abort branch) runs an inline async finalizer (`emit_meter`) — emit lives in
   poll-completion, **not** `Drop`.
4. For the **client-disconnect** path (axum drops the body, poll-completion never runs): the
   adaptor's `Drop` does `tokio::spawn(emit_meter(...))`, guarded by an `AtomicBool
   already_emitted` (shared with the poll-completion path) so V13a fires **exactly once** on
   whichever path wins. The spawned task holds the `Arc<Outbox>` so it can await.

### 2.6 Body wiring (web layer)

`llm_proxy_impl`: after parsing `request_body`, branch on `request_body.get("stream") ==
Some(&Value::Bool(true))` **and** `streaming_enabled`. If both → `execute_gated_streaming` →
an axum `Body::from_stream(adaptor)` response, preserving the provider `Content-Type`
(`text/event-stream`). Else → existing buffered `execute_gated` branch (when
`streaming_enabled=false` but `stream:true`, strip stream flags first so upstream returns
JSON). Pre-stream errors keep the existing generic-withholding behavior (no `{e}` /
upstream-body leak — scrub has not run on the `Err` path).

---

## 3. Incremental egress scrub

### 3.1 The carry-buffer algorithm (precise; DECIDED)

`StreamScrubber` in `src/egress.rs` reuses the **exact** form set the buffered redactor
builds. **Mandate:** extract the form-derivation loop from `redact_secret_material` into a
single shared `derive_secret_forms(secrets) -> Vec<String>` (raw + `urlencoding::encode` +
json-escaped-inner, filter `< MIN_REDACT_LEN`=5, dedup, **sort longest-first**) used by
**both** the buffered redactor and `StreamScrubber`. A parity test asserts identical form
sets — a divergence here is a silent secret-leak vector.

```rust
pub struct StreamScrubber {
    forms: Vec<Zeroizing<String>>,   // longest-first, all >= MIN_REDACT_LEN
    marker: String,                  // [REDACTED:alias]
    carry: Vec<u8>,
    max_form_len: usize,             // = longest BYTE len over ALL forms (0 => pass-through)
}
```

- **`CARRY = max_form_len - 1`**, where `max_form_len` = longest byte length over **all** forms
  (raw, percent-encoded, json-escaped). *Why the encoded form, not raw:* the percent/json form
  can be longer than the raw secret; sizing carry off the raw length alone leaks the encoded
  form at a boundary.
- **`push(chunk)`**: append `chunk` to `carry`; run non-overlapping `replace_bytes` over the
  whole working buffer for every form (longest-first); split off and **emit all but the
  trailing `CARRY` bytes**; retain the trailing `CARRY` as the new carry. Re-scanning the
  retained tail next round is safe/idempotent because the marker `[REDACTED:alias]` cannot
  contain a secret form.
- **`finish()`**: run the forms over the residual carry and emit it fully (flushes a trailing
  partial secret).
- **Bound:** a hard cap on `carry` + a max-SSE-line cap so a delimiter-less multi-GB line trips
  a limit (fail closed) instead of OOMing. Carry is `Zeroizing` so a secret fragment isn't left
  in a freed buffer on halt/abort.

Cost is `O(total_bytes × num_forms)` (tiny fixed form set), no O(n²) rescan. If `max_form_len
== 0` (no scrubbable secret ≥ 5 chars), the scrubber is pass-through — matches buffered
behavior; surface a `has_unredactable_secret` config warning.

### 3.2 Compressed / block-rule handling — header-only, pre-body, fail-closed

`block_if_compressed` and operator `block` / `redact_patterns` are **whole-body** concepts.
Decide them from the response **headers before the first byte**:

- **Compressed** (residual non-identity Content-Encoding/Transfer-Encoding): do **not** stream
  — return the existing withheld placeholder (cleared headers, `text/plain`), exactly as
  buffered.
- **Operator `block` rule** matching `(alias, action)`: do not stream — buffer-then-withhold
  (the whole body is secret-bearing; any flushed byte is a leak).
- **Operator `redact_patterns` (arbitrary regex)** matching `(alias, action)`: **fall back to
  the buffered path.** *Honest limitation:* arbitrary regex can match across an unbounded
  span; no finite carry guarantees correctness, so incremental regex would under-redact at
  chunk seams (a fail-open leak). We refuse to ship that. Only the always-on **literal
  credential-secret scrub** runs on the true streaming path.

Add `egress::stream_is_egress_safe(rules, alias, action) -> bool` (false if any matching rule
has `block` or non-empty `redact_patterns`) + the header compression check. When unsafe,
`execute_gated_streaming` routes to the **buffered** `run_action` so `apply_egress` + V13b run
unchanged.

**Honesty note (DECIDED):** when a `stream:true` request falls back to buffered for these
capabilities, the agent's SDK gets a buffered `text/event-stream` blob. This is the safe
trade. We document it; we do **not** add a "served-buffered" signal in v1 (no
provider-compatible header exists). Operators are warned at config load when a
streaming-intended capability carries a `block`/`redact_patterns` rule.

### 3.3 Header scrub on the streaming path (DECIDED — real regression closed)

Today `scrub_response` redacts secrets from **headers** too. In streaming the response head
commits to the wire **before any body byte**, so a secret reflected in a provider response
header (echo reflectors, `Set-Cookie`, debug headers) would escape entirely. **Mandate:** at
head-build time, run the response headers through `derive_secret_forms` (a
`scrub_headers(headers, forms)` helper) **before** flushing the head, and **strip
`Content-Length` / `Transfer-Encoding`** (redaction changes length; provider framing is
invalid — axum frames from emitted bytes). Preserve `Content-Type` (`text/event-stream`)
verbatim — not secret-bearing, and the SDK's SSE parser needs it. HTTP/2 trailers: confirm
axum/reqwest expose them on the streaming path; if so, scrub identically (tracked, §10).

---

## 4. Streamed token metering (V13b)

### 4.1 `include_usage` injection (DECIDED)

**HONOR an explicit client value; INJECT only when absent.** When `stream==true` and
`stream_options.include_usage` is **absent**, vultrino structurally sets
`stream_options.include_usage = true` (additive merge into the existing `stream_options`
object via serde_json `Value` mutation — never string concat, never dropping sibling fields),
gated by config `inject_stream_usage` (default `true`), **OpenAI-chat shape only**. If the
client explicitly set `true` OR `false`, honor it verbatim. Non-JSON / non-OpenAI bodies pass
through untouched. Anthropic `/v1/messages` and OpenAI `/v1/responses` report usage natively —
**no injection there**.

*Why honor-false over overwrite-false-to-true:* the "evasion" framing is weak. The agent
already pays the V13a `api-calls=1` signal, and credential-reachability/spend **policy**
gating runs at admission **before any tokens** — so `include_usage:false` does not bypass
spend policy, only token-**granularity observability**. Overwriting an explicit client `false`
mutates request semantics an SDK may depend on and risks the drop-in promise.

### 4.2 SSE usage tap (per-provider rules)

New `UsageAccumulator` in `src/outbox.rs` (alongside, not replacing, `parse_token_usage`). It
is fed the **RAW pre-scrub** chunks (see §4.4), line-buffers across chunk boundaries (carry
for a partial `data:`/`event:` line), parses **only** `usage` counts + `model` from the
**parsed-JSON top level** of a recognized event/data line (never a substring scan — defeats a
prompt that literally contains `"usage":{…}`), retains **no** prompt/content, and exposes
`finish() -> (Option<TokenUsage>, Option<String>)`:

- **OpenAI chat:** top-level `usage.prompt_tokens` / `completion_tokens` from the usage-only
  `data:` event (the one with `choices: []`), last-writer-wins (exactly one). `model` from any
  data frame.
- **OpenAI `/v1/responses`:** on `event: response.completed`, read `response.usage.input_tokens`
  / `output_tokens`. (Confirm exact field path against a live fixture, §10.)
- **Anthropic `/v1/messages`:** `input_tokens` from `message_start`
  (`message.usage.input_tokens`); `output_tokens` from the **last** `message_delta`
  (`usage.output_tokens` is **cumulative** → overwrite, take the final value — **never sum**).
  `model` from `message_start`. `message_stop` carries no usage. Ignore `data: [DONE]`.

**Provider flavor is resolved deterministically by the request path/provider, not pure
wire-sniffing** (DECIDED), so an unrecognized shape can't silently yield `None` for the wrong
provider. The accumulator still tolerates all three carriers; the path picks which extractor
is authoritative.

### 4.3 Emit timing (DECIDED)

- **V13a `api-calls=1`** fires **exactly once at stream termination** (clean EOF, error, abort,
  or disconnect) via the §2.5 finalizer + `already_emitted` guard. *Why not at admission:* it
  must stay consistent with the buffered path (post-execute) and must fire even on halt
  mid-stream so a halted agent's call cannot escape metering. It fires regardless of whether
  usage was seen.
- **V13b tokens** fires **only on clean EOF with a parsed usage split**. On
  abort/halt/disconnect/mid-stream-SSE-`error` → **V13a only, skip V13b**. *Why:* a truncated
  OpenAI stream has **no** usage frame at all (terminal-only), so there is nothing to emit;
  emitting partial counts would under-count (the dangerous direction).
- A mid-stream SSE `error` event is a failed turn → V13a-only, even if a usage chunk preceded
  it.

The V13b payload shape is **identical** to buffered (`event_id = "{request_id}:tokens"`,
`correlation_id = request_id`, counts not dollars, `dims.model_ref`,
`cost_source=gateway-observed`, `confidence=low`) so leria prices it identically and its dedup
contract holds.

### 4.4 Tee ordering (DECIDED — hard wiring rule)

The upstream raw chunk fans out: `raw_chunk → UsageAccumulator.push(raw)` **and**
`StreamScrubber.push(raw) → emit_to_agent`. The usage parser reads the **same raw chunk the
scrubber consumes**, **never the scrubbed output** — symmetry with the buffered path (which
reads usage pre-scrub, `src/server/mod.rs ~820`) and avoids under-count if a usage integer
ever collided with a secret form.

---

## 5. Security — consolidated mitigations

| Threat | Streaming break vs buffered | Mitigation |
|---|---|---|
| **SSRF** (redirect-to-IMDS, DNS rebinding) | Could re-open if a different client is built | `execute_streaming` uses the **unchanged** `build_guarded_client()` (redirect::none, `SsrfGuardResolver`, `validate_url_ssrf`, `force_client_managed_encoding`). `bytes_stream()` changes only body consumption, not connection setup; one connection, no per-chunk rebinding window. **Explicit P1 test.** |
| **Secret leak across chunk boundary** | Per-chunk scrub misses a straddling secret | `StreamScrubber` carry = `max_form_len-1` over **all** forms; emit only before the carry window; `finish()` flushes. Shared `derive_secret_forms` + parity test. |
| **Secret reflected in response HEADER** | Head commits before body scrub | `scrub_headers` at head-build time with the same forms; strip `Content-Length`/`Transfer-Encoding`; preserve `Content-Type`. |
| **Compressed / block / regex body** | Incremental scrub blind | Header-only pre-body decision; fail-closed (withhold for compressed/block) or buffered fallback (regex). |
| **Halt bypass via long-lived stream** | Token-revoke gates only next consume; guard dropped at fn return | SessionGuard moved into stream (lives to last byte); new per-session `Notify` + `signal_halt`; adaptor `select!`s on abort; cancel latency ≤ one chunk. |
| **Token-metering under-count** (unbounded spend) | OpenAI omits usage without `include_usage`; truncated stream | Inject `include_usage:true` when absent (config-gated); read usage from provider bytes (agent can't forge into the TLS stream); V13a always fires; V13b only on clean EOF; never zero-fill. |
| **DoS** (slow-loris, infinite stream, giant line) | Buffered path implicitly bounded by full materialization | Idle timeout, total-duration cap, max-total-bytes cap, max-SSE-line / carry-buffer cap; on breach abort upstream + generic SSE error. Conservative configurable defaults. |
| **Error-path leak** | Pre-stream error body / mid-stream error event | Pre-stream non-2xx JSON → generic `BAD_GATEWAY`, no `{e}`/body leak, logged server-side. Mid-stream SSE `error` event passes through the **same** scrubber (not trusted passthrough). |
| **Request-body mutation smuggling** | `include_usage` injection | Structural serde_json `Value` mutation, additive into `stream_options`, gated on `stream==true` + OpenAI chat; non-JSON untouched; no concat. |
| **Exactly-once token consume** | Streamed retry could re-consume | `consume_use_token` stays in pre-stream preflight, before the first byte; unchanged. |

---

## 6. Data / struct changes

- **src/lib.rs** — add `StreamingResponse` (status, headers, `Pin<Box<dyn
  Stream<Item=Result<Bytes,PluginError>>+Send>>`, updated_credential). Not Serialize/Clone.
  Keep `ExecuteResponse` as-is.
- **src/plugins/mod.rs** — `Plugin::execute_streaming` default method (buffered fallback) +
  `StreamingResponse::from_buffered`.
- **src/plugins/http.rs** — `execute_streaming` override (bytes_stream, same guarded client).
- **src/server/mod.rs** — `gate()` extraction; `execute_gated_streaming`;
  `run_action_streaming`; free async `emit_meter(outbox, attr, usage, model)` +
  `MeterAttribution` struct; the stream adaptor type (owns SessionGuard, abort `Notify`,
  `StreamScrubber`, `UsageAccumulator`, `Arc<Outbox>`, `AtomicBool already_emitted`);
  `halt_agent` calls `signal_halt`.
- **src/session.rs** — `SessionEntry.abort: Arc<Notify>`; `begin` returns `(SessionGuard,
  Arc<Notify>)`; `SessionRegistry::signal_halt(target)`.
- **src/egress.rs** — `derive_secret_forms` (shared); `StreamScrubber` (push/finish,
  Zeroizing); `scrub_headers`; `stream_is_egress_safe`.
- **src/outbox.rs** — `UsageAccumulator`; `maybe_inject_stream_usage(&mut Value, enabled)`.
- **src/config.rs** — `[llm_proxy] streaming_enabled: bool = true`, `inject_stream_usage: bool
  = true`, DoS caps (`stream_idle_timeout`, `stream_total_timeout`, `stream_max_bytes`,
  `stream_max_line`).
- **Cargo.toml** — reqwest features add `"stream"` →
  `["json","rustls-tls","gzip","deflate","brotli","stream"]`; dev-dep `proptest`. **Install via
  `sfw cargo …` / verify via `sfw cargo build`** per the global Socket Firewall rule — no bare
  build on the lockfile change.

---

## 7. Phased implementation plan

Each phase is independently shippable + reviewable. Reqwest `stream` + `proptest` land in P0
via `sfw`.

**P0 — Plumbing & preconditions (no behavior change).**
Scope: enable reqwest `stream` (`sfw cargo build`); add `StreamingResponse` + default
`execute_streaming` (buffered wrap); add config flags (default streaming_enabled=true but no
streaming path wired yet → still buffered); **verify the request-header precondition** — the
http plugin must inject the credential-correct auth header per provider (Anthropic `x-api-key`
vs OpenAI `Bearer`), **and** the proxy must forward provider-required non-auth headers
(`anthropic-version`, `anthropic-beta`). ⚠️ Today `llm_proxy_impl` forwards **only**
`Content-Type` (`src/web/llm_proxy.rs:229`), so `anthropic-version` is dropped and Anthropic
calls 400 — block/extend the PR here. Files: Cargo.toml, src/lib.rs, src/plugins/mod.rs,
src/config.rs, src/web/llm_proxy.rs. Tests: existing suite green; a trait-object test that the
default `execute_streaming` returns the same bytes as `execute`. **Acceptance:** builds via
sfw; zero behavior change; header precondition confirmed/fixed.

**P1 — Minimal end-to-end streaming passthrough (no incremental scrub, no metering changes).**
Scope: `gate()` extraction; `execute_gated_streaming` + `run_action_streaming` (preamble
verbatim); `HttpPlugin::execute_streaming` (bytes_stream via guarded client); web-layer
`stream:true` branch → `Body::from_stream`; SessionGuard moved into a minimal adaptor (no
abort yet); pre-stream non-2xx JSON buffered with correct status. For P1 only, scrub runs as a
**whole-buffer-at-end** placeholder so security isn't regressed (or restrict P1 to
capabilities with no scrubbable secret behind a test-only flag) — **do not ship P1 to prod
without P2.** Files: src/server/mod.rs, src/plugins/http.rs, src/web/llm_proxy.rs,
src/session.rs. Tests (oneshot harness + a `MockStreamingPlugin` emitting `text/event-stream`):
SSE frames arrive with `Content-Type: text/event-stream`; `[DONE]` passes verbatim;
guarded-client/SSRF still applies on the streaming path; non-stream request byte-for-byte
unchanged. **Acceptance:** a real client streams through vultrino end-to-end.

**P2 — Incremental egress scrub (security-complete).**
Scope: `derive_secret_forms` shared extraction + parity test; `StreamScrubber` (push/finish,
Zeroizing, bounded carry); `scrub_headers` + framing strip at head-build; `stream_is_egress_safe`
+ compression header check → buffered fallback; carry/line caps. Files: src/egress.rs,
src/server/mod.rs, src/plugins/http.rs. Tests: unit boundary-split per form (raw/pct/json);
finish() flush; pass-through when max_form_len==0; **proptest oracle** `concat(push…+finish())
== redact_secret_material(whole)`; integration `llm_streamed_split_secret_not_leaked` (key
split across two frames); header-reflected-secret scrubbed; compressed/block/regex → buffered
fallback. **Acceptance:** the provider key never reaches the agent on any chunking; parity
test green.

**P3 — Streamed token metering (V13b).**
Scope: free async `emit_meter` + `MeterAttribution` refactor (buffered path switched to call
it — no drift); `UsageAccumulator` (3 carriers); `maybe_inject_stream_usage`; finalizer wiring
(poll-completion + `tokio::spawn`-on-Drop + `AtomicBool` once-guard); V13a-always /
V13b-clean-EOF-only. Files: src/outbox.rs, src/server/mod.rs, src/web/llm_proxy.rs,
src/config.rs. Tests: usage parser per wire shape incl. chunk-split usage JSON + Anthropic
cumulative-overwrite (assert not summed) + `[DONE]` + SSE `error`→None; inject-when-absent /
honor-true / honor-false / no-op-when-non-stream; **invert** the existing limitation test →
`llm_streamed_emits_api_calls_AND_tokens`; disconnect mid-stream → V13a only. **Acceptance:** a
streamed call with usage emits both V13a and V13b identical in shape to buffered.

**P4 — Halt, DoS, multi-provider polish.**
Scope: per-session `Notify` + `signal_halt`; adaptor `select!` on abort + terminal SSE error +
V13a-only finalizer; halt_agent leg; DoS caps enforced; `/v1/responses` + Anthropic extractor
hardening against live fixtures. Files: src/session.rs, src/server/mod.rs. Tests:
`llm_streamed_halt_cancels_midstream` (abort within one chunk, guard deregisters, V13a fired,
no V13b); idle/total/byte/line cap breach → generic SSE error; Anthropic + responses usage
fixtures. **Acceptance:** a V6 halt cancels a live stream within one chunk; caps trip
fail-closed.

---

## 8. Testing plan

- **Unit (src/egress.rs):** boundary-split per form, finish() flush, idempotent carry rescan,
  max_form_len==0 pass-through, `derive_secret_forms` parity (buffered vs scrubber), carry
  hard-cap trips.
- **Unit (src/outbox.rs):** `UsageAccumulator` for all three wire shapes + adversarial
  chunk-splits of `data:`/`event:` lines + Anthropic cumulative-overwrite + SSE `error`→None +
  `[DONE]`; `maybe_inject_stream_usage` matrix.
- **Property (proptest, dev-dep via sfw):** (1) scrubber-equivalence oracle over `(body,
  Vec<split_points>)` with split points forced at **every index inside an embedded secret**,
  asserting `concat(push…+finish()) == redact_secret_material(body)`; (2) usage-parser
  chunk-split oracle.
- **Integration (tests/llm_proxy_integration.rs, oneshot tower harness + `MockStreamingPlugin`):**
  key-scrubbed-from-stream; split-secret-not-leaked; V13a+V13b both fire (replaces
  `llm_streamed_emits_api_calls_only_no_token_count`); halt cancels mid-stream; SSRF guard
  still applies; **backward-compat: non-stream request byte-for-byte unchanged + buffered V13b
  intact.**
- **Backward-compat assertions:** all existing plugins compile with the default
  `execute_streaming`; buffered path emit now routes through `emit_meter` with identical
  payloads (golden-event assertion).

---

## 9. Docs to update

- **docs/dev/LIMITATIONS.md** — delete the "Token metering is non-streaming-only" bullet and
  the deferred "SSE/streaming awareness …" bullet. Add honest residuals: operator
  `block`/`redact_patterns` and compressed responses force buffered fallback; only the literal
  credential scrub runs incrementally; a client setting `include_usage:false` or a truncated
  stream gets api-calls=1 only.
- **docs/dev/METERING.md** — drop the "non-streaming only" qualifier; replace the "v1
  limitation" section with "Streamed token metering" (UsageAccumulator, inject-when-absent,
  V13a-always/V13b-clean-EOF-only, Anthropic cumulative rule).
- **src/web/llm_proxy.rs module doc** — replace the "Honest non-streaming caveat" block with a
  "## Streaming" section (wire-flag trigger, default-on kill-switch, incremental scrub, header
  scrub, V13b-on-stream, honest residual).
- **README.md** — add a "Streaming LLM proxy" feature line.

---

## 10. Open questions / explicit non-goals for v1

**Non-goals (v1):**
- GET `/v1/models`, inbound query-string forwarding, multi-cap-as-error (split to a follow-up
  compat PR).
- Provider selection by request `model:` field or inbound path prefix (one key = one provider
  stays canonical; agent-controlled body must never select which vault credential is injected).
- Incremental `redact_patterns` regex (buffered fallback is the honest answer).
- "Served-buffered" signaling when a stream falls back (no provider-compatible header).
- HTTP/2 trailer scrubbing if axum/reqwest don't expose trailers on the streaming path.

**Open questions (confirm during implementation, not blocking the design):**
- Exact `/v1/responses` `response.completed` usage field path — pin against a live fixture.
- Do any real providers send `text/event-stream` with a residual non-identity
  `Content-Encoding`? If so the pre-body compression check withholds the whole completion —
  confirm providers send identity for SSE, else streaming is unusable against them.
- Concrete default values for idle/total/byte/line DoS caps.
- Whether to tag V13a with a `dims.streamed=true` marker so leria can distinguish
  streamed-but-token-unpriced calls (leria-contract check; out of scope unless leria needs it).

---

## Appendix — provider wire facts (verified 2026-06-23 against vendor docs)

- **OpenAI chat completions streaming:** `Content-Type: text/event-stream`; events are `data:
  {json}\n\n` terminated by `data: [DONE]\n\n`. With `stream_options:{include_usage:true}` an
  **extra** chunk is emitted **before** `[DONE]` carrying top-level `usage`; that chunk's
  `choices` is `[]`; every other chunk's `usage` is `null`. If the stream is
  interrupted/cancelled the client may not receive the usage chunk. → drives §4.1 inject-when-absent
  and §4.3 V13b-clean-EOF-only.
- **Anthropic messages streaming:** `Content-Type: text/event-stream`; named events
  `message_start` → (`content_block_start` / `content_block_delta` / `content_block_stop`)* →
  `message_delta`* → `message_stop`. `input_tokens` is in `message_start.message.usage`;
  `output_tokens` is in `message_delta.usage` and is **cumulative** (take the last value, never
  sum). Errors arrive as `event: error`. → drives the §4.2 Anthropic extractor.

_Sources: OpenAI Chat Completions streaming reference / community "usage stats in streaming";
Anthropic "Streaming Messages" docs._
