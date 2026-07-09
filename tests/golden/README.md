# V13b golden-vector fixture (integration#7)

`v13b_meter_tokens.json` is the canonical shape of the V13b priced-token
`meter.observed` payload vultrino emits (`src/outbox.rs::meter_tokens_payload`,
built from a REAL end-to-end run of
`tests/llm_proxy_integration.rs::llm_non_streamed_injects_key_returns_body_meters_tokens_and_scrubs`).
It is pinned as a **byte-identical** fixture in THREE repos so a shape drift in
any one of them fails loudly instead of silently diverging:

- `vultrino/tests/golden/v13b_meter_tokens.json` — **this copy, the source of
  truth** (generated from the real emit path; the other two are copied from it
  verbatim).
- `leria/testdata/v13b_meter_tokens.json` — fed through leria's real
  authenticated ingest + rate-card pricing (`cmd/leria/ingest_test.go`).
- `govder/e2e/testdata/v13b_meter_tokens.json` — loaded by the govder/e2e
  `leriaTokenIngest` fixture (`provision_test.go`).

A fourth check (`leria`'s `TestV13bCrossRepoRegenAndDiff`, when a sibling
vultrino checkout + `cargo` are available) re-runs the vultrino test above with
`V13B_ARTIFACT_PATH` set to a scratch file and diffs the freshly generated,
canonicalized artifact against leria's committed copy — this is the one check
that catches REAL drift as soon as vultrino's code changes, independent of
anyone remembering to regenerate the committed fixtures.

## Canonicalization

Four fields vary every test run and are replaced with fixed placeholders before
comparison (see `canonicalize_v13b_golden` in
`tests/llm_proxy_integration.rs`):

| Field            | Placeholder            | Why it varies                                   |
|-------------------|------------------------|--------------------------------------------------|
| `event_id`        | `<REQUEST_ID>:tokens`  | threads the request's UUID                       |
| `correlation_id`  | `<REQUEST_ID>`         | threads the request's UUID                       |
| `occurred_at`     | `<OCCURRED_AT>`        | wall-clock                                        |
| `principal`       | `<PRINCIPAL>`          | this test's minted use-token id (`ut_<uuid>`)     |

Every other field (`asset`, `tokens.{input,output}_tokens`, `cost_source`,
`confidence`, and `dims.{model_ref,credential,provider,channel}`) is a STABLE,
pinned literal from the test fixture. A rename, re-nesting, or value change
anywhere else fails the comparison loudly.

## Regenerating (after an INTENTIONAL shape change)

From `vultrino/`:

```sh
V13B_ARTIFACT_PATH=tests/golden/v13b_meter_tokens.json \
  cargo test --test llm_proxy_integration \
  llm_non_streamed_injects_key_returns_body_meters_tokens_and_scrubs
```

This regenerates `vultrino/tests/golden/v13b_meter_tokens.json` in place (the
test compares its own freshly-written file against itself, so it trivially
passes). Then copy that file **byte-for-byte** over:

```
leria/testdata/v13b_meter_tokens.json
govder/e2e/testdata/v13b_meter_tokens.json
```

All three files must stay byte-identical. Do not hand-edit any of the copies —
regenerate from the real emit path instead.
