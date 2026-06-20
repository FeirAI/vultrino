# Integration

How to integrate Vultrino **by itself** (the standalone, client-facing API),
followed by an **optional** section on composing it with sibling planes via the
cross-plane contracts. Vultrino is a complete, usable product on its own — you do
not need any other component.

## Standalone integration (the common case)

### 1. Run it and provision

Run `vultrino web` (the JSON API server), then provision via the admin API or CLI:

- Store credentials (`POST /api/v1/credentials` or `vultrino add`) — secrets are
  write-only.
- Author allow policies (default-deny means a credential is blocked until you
  allow it) via `POST /api/v1/policies` or `[[policies]]` in `config.toml`.
- Mint either a long-lived **API key** (`POST /api/v1/keys` via the web UI / CLI)
  or a narrow **use token** (`POST /api/v1/tokens`) for the agent.

Full details in [QUICKSTART.md](QUICKSTART.md), [API.md](API.md), and
[CONFIGURATION.md](CONFIGURATION.md).

### 2. Give the agent a bearer, not a secret

The agent (or your service-on-behalf-of-the-agent) makes one HTTP call per action:

```http
POST /api/v1/execute
Authorization: Bearer vut_…        # use token (preferred for agents) or vk_…
Content-Type: application/json

{ "credential": "github-api", "method": "GET", "url": "https://api.github.com/user" }
```

The agent knows only the credential **alias** and its own bearer token. Vultrino
injects the real secret, enforces policy, and returns the (scrubbed) upstream
response. This is the entire integration surface for "use a credential safely".

### 3. Handle the three outcomes

- **`200`** — the action ran; use `status`/`headers`/`body`.
- **`202` `pending_approval`** — the action is gated on a human; poll
  `GET /api/v1/approvals/{id}` with the **same** bearer until `status` is
  `Approved` (then `result` is present), `Denied`, or `Expired`. Run **at most
  once** — don't resubmit on `Approved`.
- **`4xx`** — denied/invalid; the `code`/`error` carry the reason. Do not retry a
  policy denial.

### 4. Integrate via MCP (for LLM tool calls)

For LLM frameworks that speak the Model Context Protocol, run `vultrino mcp`
(stdio). It exposes Vultrino's capabilities as MCP tools (including the
`check_approval` tool, which mirrors the HTTP approval-poll contract) so an agent
calls them as tools rather than raw HTTP. See `docs/src/api/mcp-tools.md` and
`docs/src/components/mcp.md` for the tool list.

### 5. Observe usage and events (optional, standalone)

Enable the `[outbox]`. Your own consumer can then:

- **Receive push deliveries** at `[outbox] url`, verifying `Govder-Signature`
  (`sha256=HMAC-SHA256(hmac_secret, body)`) on each.
- **Poll** `GET /api/v1/events?after=N` (admin key) to replay the ordered,
  gap-free event stream — approvals, halts, policy changes, credential rotation,
  and per-call `meter.observed` usage. See [METERING.md](METERING.md).

### 6. Runtime control (optional, standalone)

The admin API is a complete runtime control surface for your own control logic:
push/replace/delete policies, mint/revoke use tokens, halt/unhalt an agent, read
metrics. All hot-reload without a restart.

## Cross-plane composition (optional)

> The combined four-plane OS (govder decides · vultrino enforces · feir proves ·
> leria meters) is a separate product. Vultrino references only the **contracts**
> an integrator needs; you can ignore this section entirely when using Vultrino
> alone. The contracts below are exactly the standalone API surfaces above — there
> is no special cross-plane mode.

### vultrino ⇄ a decision plane (e.g. govder)

A decision plane drives Vultrino entirely through the **standalone admin API**
(V1): it pushes allow/deny/kill policies (`POST/PUT/DELETE /api/v1/policies`),
mints/revokes use tokens, and halts agents. Two contract details:

- **Action labels (V8):** a decision plane may present a business verb (e.g.
  `payments.refund`); map it to a canonical `plugin.action` via
  `[[action_labels]]` so policy/audit see both forms.
- **Principal targeting (V4):** bind an `agent_label` to a use token (or set it on
  a kill policy's `principal_pattern`) so a policy targets one agent.
- **Propagation timing:** an admin policy push is synchronous on the web process
  but bounded-staleness (`POLICY_REFRESH_SECS = 5`) on other processes. For an
  immediate kill, revoke the token (storage-authoritative). See
  [ARCHITECTURE.md](ARCHITECTURE.md).

### vultrino → a metering plane (e.g. leria)

Vultrino is the metering plane's `gateway-observed` cost source. It emits signed
`meter.observed` events; the metering plane consumes them — and, when a budget is
exhausted, pushes a `Deny` policy *back* through the admin API (no new vultrino
code; it's the same enforcement path). The full payload shapes, the poll-vs-push
decision (the metering plane **polls** `GET /api/v1/events`, since the single push
slot is one consumer), the latency floor, and the **honest loss-mode bounds** are
in [METERING.md](METERING.md). Wire-contract specifics:

- Dedup key is `event_id` (the `/execute` request id; the token event uses
  `<request_id>:tokens`).
- The token event is `asset=usd` + a `tokens` split + `dims.model_ref`, with **no
  `amount`** — the consumer mints usd from the counts. Vultrino sends counts, not
  dollars, and holds no pricing/ledger state.

### vultrino → a proof plane (e.g. feir)

Vultrino's signed event outbox is the authentic, ordered record a proof plane can
ingest and attest over. Vultrino itself does not produce cryptographic proofs; it
produces the HMAC-signed, gap-free event stream that a proof plane elevates.

### Shared-secret alignment

When composing, align the HMAC secrets at each seam. From the e2e harness: the
metering consumer's gateway-verify secret equals Vultrino's `[outbox] hmac_secret`
(the `Govder-Signature` key); an approval-webhook consumer shares the approval
signature secret. Generate these once and thread them to both sides so every
verify lines up.
