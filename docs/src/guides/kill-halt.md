# Kill Switches & Halt (V6)

When an agent misbehaves you need to **stop it now**, not at the end of its run. Vultrino's halt is a layered kill switch with a deliberately-documented set of *achievable* semantics — it does not pretend to preempt work a harness gives it no way to preempt.

## Halting an agent

```bash
# Admin API (Permission::Admin). Idempotent via Idempotency-Key.
curl -XPOST https://vultrino.example.com/api/v1/agents/bot-7/halt \
  -H "Authorization: Bearer vk_admin_..."
```

The response summarizes the three legs:

```json
{
  "agent_label": "bot-7",
  "revoked_tokens": ["vut_..."],
  "deny_policy_id": "halt:bot-7",
  "policy_active": true,
  "in_flight": [ { "session_id": "...", "credential": "...", "action": "...", "started_at": "..." } ],
  "callbacks_fired": 1
}
```

Lift a halt with `DELETE /api/v1/agents/{label}/halt` (the kill policy is removed; **already-revoked tokens stay revoked** — revocation is permanent, so mint fresh tokens to resume the agent).

## What halt actually does — the three legs

1. **Revoke the agent's use tokens.** Storage-authoritative and re-checked under the vault lock on **every** gated call, so it takes effect *immediately and across processes* (web + MCP).
2. **Install an authoritative per-agent kill policy** (`principal_pattern` = the halt target). The target is matched against the principal's **agent label *or* its key/token id**, so it covers both label-bound use-token agents (`/api/v1/agents/refund-bot/halt`) and an API-key agent that carries no label (halt it by its key id, `/api/v1/agents/vk_<id>/halt`). It is a **kill** policy: unlike an ordinary per-agent Deny, it is evaluated *before* every other policy, so an `allow` rule that happens to be ordered first can never let a halted agent slip through. It is persisted and propagates to other processes via the policy refresh. (The halt target must be a literal identifier — `*?[]` globs are rejected — so a halt can't accidentally deny a whole fleet. The kill policy is a normal stored policy: it is visible in, and removable via, the policy admin API, in addition to `DELETE …/halt`.)

> If the immediate in-process engine reload fails (rare), the halt still returns `200` with `"policy_active": false`: token revocation has taken effect immediately and the kill policy is persisted, so it activates within the refresh window. The halt is effective within the kill-SLA regardless.
3. **Fire registered abort callbacks** for the agent's in-flight sessions.

## Achievable semantics (read this before relying on it)

- **Deny-the-next-gated-call** is the baseline guarantee, and it is solid: within the kill-SLA, the halted agent's next attempt to use *any* credential is denied — on every path (MCP and HTTP), on every process. On the process that serves the admin API the kill policy is live immediately; other processes pick it up within the policy-refresh window (a few seconds), while token revocation is immediate everywhere.
- **True preemption of in-flight work** is only possible where the *harness* exposes an abort/pause primitive. Vultrino can't reach into an agent runtime it doesn't control. Register a [`HaltCallback`](#abort-callbacks) for harnesses that do expose one; without it, an action already mid-flight runs to completion (its result is still subject to egress controls), and the halt takes hold on the *next* gated call.

## The session registry

Vultrino records in-flight gated executions so a halt can report — and a callback can act on — what an agent is doing right now:

```bash
curl https://vultrino.example.com/api/v1/sessions -H "Authorization: Bearer vk_admin_..."
```

> The registry is **in-memory and per-process** (the same model as the rate-limit and spend ledgers): it resets on restart, and in a web+MCP deployment each process only sees the executions *it* is running. The cross-process kill legs (token revoke + kill policy) are not subject to this limitation.

## Abort callbacks

A harness integration registers a `HaltCallback` on the server; on halt it is fired with the agent's in-flight sessions, so an integration that can signal the agent runtime (cancel a task, close a session) can preempt rather than wait for the next gated call. With no callback registered, halt is purely deny-next-gated-call plus token revocation.
