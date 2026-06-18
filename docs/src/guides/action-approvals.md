# Action Approvals

Some actions are too consequential to let an agent run unsupervised — a production refund, a `DROP TABLE`, a deploy. **Action approvals** put a human in the loop: Vultrino pauses before the action executes, and the agent never sees a result until someone signs off. The decision can be made in the admin panel, from a Telegram button, or via a link delivered by webhook/email.

## What triggers an approval

An action is gated if **any** of these match:

- The credential is flagged: `vultrino meta set <alias> require_approval true`
- The request is authorized by a [use token](./use-tokens.md) created with `--require-approval`
- A [policy](./policies.md) rule matches with `action = "prompt"`

## What the agent experiences

The flow is designed so the agent clearly understands it is *waiting*, not failing, and knows how to check back:

1. The agent calls a tool. Instead of a result it receives an **"APPROVAL REQUIRED"** message containing an `approval_id`. The action has **not** run.
2. The agent polls with that id — the `check_approval` MCP tool, `GET /api/v1/approvals/{id}`, or `vultrino approval status <id> --wait`.
3. A human approves or denies it.
4. On the next poll after approval, Vultrino **runs the action and returns the real result**. If denied or expired, the agent is told to stop.

Execution happens lazily on that poll, so no background worker is required and the result is delivered the moment the agent next checks.

## Configuration

Enable approvals and configure out-of-band notifiers under `[approvals]` in `config.toml`:

```toml
[approvals]
enabled = true
ttl_secs = 3600                                   # default Medium-class total window
public_base_url = "https://vultrino.example.com"  # base for approve/deny links
oob_approver_identity = "oncall@example.com"      # identity OOB links are bound to (V5)
reauth_interval_secs = 900                         # optional continuous re-auth (V5)
enforce_separation_of_duty = false                 # hard-reject self-approvals (V5)
dual_control_approvers = 2                          # distinct approvers for dual control (V12)

[approvals.telegram]                              # inline Approve / Deny buttons
bot_token = "123456:ABC-DEF..."
chat_id = "987654321"

[approvals.webhook]                               # POST to any URL (email / Slack / ...)
url = "https://hooks.example.com/vultrino-approvals"
auth_header = "Bearer your-webhook-secret"

# Per-criticality SLA windows (V5): window 1 = Pending→Escalated, window 2 =
# Escalated→Expired. Omitted classes use built-in defaults.
[[approvals.sla]]
class = "critical"
escalate_after_secs = 300
escalate_window_secs = 300

# Assign a criticality class to a (credential, action). First match wins;
# unmatched actions are "medium".
[[approvals.criticality_rules]]
credential_pattern = "pay-*"
action_pattern = "*"
class = "critical"
```

If approvals are enabled but no notifier is configured, decisions can still be made from the admin panel; Vultrino logs a warning that out-of-band approval is unavailable.

## SLA, escalation, and continuous re-authorization (V5)

Every request is assigned a **criticality class** (`low` | `medium` | `high` | `critical`) from the first matching `[[approvals.criticality_rules]]` rule, defaulting to `medium`. The class drives a two-phase SLA:

1. **First window** — while undecided, the request is `pending`. When the first window elapses it moves to `escalated` and the configured notifiers are re-pinged (with a panel link; the original one-time decision token is not re-issued).
2. **Second window** — an `escalated` request that is still undecided when the final deadline passes auto-**expires** (a fail-closed deny). A high/critical request therefore escalates fast and then denies, rather than lingering open indefinitely.

Higher criticality uses shorter windows (built-in defaults: `critical` 5m+5m, `high` 15m+15m, `low` 4h+4h; `medium` splits the legacy `ttl_secs` across both phases). Override any class with `[[approvals.sla]]`. Lifecycle advancement happens both on each agent poll and via a background sweep, so a request nobody is polling still escalates and expires on time. From the agent's side `escalated` behaves exactly like `pending` — keep polling.

Set `reauth_interval_secs` to require **continuous re-authorization**: an approved grant that has not yet run within that window is treated as lapsed and must be re-approved before it can execute, rather than running on a stale decision.

## Approver identity and separation of duty (V5)

Every human decision records an **authenticated approver identity**, not just the channel:

- **Admin panel** — the logged-in session user.
- **Out-of-band link** — the named `oob_approver_identity` the link is bound to (rather than an anonymous capability token); falls back to a generic `out-of-band` label if unset.
- **CLI** — the local OS user (`cli:<user>`).

A decision with a blank identity is rejected. Because both the requester's owner and the approver are recorded, **separation of duty** ("the approver must not be the requesting agent") is computed and **recorded on every decision** (and logged when violated) — an agent self-approving its own request is flagged. Set `enforce_separation_of_duty = true` to **hard-reject** a self-approval rather than only recording it (a self-*denial* is always allowed). The CLI decides as a trusted local admin, so its OS-user identity is advisory.

## Dual control (M-of-N) (V12)

A high-risk action can require **more than one** distinct approver before it runs. A use token minted with `strictness: direct` (or any token flagged `dual_control`) opens an approval that needs `[approvals] dual_control_approvers` distinct sign-offs (default **2**) — the action does not execute until the threshold is met:

- Each approval records a **distinct** approver sign-off; the **same** identity can't satisfy two of the required slots (rejected as a duplicate).
- The request stays `pending` (the poll response carries `approvals_received` / `approvals_remaining`) until enough distinct approvers sign off, then flips to `approved` and runs on the next poll.
- A **single denial vetoes** the whole request regardless of how many approvals were gathered.
- Separation of duty composes: with `enforce_separation_of_duty`, a self-approval by the requester is rejected and does not count toward the M-of-N threshold.

```toml
[approvals]
dual_control_approvers = 2   # distinct approvers a dual-control request needs (default 2)
```

## Metrics read-back (V12)

`GET /api/v1/metrics` (admin) returns a structured point-in-time read-back: `unauthorized_attempts` (tool-call attempts denied by the policy engine **or** by cross-tenant isolation — counted whether the denial was enforced or, for an [observe-mode tenant](./multi-tenancy.md), merely observed; a **per-process** in-memory counter, like the rate-limit/spend ledgers, that resets on restart and counts only this process), approval counts by state (`approvals.by_status`, plus `dual_control_awaiting`), and approval-decision latency percentiles (`approval_latency_secs.{count,avg,p50,p95,max}`). The durable, cross-process event history is the signed [event outbox](../getting-started/configuration.md#event-outbox-v9).

## Out-of-band decision links

Telegram/webhook/email links carry a **single-use capability token** and open a **confirmation page** rather than deciding on load — so a link prefetch or scanner can't silently approve an action, and the admin session is never required to act on a notification.

> Set `public_base_url` to an **HTTPS** address so these links stay confidential, and avoid running the web server at `DEBUG` log level in production: request URIs (which carry the link's capability token) are logged at `DEBUG`.

## Guarantees

- **At most once.** An approved action's execution is claimed atomically, so two racing polls can't both run it. A claim from a process that crashed mid-execution is auto-recovered after a timeout; a transient pre-execution failure (e.g. a plugin not yet loaded) is retried rather than marked done.
- **Ownership.** An agent may only poll approvals created by the **same principal** (API key or use token) that made the original request — checked before any execution.
- **Bounded pending approvals.** A use token's `uses + outstanding pending approvals` can never exceed `max_uses`, enforced atomically under the vault lock — so a single-use token can't flood the approval queue (or the notifier) with requests it could never run.
- **Policy still applies at run time.** Policy is re-evaluated when the action finally executes, so an explicit **deny** rule (URL / method / time-window) blocks even a human-approved action — a human approval is not a policy bypass. Rate limits are charged **once, at request time**; the deferred re-check never re-charges or re-denies an approved action against the rate limiter. When a deny does fire on resume, the use token is left unconsumed.

## Managing approvals

```bash
vultrino approval list                  # pending and recent decisions
vultrino approval status <id> [--wait]  # poll one approval (optionally block)
vultrino approval approve <id>
vultrino approval deny <id>
```

The **Approvals** page of the web UI shows pending requests with their requester, credential, action, and parameters, and offers Approve / Deny actions.
