# Multi-Tenancy & Per-Team Partition (V11)

A single vultrino can serve multiple teams/tenants, each with its own enforcement posture and credential isolation — so a federated enterprise can run **one team in enforce mode while another is observe-only**, on the same instance.

## Tagging a principal with a tenant

An API key or use token carries an optional `tenant`. For a use token, set it at the admin mint:

```bash
curl -XPOST .../api/v1/tokens -H "Authorization: Bearer vk_admin_..." -d '{
  "name": "team-b-bot", "credential_scope": "*", "tenant": "team-b"
}'
```

The principal's tenant is what selects its enforcement mode and scopes its credential access.

## Per-tenant enforcement mode

Configure each tenant's mode under `[[tenants]]`:

```toml
[[tenants]]
id = "team-a"
mode = "enforce"   # the default — a policy Deny blocks the action

[[tenants]]
id = "team-b"
mode = "observe"   # a policy Deny is recorded + emitted but NOT blocked
```

- **`enforce`** (the default, and the mode for any untenanted or unlisted principal — fail-closed): a policy `Deny` blocks the action as usual.
- **`observe`**: a policy `Deny` is **downgraded to allow** — the action runs, a warning is logged, and a `policy.observed_denial` event is emitted to the signed [outbox](../getting-started/configuration.md#event-outbox-v9) (carrying the credential, action, and what *would* have happened). This lets a team onboard and watch what *would* be blocked before flipping to `enforce`, while other teams enforce on the same vultrino. Note this also downgrades the engine's fail-closed `no_policy` default-deny, so in an observe tenant a credential lacking an explicit allow policy is *usable* (the point of observe-only onboarding) — size the blast radius accordingly.

> Observe mode downgrades an **authorization-posture** denial only. The following are security/financial/abuse boundaries and are **not** observable-away — they hold even in an observe tenant: cross-tenant isolation (below), use-token scope, RBAC, the dual-control gate, **SpendCap / RateLimit resource guards** (a credential under a spend or rate cap is never downgraded — an over-cap call would otherwise run uncharged), and — critically — a [halt / kill switch](./kill-halt.md) (a halted agent stays blocked).

## Credential isolation

A credential can be tagged to a tenant via its `tenant` metadata:

```bash
vultrino meta set team-a-secret tenant team-a
```

A principal may only use credentials in **its own** tenant; an **untenanted credential is shared** (usable by any tenant). A principal in `team-b` attempting to use a `team-a`-tagged credential is denied — regardless of `team-b`'s enforce/observe mode (isolation is a hard boundary, not a policy that observe mode can downgrade).
