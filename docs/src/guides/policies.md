# Policy Configuration

Policies add fine-grained control over how credentials can be used, including URL restrictions, method limits, and rate limiting.

## Overview

Policies are evaluated for every credential use:

```
Request → RBAC Check → Policy Check → Credential Injection → Forward
                            │
                            └─ Deny if policy fails
```

### Default posture for un-policied credentials

A policy's `default_action` only governs credentials its `credential_pattern`
**matches**. What happens to a credential that matches *no* policy is set
engine-wide by `[enforcement] default_action` (see
[Configuration](../getting-started/configuration.md#enforcement-section)):

- `deny` (default): a credential matched by no policy is denied with a distinct
  `no_policy` reason — fail-closed. Grant access by adding a policy whose
  `credential_pattern` matches it.
- `allow`: a credential matched by no policy is permitted — the legacy
  fail-open behavior.

## Policy Structure

Policies are defined in the configuration file:

```toml
[[policies]]
name = "github-readonly"
credential_pattern = "github-*"
default_action = "deny"

[[policies.rules]]
condition = { url_match = "https://api.github.com/*" }
action = "allow"

[[policies.rules]]
condition = { method_match = ["GET", "HEAD"] }
action = "allow"
```

## Configuration Fields

### Policy Definition

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique policy name |
| `credential_pattern` | string | Glob pattern for credentials this policy applies to |
| `principal_pattern` | string (optional) | Glob over the presenting principal (key/token id or its `agent_label`). When set, the policy applies **only** to matching principals (V4). |
| `default_action` | string | Action when no rules match: `allow`, `deny` |
| `rules` | array | List of policy rules |

### Per-agent policies (`principal_pattern`)

A policy with `principal_pattern` applies only to requests from a matching
principal — the presenting key/token id, or an `agent_label` bound to the token
(via the admin API). This makes a **per-agent kill** expressible: push a Deny
scoped to one agent without affecting other agents sharing the same credential.

```toml
[[policies]]
name = "kill-refund-bot"
credential_pattern = "payments-*"
principal_pattern = "refund-bot"   # only this agent
default_action = "deny"
```

A request that carries **no** principal never matches a policy that sets
`principal_pattern`.

### Rule Definition

| Field | Type | Description |
|-------|------|-------------|
| `condition` | object | Condition to evaluate |
| `action` | string | Action if condition matches: `allow`, `deny` |

## Conditions

### URL Match

Restrict to specific URLs or patterns:

```toml
# Exact match
condition = { url_match = "https://api.github.com/user" }

# Wildcard pattern
condition = { url_match = "https://api.github.com/repos/*" }

# Multiple paths
condition = { url_match = "https://api.github.com/{user,repos,gists}/*" }
```

### Method Match

Restrict to specific HTTP methods:

```toml
# Single method
condition = { method_match = ["GET"] }

# Multiple methods
condition = { method_match = ["GET", "HEAD", "OPTIONS"] }

# All read operations
condition = { method_match = ["GET", "HEAD"] }

# Write operations
condition = { method_match = ["POST", "PUT", "PATCH", "DELETE"] }
```

### Time Window

Restrict to specific hours:

```toml
# Business hours only (9 AM - 5 PM)
condition = { time_window = { start = "09:00", end = "17:00" } }

# Night shift (11 PM - 7 AM)
condition = { time_window = { start = "23:00", end = "07:00" } }
```

### Rate Limit

Limit request frequency:

```toml
# 100 requests per minute
condition = { rate_limit = { max = 100, window_secs = 60 } }

# 1000 requests per hour
condition = { rate_limit = { max = 1000, window_secs = 3600 } }

# 10 requests per second (burst protection)
condition = { rate_limit = { max = 10, window_secs = 1 } }
```

### Spend Cap

Cap the value an agent can spend in a **single call**, in **minor units** (e.g.
cents) (V3). The amount is read from the request body by a [spend
extractor](../getting-started/configuration.md#enforcement-section); a
missing/unparseable amount fails **closed** (deny).

```toml
# Refunds: at most $50.00 per call, in USD.
condition = { spend_cap = { asset = "usd", per_action_max = 5000 } }
```

Use it as the condition of an `allow` rule (with `default_action = "deny"`): the
call is allowed only while within the per-call cap. A `SpendCap` must be a rule's
**top-level** condition (not nested in `and`/`or`/`not`), and its policy must be
fail-closed (`default_action = "deny"`) — both are enforced at load.

> **Per-action only — the spend check is stateless.** Vultrino does *not* keep a
> cumulative/windowed ledger: a single call is the unit it bounds. **Cumulative
> or budget enforcement is the book-of-record's plane** (e.g. a spend ledger
> service) — it arrives as a per-agent/credential `Deny` policy pushed through
> the [admin write API](./policies.md) when a budget is exhausted, not as engine
> state inside vultrino. This keeps the proxy's decision stateless and the same
> across the web and MCP processes.

Notes:

- **Approval-gated spends** are re-checked when the approval finally executes
  via the read-only resume path, which treats the already-checked per-action
  amount as admitted (it does not re-deny on resume).
- **Multiple assets**: put per-asset caps as multiple *rules in a single
  policy* (first match wins). Two *separate* per-asset policies would deny each
  other's asset, because a non-matching asset falls through to that policy's
  `deny` default.

### Combined Conditions

Use `and` and `or` for complex logic:

```toml
# URL AND method match
condition = { and = [
  { url_match = "https://api.github.com/repos/*" },
  { method_match = ["GET"] }
]}

# Allow GET to anything OR POST to specific endpoint
condition = { or = [
  { method_match = ["GET"] },
  { and = [
    { method_match = ["POST"] },
    { url_match = "https://api.github.com/repos/*/issues" }
  ]}
]}
```

## Complete Examples

### Read-Only API Access

```toml
[[policies]]
name = "github-readonly"
credential_pattern = "github-readonly-*"
default_action = "deny"

[[policies.rules]]
condition = { url_match = "https://api.github.com/*" }
action = "allow"

[[policies.rules]]
condition = { method_match = ["POST", "PUT", "PATCH", "DELETE"] }
action = "deny"
```

### Rate-Limited Production Access

```toml
[[policies]]
name = "stripe-production"
credential_pattern = "stripe-live-*"
default_action = "deny"

# Allow only Stripe API
[[policies.rules]]
condition = { url_match = "https://api.stripe.com/*" }
action = "allow"

# Rate limit to prevent abuse
[[policies.rules]]
condition = { rate_limit = { max = 100, window_secs = 60 } }
action = "allow"
```

### Business Hours Only

```toml
[[policies]]
name = "sensitive-data-access"
credential_pattern = "database-*"
default_action = "deny"

# Only during business hours
[[policies.rules]]
condition = { time_window = { start = "09:00", end = "18:00" } }
action = "allow"
```

### Multi-Service Policy

```toml
[[policies]]
name = "payment-processing"
credential_pattern = "payment-*"
default_action = "deny"

# Allow Stripe
[[policies.rules]]
condition = { url_match = "https://api.stripe.com/*" }
action = "allow"

# Allow PayPal
[[policies.rules]]
condition = { url_match = "https://api.paypal.com/*" }
action = "allow"

# Allow Braintree
[[policies.rules]]
condition = { url_match = "https://api.braintreegateway.com/*" }
action = "allow"

# Block everything else by default
```

### AI Agent Restrictions

```toml
[[policies]]
name = "ai-agent-safety"
credential_pattern = "ai-*"
default_action = "deny"

# Only read operations
[[policies.rules]]
condition = { method_match = ["GET", "HEAD"] }
action = "allow"

# Allow POST only to specific safe endpoints
[[policies.rules]]
condition = { and = [
  { method_match = ["POST"] },
  { or = [
    { url_match = "https://api.github.com/repos/*/issues" },
    { url_match = "https://api.github.com/repos/*/comments" }
  ]}
]}
action = "allow"

# Rate limit all requests
[[policies.rules]]
condition = { rate_limit = { max = 60, window_secs = 60 } }
action = "allow"

# Block dangerous operations
[[policies.rules]]
condition = { url_match = "https://api.github.com/repos/*/delete" }
action = "deny"
```

## Policy Evaluation Order

1. **RBAC check** — Does the API key have permission?
2. **Credential scope** — Is the credential in scope for this role?
3. **Policy match** — Find policies matching the credential alias
4. **Rule evaluation** — Evaluate rules in order
5. **Default action** — Apply if no rules matched

Rules are evaluated in order. First matching rule determines the action.

## Debugging Policies

### Verbose Logging

Enable debug logging to see policy evaluation:

```bash
RUST_LOG=vultrino=debug vultrino serve
```

Output:
```
DEBUG vultrino::policy: Evaluating policy "github-readonly" for credential "github-api"
DEBUG vultrino::policy: Rule 1 url_match: matched
DEBUG vultrino::policy: Rule 2 method_match: GET in [GET, HEAD] = true
DEBUG vultrino::policy: Result: allow
```

### Test Policies

Test a policy without making real requests:

```bash
vultrino policy test --credential github-api \
  --url "https://api.github.com/user" \
  --method GET
# Result: allow (matched rule 1: url_match)
```

### Audit Log

Check why requests were denied:

```bash
grep "policy_denied" /var/log/vultrino/audit.log
```

## Common Patterns

### Deny by Default

Start restrictive, add specific allows:

```toml
[[policies]]
name = "strict-access"
credential_pattern = "*"
default_action = "deny"

[[policies.rules]]
condition = { url_match = "https://api.company.com/*" }
action = "allow"
```

### Allow by Default with Blocklist

Allow most things, block specific patterns:

```toml
[[policies]]
name = "open-access"
credential_pattern = "dev-*"
default_action = "allow"

# Block production endpoints
[[policies.rules]]
condition = { url_match = "https://api.company.com/admin/*" }
action = "deny"

[[policies.rules]]
condition = { url_match = "https://api.company.com/billing/*" }
action = "deny"
```

### Environment Separation

Different policies per environment:

```toml
# Production: strict
[[policies]]
name = "production"
credential_pattern = "*-prod"
default_action = "deny"

[[policies.rules]]
condition = { url_match = "https://api.production.com/*" }
action = "allow"

# Development: permissive
[[policies]]
name = "development"
credential_pattern = "*-dev"
default_action = "allow"
```

## Best Practices

### 1. Start Restrictive

Default to `deny` and add specific allows:

```toml
default_action = "deny"
```

### 2. Use Specific URL Patterns

```toml
# Bad: too broad
condition = { url_match = "*" }

# Good: specific
condition = { url_match = "https://api.github.com/repos/myorg/*" }
```

### 3. Combine with RBAC

Policies complement RBAC, not replace it:

- **RBAC**: Who can access which credentials
- **Policies**: How credentials can be used

### 4. Document Policies

Use clear names and comments:

```toml
[[policies]]
# SECURITY: Prevents AI agents from deleting repositories
name = "ai-no-destructive"
credential_pattern = "ai-*"
```

### 5. Test Before Deploying

Use the policy test command to verify behavior before applying in production.
