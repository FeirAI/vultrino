# Use Tokens

A **use token** is a narrow, ephemeral grant — the opposite of a durable API key. Where an API key is a long-lived identity scoped by a role, a use token authorizes *one kind of action* against *one credential (or glob)*, optionally capped to a number of uses and/or a time window. It is designed to be handed to an agent for a single task and then forgotten.

Use tokens are recognized by their `vut_` prefix and are presented in exactly the same place as an API key — the `api_key` tool argument (MCP) or an `Authorization: Bearer <token>` header (HTTP). The agent still never sees the underlying credential secret.

## Creating a token

```bash
# "POST to the deploy webhook once, in the next 10 minutes"
vultrino token create deploy-once \
  --credential deploy-hook --action http.request --uses 1 --expires 10m
# Output: vut_xxxxxxxx...  (shown once — copy it now)
```

The plaintext token is shown **once** at creation. Vultrino stores only a hash, so it can never be recovered or re-displayed.

## Scoping options

| Flag | Meaning |
|------|---------|
| `--credential <glob>` | Credential alias or glob the token may use (e.g. `deploy-hook`, `github-*`). Required. |
| `--action <glob>` | Restrict to a single action (`http.request`) or a plugin glob (`postgres.*`). Omit for any action. |
| `--uses <N>` | Cap total executions. `--uses 1` is single-use; omit for unlimited. |
| `--expires <dur>` | Time window: `30m`, `24h`, `7d`. Omit for no expiry. |
| `--require-approval` | Gate **every** use behind a human decision — see [Action Approvals](./action-approvals.md). |

Both scopes are enforced **authoritatively in the server** at execution time, not just at the edge — a token narrowed to `github-*` / `http.request` is rejected for any other credential or action even if a caller tries to use it directly.

## Guarantees

- **Fail-closed counting.** A use is spent the moment the action runs — *before* the side effect, and even if the downstream call then errors. A single-use token can never drive two executions.
- **Cross-process atomic.** The check-and-increment happens under a cross-process file lock on the vault, so the count holds even when the web UI and the MCP server run as separate processes sharing one encrypted store.
- **Preflight is free.** A not-yet-loaded plugin or invalid parameters are caught *before* a use is consumed, so a misconfigured call doesn't burn the token.

## Managing tokens

```bash
vultrino token list             # show tokens, their scopes, uses, and status
vultrino token revoke <id>      # immediately disable a token
```

Tokens are also listed and revocable in the **Use Tokens** page of the web admin UI.

## Relationship to approvals

Add `--require-approval` to make a token's every use pause for a human. The use is **not** consumed when the approval is opened — only when the approved action actually runs. A use token's *pending* approvals are bounded so it can never open more outstanding approvals than it has remaining capacity (`uses + pending ≤ max_uses`). See [Action Approvals](./action-approvals.md).
