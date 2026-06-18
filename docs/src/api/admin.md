# Admin API (runtime config-write)

The admin API lets a control plane (e.g. govder) configure the enforcement plane
at runtime — push policies, mint/revoke tokens, manage roles, and register
credentials — **without restarting** vultrino. It is served by `vultrino web`
under `/api/v1/` alongside the existing read/execute endpoints.

## Authentication

Every admin endpoint requires an **API key** (`vk_…`) whose role holds the
`admin` permission. The predefined `admin` role has it; grant it to a custom
role with `"permissions": ["admin", …]`. Use tokens (`vut_…`) are rejected
outright — admin is an API-key-only capability.

```
Authorization: Bearer vk_your_admin_key
```

Responses: `401` (missing/invalid key), `403` (valid key without `admin`, or a
use token), `400` (invalid body), `404` (no such resource), `409` (duplicate or
an in-flight idempotency key), `201`/`200` on success.

## Idempotency

Create/mint endpoints accept an optional `Idempotency-Key` header. A repeated
request with the same key **replays the original response** instead of acting
again (so a retried token mint never creates a second token). While the first
request is still in flight, a second with the same key gets `409`. Keys are
remembered for 24h.

```
Idempotency-Key: 5f3c…unique-per-logical-request
```

The key is bound to a hash of the request body: reusing a key with a *different*
body returns `409` rather than replaying the original response. Minted token
plaintext is **not** retained in the idempotency record — a replayed mint returns
metadata plus a note (revoke and re-mint if you lost the original response).

> **At-least-once on crash.** Reserve → operate → record-completion are three
> separate atomic storage writes, not one transaction. If the process crashes
> after the operation persists but before completion is recorded, a retry (after
> the ~60s stale-reservation window) re-runs the operation. Idempotency is
> exactly-once only absent a mid-operation crash.

## Endpoints

### Policies

Policies pushed here are **merged with** the static `[[policies]]` from
`config.toml` into the live engine (config policies stay declarative; the API
manages dynamic ones by id). Each write hot-reloads the engine **on the web
process** synchronously.

> **Cross-process propagation.** Other long-running processes that share the
> same vault (notably the MCP server) reload policies on a periodic refresh
> (default 5s), so an admin push reaches them within that window — not
> instantly. For an **immediate** kill, revoke the use token instead: token
> revocation is storage-authoritative and re-checked under the lock on every
> gated call, so it takes effect on the very next call in every process.

| Method | Path | Body | Result |
|--------|------|------|--------|
| `POST` | `/api/v1/policies` | `{name, credential_pattern, rules?, default_action, id?}` | `201` canonical policy (id generated if omitted) |
| `PUT` | `/api/v1/policies/{id}` | same | `200` canonical policy (create-or-replace) |
| `DELETE` | `/api/v1/policies/{id}` | — | `200 {deleted}` / `404` |

`rules` and `default_action` use the same shape as the config file
(`allow` / `deny` / `prompt`). An invalid `credential_pattern` glob is rejected
with `400` rather than silently never matching.

### Use tokens

| Method | Path | Body | Result |
|--------|------|------|--------|
| `POST` | `/api/v1/tokens` | `{name, credential_scope, action_scope?, max_uses?, require_approval?, expires_in_secs?}` | `201 {token, metadata}` — plaintext shown **once** |
| `POST` | `/api/v1/tokens/{id}/revoke` | — | `200 {revoked, metadata}` / `404` |

### Roles

| Method | Path | Body | Result |
|--------|------|------|--------|
| `POST` | `/api/v1/roles` | `{name, permissions[], credential_scopes?, description?}` | `201` role / `409` if the name exists |
| `DELETE` | `/api/v1/roles/{id}` | — | `200 {deleted}` / `404` |

### Credentials

Secret material is **write-only**: it is stored encrypted and never returned by
any endpoint (the create response carries metadata only).

| Method | Path | Body | Result |
|--------|------|------|--------|
| `POST` | `/api/v1/credentials` | `{alias, metadata?, data}` | `201` credential metadata / `409` duplicate alias |
| `DELETE` | `/api/v1/credentials/{id}` | — | `200 {deleted}` / `404` |

`data` is the tagged credential payload, e.g.
`{"type":"api_key","key":"…","header_name":"Authorization","header_prefix":"Bearer "}`.

### Webhooks

`PUT /api/v1/config/webhooks` (govder approval-callback target + signing key) is
delivered as part of the **signed webhook outbox** (see the events/outbox
guide), which owns webhook configuration and ordered, replayable delivery.

## Deployment note (vault format v4)

The admin API stores policies and idempotency records, which bumped the vault
format from v3 to v4. A v4-aware binary reads v3 vaults fine, but the **first
admin write upgrades the on-disk vault to v4**, after which any still-running v3
binary (a not-yet-upgraded MCP or CLI process sharing the same vault) is refused
the vault entirely. **Upgrade all vultrino processes before issuing admin
writes** to avoid breaking the un-upgraded enforcement plane.

## Example

```bash
# Push an allow policy for github credentials (takes effect immediately).
curl -sX POST http://127.0.0.1:7879/api/v1/policies \
  -H "Authorization: Bearer $VULTRINO_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{"name":"gh-allow","credential_pattern":"github-*","default_action":"allow"}'
```
