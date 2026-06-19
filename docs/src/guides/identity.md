# Workload Identity & Owner Binding (V10)

Vultrino's principal — the thing a policy's `principal_pattern` matches and an approval's separation-of-duty is computed against — can be a **workload identity** resolved from an external identity document, and a `vk_`/`vut_` can carry an **IdP-resolvable owner** so a non-human identity (NHI) maps to a directory identity.

> **Trust boundary.** The SPIFFE and OIDC resolvers parse and validate an **already-verified** document. The cloud-IAM resolvers are *claim adapters* — they map a verified token's claims to a principal but do **not** perform the cloud-specific cryptographic verification (JWKS fetch / cloud SDK), which is wired at deployment. **Signature/issuer verification must happen before resolution** — these resolvers trust the document they are handed, so the deployment must terminate mTLS / verify the token at the edge and pass the *verified* document inbound. The cloud-IAM adapters stay integration-time and are not auto-wired inbound.

## Wiring it inbound (R6)

Enable inbound resolution with `[identity]`: a request carrying the configured `header` (the already transport-verified SVID or OIDC claims) has its principal resolved from that document **before policy evaluation** — `subject` becomes the `Principal.id` a `principal_pattern` matches, and `owner` the SoD owner.

```toml
[identity]
kind = "spiffe"                 # spiffe | oidc (the two wireable resolvers)
header = "x-spiffe-verified"    # inbound header carrying the verified document
allowed = ["example.org"]       # SPIFFE trust domains (or OIDC issuers); empty = any
```

So a `principal_pattern` Deny on `spiffe://example.org/*` blocks any request whose presented SVID is in that trust domain, regardless of which `vk_`/`vut_` carried it. A malformed or untrusted document is logged and **ignored** (the request falls back to its static `vk_`/`vut_` principal) — a bad document can only fail to refine the principal, never elevate it.

> **The resolved subject is an _additional_ match dimension, never a replacement.** The principal's stable `vk_`/`vut_` id remains the **halt / ownership anchor**, so a [halt](./kill-halt.md) keyed on the credential always holds even when a workload identity is presented (it can't be escaped by waving an SVID). To **halt by a resolved workload identity** itself, push a kill/Deny policy with `principal_pattern = <the SVID/OIDC subject>` through the [admin write API](./policies.md) — `vultrino agent halt` targets agent labels / credential ids (which exclude the `:`/`/` in SVID strings), whereas a policy `principal_pattern` matches the resolved subject directly.

## Resolving a workload identity

The `vultrino::identity` module turns an identity document into a `WorkloadIdentity { kind, subject, trust_domain, owner }`:

| Source | Resolver | `subject` | `trust_domain` |
|--------|----------|-----------|----------------|
| SPIFFE/SPIRE SVID | `SpiffeResolver` | the full `spiffe://…` ID | the trust domain (optionally allowlisted) |
| Generic OIDC | `OidcResolver` | the `sub` claim | the `iss` (optionally allowlisted); `owner` from `email`/`preferred_username` |
| AWS IAM (Roles Anywhere) | `resolve_cloud_iam(AwsIam, …)` | the assumed-role `arn` | `aws` |
| GCP workload identity | `resolve_cloud_iam(GcpWorkload, …)` | the service-account `email` | the `iss` |
| Entra workload identity | `resolve_cloud_iam(EntraWorkload, …)` | the `oid` | the `tid` (tenant) |

The resolved `subject` is what a policy `principal_pattern` matches — so a policy (or a [halt](./kill-halt.md)) can target a SPIFFE ID, an IAM role ARN, or an OIDC subject, not just a static `vk_`/`vut_` id.

## Owner binding

A use token can be bound to a **human/directory owner** — the OIDC `sub` / SCIM id of the person accountable for the NHI. (The same `owner_identity` field exists on API keys for when the key-mint path is extended; today it is settable on use tokens via the admin token-mint.)

```bash
# Mint a use token bound to a directory owner (admin API).
curl -XPOST .../api/v1/tokens -H "Authorization: Bearer vk_admin_..." -d '{
  "name": "refund-bot", "credential_scope": "pay-*",
  "owner_identity": "alice@example.com"
}'
```

The owner flows into the resolved principal and the approval record, and — most importantly — into **separation of duty**: when an owner is bound, `approver ≠ requester's owner` is computed against the **directory owner** (the precise human), not just the agent label. So a human approving an action requested by an NHI they own is flagged (or rejected, with `enforce_separation_of_duty`). See [Action Approvals](./action-approvals.md#approver-identity-and-separation-of-duty-v5).
