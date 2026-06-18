# Workload Identity & Owner Binding (V10)

Vultrino's principal — the thing a policy's `principal_pattern` matches and an approval's separation-of-duty is computed against — can be a **workload identity** resolved from an external identity document, and a `vk_`/`vut_` can carry an **IdP-resolvable owner** so a non-human identity (NHI) maps to a directory identity.

> **Scope (scaffolding).** The SPIFFE and OIDC resolvers are complete and pure: they parse and validate an **already-verified** document. The cloud-IAM resolvers are *claim adapters* — they map a verified token's claims to a principal but do **not** perform the cloud-specific cryptographic verification (JWKS fetch / cloud SDK), which is wired at deployment. **Signature/issuer verification must happen before resolution** — these adapters trust the document they are handed. This is the deliberate V10 boundary: the principal-mapping contract is real and tested; the transport-verification half is integration-time.

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

An API key or use token can be bound to a **human/directory owner** — the OIDC `sub` / SCIM id of the person accountable for the NHI:

```bash
# Mint a use token bound to a directory owner (admin API).
curl -XPOST .../api/v1/tokens -H "Authorization: Bearer vk_admin_..." -d '{
  "name": "refund-bot", "credential_scope": "pay-*",
  "owner_identity": "alice@example.com"
}'
```

The owner flows into the resolved principal and the approval record, and — most importantly — into **separation of duty**: when an owner is bound, `approver ≠ requester's owner` is computed against the **directory owner** (the precise human), not just the agent label. So a human approving an action requested by an NHI they own is flagged (or rejected, with `enforce_separation_of_duty`). See [Action Approvals](./action-approvals.md#approver-identity-and-separation-of-duty-v5).
