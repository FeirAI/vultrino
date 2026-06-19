# Vultrino Capability Requirements — govder Enforcement Contract

**Audience:** the vultrino developer. **Purpose:** govder uses vultrino as its in-path **policy-enforcement
point (PEP) + token broker** ("govder decides · vultrino enforces · feir proves"). The adversarial design
review ([adversarial-design-review.md](adversarial-design-review.md)) found that several capabilities the
govder↔vultrino contract ([05/05](../deep-dives/05-integration-architecture/05-govder-vultrino-enforcement-contract.md))
depends on **do not exist in vultrino today**. Because vultrino is our own tool, the fix is to **build them in
vultrino**, not scope govder down. This doc enumerates each capability as an implementable requirement, grounded
in current vultrino source (`/Users/dzcodes/Projects/vultrino`), prioritized P0→P2.

Every requirement below states: **Why** (the govder need + the review finding) · **Current state** (vultrino
code ref) · **Proposed change** (in vultrino's idiom) · **Acceptance** · **govder-side follow-on**.

---

## 0. Current vultrino baseline (what exists today — confirmed in source)

- **Policy model** (`src/policy/types.rs`): `Policy { id, name, credential_pattern, rules, default_action }`;
  `PolicyRule { condition, action }`; `PolicyCondition ∈ {UrlMatch, MethodMatch, TimeWindow, RateLimit{max,window_secs}, And, Or, Not, Always}`;
  `PolicyAction ∈ {Allow, Deny, Prompt}` (`Prompt` is marked *"future feature"*). `Policy::allow_all` and
  `Policy::deny_all` constructors exist.
- **Evaluation** (`src/policy/mod.rs`): `evaluate(credential_alias, url, method, ctx)` — matched **only by
  `credential_pattern`**; **returns `Allow` when no policy matches** (`:138`). No principal/agent input.
- **Tokens** (`src/auth/tokens.rs`): `UseToken { credential_scope, action_scope?, max_uses?, uses, require_approval,
  expires_at?, revoked }` (`vut_`); `ApiKey` (`vk_`) + `Role`. SHA-256 hash auth; **no principal/agent_id, no
  value field, single `expires_at`**.
- **Approvals** (`src/approval/`): flat `ApprovalConfig.ttl_secs` (default 3600); `Pending → Approved/Denied/Expired`;
  `decided_by` is a **channel label** ("admin panel" / "out-of-band link"), not an authenticated identity.
- **Execute** (`src/server/mod.rs`, `src/web/api.rs`): resolves credential → scope-checks token → evaluates
  policy → injects credential → **returns the upstream response (headers+body) verbatim**. Actions are
  `plugin.action` (`http.request`, `postgres.run_sql`, `ssh.deploy`); the JSON `/execute` path **hardcodes
  `action:"http.request"`** (`web/api.rs:180`).
- **API routes** (`src/web/server.rs:166-169`): `GET /api/v1/health`, `GET /api/v1/credentials`,
  `POST /api/v1/execute`, `GET /api/v1/approvals/{id}`. **No write API** — policies load once from `config.toml`
  at startup (`add_policy`/`load_policies` are in-process, called from config-load + `#[cfg(test)]`).
- **Webhooks**: fire-and-forget approval webhook (no sequence/ordering/replay).
- **Identity/secrets**: vault stores **static** secrets (API key/basic/private-key/cert/OAuth2); OAuth2 refreshes
  **inline** and persists the rotated token (`http.rs:218-285`). **Zero** SPIFFE/SPIRE/OIDC/workload-identity.
- **Tenancy**: none (no tenant/team partition primitives).

---

## 1. Requirements summary

| ID | Capability | Pri | Unblocks (govder) |
|---|---|---|---|
| V1 | Runtime config-write API (policies/tokens/roles/creds) | **P0** | "govder configures the enforcement plane"; shadow→enforce flip; L3 auto-force-enable |
| V2 | Engine-level **default-deny** mode | **P0** | The headline "default-deny tool allowlist" being true at the engine, not just the token layer |
| V3 | Value/**spend** PolicyCondition + cumulative accounting | **P0** | Enforceable refund/spend caps ("budget guardrails the model can't talk past") |
| V4 | **Principal/agent** dimension on policies + per-agent kill | **P0** | Per-agent Deny (kill-leg W3); per-agent policy |
| V5 | Approval **SLA/escalation/continuous-reauth** + approver identity | P1 | Time-boxed lanes; separation-of-duty; oversight analytics |
| V6 | **Kill/halt** semantics + session registry | P1 | Honest kill triad; pause/abort where the harness supports it |
| V7 | Held-secret **egress** handling + downstream-cred model + OAuth-rotation hook | P1 | "revoke within seconds" being real; no secret-extraction bypass |
| V8 | Action-namespace contract + **strictness** compilation | P1 | Business-verb scopes; `direct` ≠ `approve-at-checkpoint` on the wire |
| V9 | **Ordered/replayable** webhook outbox (signed) | P1 | govder's webhook delivery contract (ordering/replay/DLQ) |
| V10 | **Identity** integration (SPIFFE/SPIRE, cloud IAM, IdP) | P2 | NHI-as-first-class; owner↔NHI binding |
| V11 | **Multi-tenancy** / per-team partition | P2 | Federated enterprise per-team enforcement |
| V12 | **Read-back/event** surface + dual-control approvals | P2 | KPIs (unauthorized-tool-call, approval-latency, MTTD/MTTC) |

---

## 2. P0 requirements

### V1 — Runtime config-write API
- **Why.** govder must push/modify policies, tokens, roles, and credential metadata at runtime to configure
  enforcement and to flip shadow→enforce per-agent. *(Review E2; finding int-vultrino "Config write has no
  implementable surface".)*
- **Current.** The whole JSON API is 4 read/execute routes; policies come from `config.toml` at process start;
  `add_policy`/`load_policies`/`remove_policy` are in-process Rust only.
- **Proposed.** Add an authenticated **admin API** behind a new `Permission::Admin` (beyond `Read`/`Execute`):
  - `POST /api/v1/policies` · `PUT /api/v1/policies/{id}` · `DELETE /api/v1/policies/{id}` (body = `Policy` JSON).
  - `POST /api/v1/tokens` (mint `vut_`, returns plaintext once) · `POST /api/v1/tokens/{id}/revoke`.
  - `POST /api/v1/roles` · `POST /api/v1/credentials` (metadata; secret material stays write-only) · `DELETE …`.
  - `PUT /api/v1/config/webhooks` (govder approval-callback target + signing key).
  - Persist to storage and **hot-reload** (the `storage.reload()` path already exists, e.g. `web/api.rs:45`);
    accept an `Idempotency-Key` header; return the canonical stored object.
- **Acceptance.** govder creates, updates, and deletes a policy/token via the API and it takes effect on the next
  `/execute` **without a restart**; concurrent writes are atomic under the storage lock.
- **govder follow-on.** Replace the "govder authors policies (`config.toml`)" language in 05/05/14 with this API;
  the shadow→enforce flip (12/02) becomes a `PUT /policies/{id}` toggling `default_action`.

### V2 — Engine-level default-deny mode
- **Why.** The platform's headline is a **default-deny** tool allowlist. Today deny-by-default holds only because
  a missing scoped token blocks credential access — the **PolicyEngine itself is fail-open**. *(Review E1;
  finding "PolicyEngine is default-ALLOW".)*
- **Current.** `evaluate_inner` returns `PolicyDecision::Allow` when no policy matches the credential
  (`policy/mod.rs:138-140`) and on fall-through (`:174`).
- **Proposed.** Add a server config `enforcement.default_action: deny|allow` (default **deny** for govder
  deployments). When `deny`: a credential with **no matching allow policy** returns `Deny("no_policy")`. Keep
  `allow` as an explicit legacy/opt-in mode. (`Policy::deny_all` already exists — this is the engine default +
  not requiring every operator to hand-author a catch-all.) Emit a distinct deny reason so govder can tell
  "denied by policy" from "denied: un-policied credential."
- **Acceptance.** With `default_action: deny`, an `/execute` for a credential with no matching allow policy
  returns Deny; a conformance test asserts "an un-policied credential is denied."
- **govder follow-on.** State the invariant honestly in 05/05 and add it as an acceptance criterion; the
  token-mint flow (V1) can co-install a scoped allow policy so the two layers agree.

### V3 — Value/spend PolicyCondition + cumulative accounting
- **Why.** Refund/spend caps are the most common real agent guardrail and are sold as in-path; vultrino has **no
  value primitive**, so a `$5,000 cap` is documentation-only. *(Review E4; finding "spend-cap unenforceable".)*
- **Current.** `PolicyCondition` = `{UrlMatch, MethodMatch, TimeWindow, RateLimit, And/Or/Not, Always}`; `RateLimit`
  is **count-based**, keyed on `credential_alias`.
- **Proposed.**
  - Add `PolicyCondition::SpendCap { asset: String, per_action_max: Option<u64>, cumulative_max: Option<u64>, window_secs: u64 }`
    (amounts in minor units, e.g. micros — mirror feir's `cost_micros_usd` unit).
  - Add an **amount-extraction** config per `(plugin.action, credential_pattern)`: a JSON-path/template stating
    where the amount + asset live in the request body vultrino proxies (vultrino already parses the body for the
    HTTP plugin). Without an extractor, `SpendCap` fails **closed** (deny) and logs `spend_unparseable`.
  - Add a **spend-accounting store** keyed by `(token_id|principal, asset, window)` with atomic increment on a
    permitted call and window reset.
- **Acceptance.** A refund call whose extracted amount exceeds `per_action_max` is denied; N calls summing past
  `cumulative_max` within the window are denied; accounting resets per window; an unparseable body denies.
- **govder follow-on.** The `is_living` "spend cap" living-policy (06/04) compiles to a `SpendCap` condition;
  remove the "advisory-until-built" caveat once shipped.

### V4 — Principal/agent dimension on policies + per-agent kill
- **Why.** Kill-leg **W3** ("push a Deny for `payments.*` for `agent_refund_bot_v3`") and any per-agent policy are
  inexpressible — policies have no principal field. *(Review E5; finding "W3 inexpressible".)*
- **Current.** `Policy` matches **only** `credential_pattern`; `evaluate(credential_alias, url, method, ctx)` is
  never passed the presenting token/principal.
- **Proposed.** Add optional `principal_pattern: Option<String>` to `Policy` (glob over the presenting `vk_`/`vut_`
  id or an `agent_label` carried on the token); thread the resolved principal into `evaluate`; a policy with a
  `principal_pattern` applies only to matching principals. Add an `agent_label` field to `UseToken`/`ApiKey` so
  govder can bind a token to an agent identity.
- **Acceptance.** govder pushes a Deny scoped to one agent_label and only that agent's calls are denied; other
  agents on the same credential are unaffected.
- **govder follow-on.** W3 becomes a `POST /policies` with `principal_pattern`; restate §6's containment math with
  two genuinely independent kill layers (token revoke **and** per-agent Deny).

---

## 3. P1 requirements

### V5 — Approval SLA / escalation / continuous-reauth + approver identity
- **Why.** govder's time-boxed-lane model (per-criticality SLA, escalate-once-then-deny, continuous
  re-authorization) and all separation-of-duty/complacency analytics have no substrate. *(Review F; findings
  C10/C11.)*
- **Current.** Flat `ApprovalConfig.ttl_secs` (3600), `Pending→Expired` (no escalation), `decided_by` = channel
  label, no re-auth/heartbeat for the approval.
- **Proposed.** Per-request `ttl_secs` + `criticality_class`; a `Pending → Escalated` intermediate state with a
  second bounded window before `Expired`; an optional re-authorization/heartbeat for long-running grants; and a
  **required authenticated approver identity** (IdP subject) captured at decision time on every channel (panel
  session user; out-of-band link **bound to a named identity**, not a bare capability token; GRC/ITSM approver).
- **Acceptance.** A high-criticality request escalates after window 1 and denies after window 2; every decision
  carries a verifiable approver identity; SoD ("approver ≠ requester's owner") is computable.

### V6 — Kill/halt semantics + session registry
- **Why.** "Layered kill switches / abort in-flight session" overstate reality: kill currently takes effect only
  on the agent's **next gated call**. *(Review E6; findings C20/C21.)*
- **Current.** Kill = `set_use_token_revoked` or push a Deny; both checked in `execute_gated` on the next call.
  No session registry, abort channel, or harness callback.
- **Proposed.** A **session registry** keyed by `(agent_label, token_id)` recording in-flight executions; a
  `POST /api/v1/agents/{label}/halt` that (a) revokes the agent's tokens, (b) installs a per-agent Deny (V4), and
  (c) where the harness exposes an abort/pause primitive, fires a registered callback. Document the **achievable
  semantics** ("deny-next-gated-call" vs true preempt) per harness.
- **Acceptance.** Halt blocks the agent's next gated call within the kill-SLA on every path; the registry shows
  what was in-flight; the callback fires for harnesses that support it.

### V7 — Held-secret egress + downstream-credential model + OAuth-rotation hook
- **Why.** vultrino returns the **upstream response body verbatim**, so an agent calling a token/login/STS/secret-
  reading endpoint extracts a live downstream secret; revoking the `vut_` doesn't revoke it. And OAuth2 rotates
  in-path with no govder visibility. *(Review E9/E10; findings int-identity-extra.)*
- **Current.** `http.rs:483-506` returns `{status, headers, body}` upstream-verbatim; OAuth2 refresh inline +
  persisted (`server/mod.rs:485`), no event.
- **Proposed.** (a) **Egress classification** per `(credential, action)` marking responses that can carry a
  secondary secret, with optional response **redaction/blocking**; (b) prefer **downstream-issued short-lived
  credentials** (STS/OAuth2 client-credentials/SVID per call) so a govder revoke maps to a real resource-side
  revoke — document which credential types support it; (c) emit a **rotation event** (and a revoke-propagation
  hook) govder can subscribe to.
- **Acceptance.** A response classified secret-bearing is redacted/blocked per policy; an OAuth rotation emits an
  event; revoke propagates to the downstream where the credential type allows.

### V8 — Action-namespace contract + strictness compilation
- **Why.** govder scopes to business verbs (`payments.refund`) but vultrino actions are `plugin.action` and
  `/execute` hardcodes `http.request`; and `direct` vs `approve-at-checkpoint` both compile to `Prompt`. *(Review
  E7/E8; findings C16/C18.)*
- **Current.** `format!("{plugin}.{action}")` matched against `action_scope`; `PolicyAction ∈ {Allow,Deny,Prompt}`.
- **Proposed.** (a) Accept a govder-supplied **action label** alongside `plugin.action`, or publish the canonical
  namespace + a govder→vultrino mapping contract; stop hardcoding `http.request` on the typed path. (b) Give
  strictness a distinct enforceable artifact: e.g. `direct` = `max_uses:1` + `require_approval` on **every** action
  in the class + a **dual-control** flag (V12), vs `approve-at-checkpoint` = `require_approval` once per checkpoint.
- **Acceptance.** A token scoped to a govder action label resolves correctly; `direct` and `approve-at-checkpoint`
  produce **different** enforced behavior.

### V9 — Ordered/replayable webhook outbox (signed)
- **Why.** govder's webhook contract promises per-subject ordering, monotonic sequence, gap-backfill, replay, and
  a DLQ; vultrino emits fire-and-forget approval webhooks. *(Review H; finding int-publicapi.)*
- **Proposed.** An **outbox** with per-subject ordering, a monotonic `sequence`, a cursor/replay API (e.g. 7-day),
  a dead-letter queue with replay, and `Govder-Signature` HMAC on every delivery. Events: approval requested/
  decided/expired, kill/revoke, policy change.
- **Acceptance.** A consumer that drops offline can replay from its last cursor with no gaps or dupes; deliveries
  verify under the shared HMAC secret.

---

## 4. P2 requirements

- **V10 — Identity integration.** Make the principal vultrino scopes against a **workload identity**: a
  SPIFFE/SPIRE SVID adapter (trust-domain → principal), cloud-IAM adapters (AWS IAM Roles Anywhere / GCP
  workload-identity / Entra workload identities), and an IdP-resolvable owner binding so a `vut_`/`vk_` maps to a
  directory identity (the human owner's OIDC `sub`/SCIM id). Today vultrino has **zero** IdP capability and stores
  static secrets — this is the NHI-as-first-class differentiator's missing half.
- **V11 — Multi-tenancy / per-team partition.** Add a tenant/team dimension across policies, tokens, credentials,
  and approvals so a federated enterprise can run one team in enforce mode while another is observe-only on the
  same vultrino, with isolation. (None today.)
- **V12 — Read-back/event surface + dual-control.** A structured read-back + event stream for the metrics govder
  computes (unauthorized-tool-call attempts/1k runs, approval latency, detect/contain timestamps), and a
  **dual-control** (second-approver / M-of-N) approval mode for Extreme-tier actions.

---

## 5. Sequencing notes for the vultrino dev

- **V1 + V2 are the keystone** — without a write API and engine-level default-deny, govder cannot configure
  enforcement at all, and the headline guarantee is fail-open. Do these first; everything else layers on the
  write API.
- **V3 (spend) and V4 (principal)** are independent of each other and of V1's transport; both extend the policy
  model and the evaluate signature — do them together to avoid two passes over `evaluate`.
- **V7 (held-secret)** is the one with a security-disclosure flavor — prioritize the classification + redaction
  even ahead of the downstream-credential rework.
- Keep changes **backward-compatible** where possible: new `Policy`/`UseToken` fields are `Option`, the
  default-deny mode is config-gated, and the admin API is additive.

---

## 6. govder-side reconciliation (tracked separately)

Once a capability lands, the corresponding govder contract claim moves from "target (requires vultrino Vn)" to
"current." The honest-scoping edits in [05/05](../deep-dives/05-integration-architecture/05-govder-vultrino-enforcement-contract.md)
and [14](../14-ecosystem-operating-system.md) reference this doc by V-number so the two stay in sync. The
remaining govder-only P0s (the **authority-signer** contract, the **enforcement-architecture reconciliation**
`/v1/decide` vs `/execute`, and the **feir retention/erasure** feasibility) are out of scope here — see the
[adversarial-design-review.md](adversarial-design-review.md) roadmap.

---

*Grounded in vultrino source at `/Users/dzcodes/Projects/vultrino` (commit state as reviewed 2026-06-18).
Derived from the adversarial design review; each requirement traces to a confirmed, code-cited finding.*
