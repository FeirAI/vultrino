# Security policy

Vultrino is a credential proxy. Treat reports that can expose secrets, bypass approval/evidence floors, or weaken tenant isolation as high priority.

## Supported versions

| Version | Supported |
|---|---|
| `main` / latest release | Yes |
| Older tagged releases | Best-effort; critical fixes may be backported |

## Reporting a vulnerability

Please **do not** file a public GitHub issue for security bugs.

Prefer one of:

1. GitHub **Private vulnerability reporting** on this repository (Security → Report a vulnerability), once enabled on the org, or
2. Email **security@feir.ai** with:
   - a short description of the impact
   - reproduction steps or a minimal PoC
   - affected commit / release if known
   - whether you plan a public write-up and your preferred disclosure timeline

We aim to acknowledge within **3 business days** and to provide a remediation plan or fix timeline once the report is confirmed.

## Scope (examples)

In scope:

- Credential material reaching agent/MCP/HTTP responses, logs, or untrusted plugins
- Authentication/authorization bypass on admin, MCP, or execute paths
- Approval, use-token, or evidence-floor bypasses
- SSRF / redirect / host-binding escapes on connectors
- Vault decryption or storage integrity failures under the documented threat model

Out of scope (unless you show a Vultrino-specific amplification):

- Issues in upstream providers an operator deliberately authorized
- Compromise of the host OS, operator-held vault password, or IdP that asserts human identity
- Denial of service without a security boundary bypass

## Safe harbor

We will not pursue legal action against researchers who:

- make a good-faith effort to avoid privacy violations and service disruption
- report promptly and keep details private until a fix is available or we agree on disclosure
- do not access data that is not theirs beyond what is needed to demonstrate the issue

Thank you for helping keep agents away from raw credentials.
