import Vultrino.Approval.ExecutionSafety
import Vultrino.Approval.Authority
import Vultrino.Approval.ActionAuthority
import Vultrino.Approval.Criticality
import Vultrino.Credentials.Confinement
import Vultrino.Action.MethodAuthority
import Vultrino.Configuration.Startup

/-!
The machine-checked entry point for Vultrino's critical-boundary model.

`lake build` checks both independent theorems:

* every reachable execution is policy-authorized and, when required, carries a
  fresh, unused, exact-request-bound approval whose recorded sign-offs satisfy
  one whole authoritative recipe;
* every reachable raw-credential flow terminates only at the encrypted vault,
  the trusted injector, or the specifically authorized upstream. Every public
  payload carries a proof that none of the declared secret byte-forms occurs,
  and arbitrary accepted streaming chunks preserve that predicate over their
  concatenated output rather than only within each chunk. Retaining the final
  `max_form_len - 1` released bytes is proved sufficient for the incremental
  boundary check used by the Rust adapter.
* broker-verified approval identity is exact-bound to tenant, approval, outcome,
  subject, class, route, host, and body digest; legacy bearer-key claims carry no
  independent-identity witness.
* a canonical plugin verb shared by configured business labels cannot fall back
  to weaker numeric approval when no exact canonical rule is found.
* a named internal-HTTP capability executes only its unique operator-pinned
  method; any caller-supplied method is rejected before composition.
* a declared human-floor capability, unavailable catalog, shared canonical verb,
  or (in production strict posture) undeclared action can never produce direct
  execution authority; production direct authority implies an exact reversible
  declaration for the executing credential and action, and an approval can resume
  only while that catalog authority class remains unchanged. Disabled approvals
  refuse rather than bypass.
* a started production web process has strict catalog enforcement and a configured
  policy-hash key, and an enabled workload exchange has a valid startup-snapshotted
  verifier.

The Rust implementation must refine this model. The proof/refinement boundary
and the deliberately explicit trusted-computing-base assumptions are documented
in `formal/lean/README.md`.
-/
