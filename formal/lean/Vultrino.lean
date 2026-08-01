import Vultrino.Approval.ExecutionSafety
import Vultrino.Approval.Authority
import Vultrino.Credentials.Confinement

/-!
The machine-checked entry point for Vultrino's critical-boundary model.

`lake build` checks both independent theorems:

* every reachable execution is policy-authorized and, when required, carries a
  fresh, unused, exact-request-bound approval whose recorded sign-offs satisfy
  one whole authoritative recipe;
* every reachable raw-credential flow terminates only at the encrypted vault,
  the trusted injector, or the specifically authorized upstream. Every public
  payload carries a proof that none of the declared secret byte-forms occurs.
* broker-verified approval identity is exact-bound to tenant, approval, outcome,
  subject, class, route, host, and body digest; legacy bearer-key claims carry no
  independent-identity witness.

The Rust implementation must refine this model. The proof/refinement boundary
and the deliberately explicit trusted-computing-base assumptions are documented
in `formal/lean/README.md`.
-/
