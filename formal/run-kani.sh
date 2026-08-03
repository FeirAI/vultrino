#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Pure-kernel proofs only — no wasmtime. Kani 0.67 ships rustc 1.93.0-nightly;
# wasmtime 47 declares rust-version = 1.94, so default features (wasm-plugins)
# cannot be compiled under Kani's toolchain.
KANI_ARGS=(--no-default-features)

run_harness() {
  cargo kani "${KANI_ARGS[@]}" --harness "$1"
}

run_harness direct_permit_truth_table_is_exact
run_harness execution_epoch_never_wraps
run_harness zero_approvers_never_satisfy
run_harness satisfaction_never_underfills_a_slot
run_harness greedy_matches_exhaustive_assignment_at_bound_5
run_harness satisfaction_is_monotone_in_availability
run_harness malformed_recipes_never_satisfy
run_harness recipe_cap_prevents_need_overflow
run_harness class_slot_contribution_agrees_with_satisfaction
