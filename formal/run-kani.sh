#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo kani --harness direct_permit_truth_table_is_exact
cargo kani --harness execution_epoch_never_wraps
cargo kani --harness zero_approvers_never_satisfy
cargo kani --harness satisfaction_never_underfills_a_slot
cargo kani --harness greedy_matches_exhaustive_assignment_at_bound_5
cargo kani --harness satisfaction_is_monotone_in_availability
cargo kani --harness malformed_recipes_never_satisfy
cargo kani --harness recipe_cap_prevents_need_overflow
cargo kani --harness class_slot_contribution_agrees_with_satisfaction
