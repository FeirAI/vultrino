#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Pinned Kani version. CI installs exactly this (cargo install --locked
# kani-verifier@$KANI_VERSION && cargo kani setup). Bump it here and in ci.yml.
KANI_VERSION="0.67.0"

# Pure-kernel proofs only: no wasmtime. Kani 0.67 ships rustc 1.93.0-nightly;
# wasmtime 47 declares rust-version = 1.94, so default features (wasm-plugins)
# cannot be compiled under Kani's toolchain.
KANI_ARGS=(--no-default-features)

have="$(cargo kani --version | awk '{print $2}')"
if [ "$have" != "$KANI_VERSION" ]; then
  echo "run-kani.sh: expected kani $KANI_VERSION, found $have" >&2
  exit 1
fi

# Vacuity gate. Kani has no flag that fails a run on an unsatisfiable
# kani::cover!, so each harness's summary is parsed: it must report at least
# one cover property and "N of N cover properties satisfied". A harness whose
# assumptions became contradictory, or whose branches are unreachable, shows
# up as N < M (or no cover line at all) and fails here.
run_harness() {
  local name="$1" out
  out="$(mktemp)"
  if ! cargo kani "${KANI_ARGS[@]}" --harness "$name" 2>&1 | tee "$out"; then
    echo "run-kani.sh: harness $name FAILED verification" >&2
    rm -f "$out"
    exit 1
  fi
  local line sat total
  line="$(grep -E '[0-9]+ of [0-9]+ cover properties satisfied' "$out" | tail -n 1 || true)"
  rm -f "$out"
  if [ -z "$line" ]; then
    echo "run-kani.sh: harness $name has no kani::cover! statements (vacuity gate)" >&2
    exit 1
  fi
  sat="$(sed -E 's/.*[^0-9]([0-9]+) of ([0-9]+) cover properties satisfied.*/\1/' <<<"$line")"
  total="$(sed -E 's/.*[^0-9]([0-9]+) of ([0-9]+) cover properties satisfied.*/\2/' <<<"$line")"
  if [ "$total" -lt 1 ] || [ "$sat" -ne "$total" ]; then
    echo "run-kani.sh: harness $name has unsatisfiable cover statements ($sat of $total satisfied)" >&2
    exit 1
  fi
  echo "run-kani.sh: $name OK ($sat of $total covers satisfied)"
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

# Every #[kani::proof] must be listed above, or it would silently not run.
listed="$(grep -c '^run_harness [a-z]' "$0")"
actual="$(grep -rEc '#\[kani::proof\]' src | awk -F: '{s+=$2} END {print s}')"
if [ "$listed" -ne "$actual" ]; then
  echo "run-kani.sh: $actual #[kani::proof] harnesses in src but $listed run" >&2
  exit 1
fi
