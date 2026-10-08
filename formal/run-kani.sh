#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Pinned Kani version. CI installs exactly this (cargo install --locked
# kani-verifier@$KANI_VERSION && cargo kani setup). Bump it here and in ci.yml.
KANI_VERSION="0.67.0"

# Pure-kernel proofs only: no wasmtime. Kani 0.67 ships rustc 1.93.0-nightly;
# wasmtime 48 declares rust-version = 1.95, so default features (wasm-plugins)
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
#
# Each harness is run by its exact, fully qualified path (`--exact`). Without
# `--exact`, Kani matches the name as a substring, so one invocation could check
# several harnesses and the parsed cover line would belong to only one of them.
# As a second guard, an invocation must report exactly one "Checking harness"
# line and exactly one cover summary line.
run_harness() {
  local path="$1" out
  out="$(mktemp)"
  if ! cargo kani "${KANI_ARGS[@]}" --harness "$path" --exact 2>&1 | tee "$out"; then
    echo "run-kani.sh: harness $path FAILED verification" >&2
    rm -f "$out"
    exit 1
  fi
  local checking covers line sat total
  checking="$(grep -cE '^Checking harness ' "$out" || true)"
  covers="$(grep -cE '[0-9]+ of [0-9]+ cover properties satisfied' "$out" || true)"
  line="$(grep -E '[0-9]+ of [0-9]+ cover properties satisfied' "$out" | tail -n 1 || true)"
  rm -f "$out"
  if [ "$checking" -ne 1 ]; then
    echo "run-kani.sh: $path: expected exactly 1 'Checking harness' line, saw $checking" >&2
    exit 1
  fi
  if [ "$covers" -gt 1 ]; then
    echo "run-kani.sh: $path: saw $covers cover summaries, expected exactly 1 (more than one harness ran?)" >&2
    exit 1
  fi
  if [ -z "$line" ]; then
    echo "run-kani.sh: harness $path has no kani::cover! statements (vacuity gate)" >&2
    exit 1
  fi
  sat="$(sed -E 's/.*[^0-9]([0-9]+) of ([0-9]+) cover properties satisfied.*/\1/' <<<"$line")"
  total="$(sed -E 's/.*[^0-9]([0-9]+) of ([0-9]+) cover properties satisfied.*/\2/' <<<"$line")"
  if [ "$total" -lt 1 ] || [ "$sat" -ne "$total" ]; then
    echo "run-kani.sh: harness $path has unsatisfiable cover statements ($sat of $total satisfied)" >&2
    exit 1
  fi
  echo "run-kani.sh: $path OK ($sat of $total covers satisfied)"
}

run_harness formal_kernel::kani_proofs::direct_permit_truth_table_is_exact
run_harness formal_kernel::kani_proofs::execution_epoch_never_wraps
run_harness approval::kani_recipe_proofs::zero_approvers_never_satisfy
run_harness approval::kani_recipe_proofs::satisfaction_never_underfills_a_slot
run_harness approval::kani_recipe_proofs::greedy_matches_exhaustive_assignment_at_bound_5
run_harness approval::kani_recipe_proofs::satisfaction_is_monotone_in_availability
run_harness approval::kani_recipe_proofs::malformed_recipes_never_satisfy
run_harness approval::kani_recipe_proofs::recipe_cap_prevents_need_overflow
run_harness approval::kani_recipe_proofs::class_slot_contribution_agrees_with_satisfaction
run_harness plugins::http::ssrf_spec::kani_ssrf_proofs::ipv4_classifier_equals_spec_over_all_u32
run_harness plugins::http::ssrf_spec::kani_ssrf_proofs::ipv6_classifier_equals_spec_over_all_u128

# Every #[kani::proof] must be listed above, or it would silently not run.
# The script has already cd'd to the repo root, so name itself by that path
# (a relative "$0" would break when run from inside formal/).
listed="$(grep -c '^run_harness [a-z]' formal/run-kani.sh)"
actual="$(grep -rEc '#\[kani::proof\]' src | awk -F: '{s+=$2} END {print s}')"
if [ "$listed" -ne "$actual" ]; then
  echo "run-kani.sh: $actual #[kani::proof] harnesses in src but $listed run" >&2
  exit 1
fi
