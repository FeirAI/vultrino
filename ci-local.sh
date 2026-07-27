#!/usr/bin/env bash
# ci-local.sh — run EXACTLY what .github/workflows/ci.yml runs, on this machine.
#
# WHY THIS FILE EXISTS. On 2026-07-27 a coverage hunt found the repo's zero-warning clippy
# gate RED on a working branch (11 errors across src/ and the test tree). It had been red for
# an unknown length of time, and nothing noticed, because:
#
#   * the repo's documented local loop is `cargo build` / `cargo test` (CLAUDE.md) — clippy is
#     not in it, so no implementer ran the gate; and
#   * ci.yml is the only thing that DOES run it, and this repo has no CI runner attached to the
#     branches the work happens on.
#
# So the gate existed, was correct, and signalled nothing. Two commands, one of them not even
# in ci.yml at the time, would have caught every one of the 11. This script is that loop, kept
# byte-identical to the workflow so the two cannot drift into disagreeing.
#
# Exit codes are captured into VARIABLES, never read through a pipe: `cmd | tee` reports tee's
# status, which is how three separate false greens were manufactured in this program.
#
# Usage:  ./ci-local.sh              # every step; keeps going, reports all failures
#         ./ci-local.sh clippy       # only the steps whose name contains "clippy"
set -uo pipefail

cd "$(cd "$(dirname "$0")" && pwd)" || { echo "ci-local: cannot cd to the repo root" >&2; exit 2; }

FILTER="${1:-}"
FAILED=()
PASSED=()

step() { # step <name> <cmd...>
  local name="$1"; shift
  if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then
    printf '\n\033[33m[skip]\033[0m %s (filtered)\n' "$name"
    return 0
  fi
  printf '\n\033[34m[ci-local]\033[0m %s\n         $ %s\n' "$name" "$*"
  local rc
  "$@"
  rc=$?                     # DIRECT capture. No pipe between the command and this line.
  if [ "$rc" -eq 0 ]; then
    printf '\033[32m[ok]\033[0m    %s (exit 0)\n' "$name"
    PASSED+=("$name")
  else
    printf '\033[31m[fail]\033[0m  %s (exit %d)\n' "$name" "$rc"
    FAILED+=("$name (exit $rc)")
  fi
}

step "cargo build"                    cargo build
step "cargo test"                     cargo test
# Feature-gated: tests/delegate_approval_integration.rs exists ONLY under mock-govder.
step "cargo test --features mock-govder" cargo test --features mock-govder
# The zero-warning gate, both ways. The default invocation does not compile the
# mock-govder-only test target, so it cannot lint it — that gap is what let a
# clippy::type_complexity error sit in the tree while the gate read green.
step "cargo clippy (default features)"  cargo clippy --all-targets -- -D warnings
step "cargo clippy (--all-features)"    cargo clippy --all-targets --all-features -- -D warnings

echo
printf '\033[34m[ci-local]\033[0m %d passed, %d FAILED\n' "${#PASSED[@]}" "${#FAILED[@]}"
if [ "${#FAILED[@]}" -gt 0 ]; then
  printf '  \033[31mFAIL\033[0m %s\n' "${FAILED[@]}"
  exit 1
fi
# A run in which every step was filtered out proves nothing — say so rather than exiting 0
# with an empty ledger (the inert-gate shape this whole pass is about).
if [ "${#PASSED[@]}" -eq 0 ]; then
  printf '  \033[31mFAIL\033[0m no step ran (filter %q matched nothing) — this run proves NOTHING\n' "$FILTER"
  exit 2
fi
exit 0
