#!/usr/bin/env bash
# Independently check the compiled Lean environment with nanoda.
#
# Both tools are pinned by full commit. The lean-action nanoda helper currently
# clones moving branches whose export/checker formats can diverge; this gate is
# intentionally reproducible instead.
set -euo pipefail

LEAN4EXPORT_REV="a3e35a584f59b390667db7269cd37fca8575e4bf" # Lean 4.30.0 exporter
NANODA_REV="ddfac2bf5a7b56cb46e141494427ff3dd55963c7"      # format 3.1 checker

script_dir="$(cd "$(dirname "$0")" && pwd)"
cache_base="${XDG_CACHE_HOME:-${HOME}/.cache}"
cache_root="${cache_base}/feir-formal"
exporter_dir="${cache_root}/lean4export"
nanoda_dir="${cache_root}/nanoda_lib"
export_file="${cache_root}/vultrino.export"
config_file="${cache_root}/nanoda-vultrino.json"

mkdir -p "$cache_root"

prepare_checkout() {
  local url="$1"
  local directory="$2"
  local revision="$3"
  if [ ! -d "${directory}/.git" ]; then
    git clone --quiet --filter=blob:none --no-checkout "$url" "$directory"
  fi
  git -C "$directory" fetch --quiet origin "$revision"
  git -C "$directory" checkout --quiet --detach "$revision"
  test "$(git -C "$directory" rev-parse HEAD)" = "$revision"
}

prepare_checkout \
  https://github.com/leanprover/lean4export.git \
  "$exporter_dir" \
  "$LEAN4EXPORT_REV"
prepare_checkout \
  https://github.com/ammkrn/nanoda_lib.git \
  "$nanoda_dir" \
  "$NANODA_REV"

toolchain="$(< "${script_dir}/lean-toolchain")"
(
  cd "$exporter_dir"
  ELAN_TOOLCHAIN="$toolchain" lake build
)

if command -v sfw >/dev/null 2>&1; then
  sfw cargo build --release --locked --manifest-path "${nanoda_dir}/Cargo.toml"
else
  cargo build --release --locked --manifest-path "${nanoda_dir}/Cargo.toml"
fi

(
  cd "$script_dir"
  lake build --wfail
  lake env "${exporter_dir}/.lake/build/bin/lean4export" Vultrino > "$export_file"
)

command -v jq >/dev/null 2>&1
jq -n --arg export_file "$export_file" '{
  export_file_path: $export_file,
  use_stdin: false,
  permitted_axioms: ["propext", "Classical.choice", "Quot.sound", "Lean.trustCompiler"],
  unpermitted_axiom_hard_error: false,
  nat_extension: true,
  string_extension: true,
  print_success_message: true
}' > "$config_file"

"${nanoda_dir}/target/release/nanoda_bin" "$config_file"
