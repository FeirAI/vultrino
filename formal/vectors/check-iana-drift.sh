#!/usr/bin/env bash
# Compare the committed IANA special-purpose registry snapshots byte for byte
# with the files IANA publishes today. Run by the scheduled `iana-snapshot-drift`
# CI job. A difference fails the job: refresh the snapshots, re-derive the spec
# tables in src/plugins/http/ssrf_spec.rs and the IPV4_BLOCKED / IPV6_BLOCKED
# tables in src/plugins/http.rs, and update formal/vectors/README.md. A download
# failure also fails the job, so a registry outage shows up as red, never as a
# silent pass.
set -euo pipefail

cd "$(dirname "$0")/../.."

base="https://www.iana.org/assignments"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

status=0
for reg in iana-ipv4-special-registry iana-ipv6-special-registry; do
  file="$reg-1.csv"
  committed="formal/vectors/$file"
  if ! curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --retry 5 --retry-all-errors --max-time 60 \
      -o "$tmp/$file" "$base/$reg/$file"; then
    echo "check-iana-drift: could not download $base/$reg/$file" >&2
    exit 1
  fi
  if [ ! -s "$tmp/$file" ]; then
    echo "check-iana-drift: downloaded $file is empty" >&2
    exit 1
  fi
  if cmp -s "$committed" "$tmp/$file"; then
    echo "check-iana-drift: $file unchanged ($(sha256sum "$committed" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$committed" | cut -d' ' -f1))"
  else
    echo "check-iana-drift: $file DIFFERS from the live IANA registry" >&2
    diff -u "$committed" "$tmp/$file" >&2 || true
    status=1
  fi
done
exit "$status"
