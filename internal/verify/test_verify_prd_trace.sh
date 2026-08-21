#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
verifier="$repo_root/scripts/verify_prd_trace.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/coh-prd-trace-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local name=$1
  local fixture="$tmp/$name"

  mkdir -p \
    "$fixture/outputs" \
    "$fixture/docs/design" \
    "$fixture/docs/adr" \
    "$fixture/docs/security"
  cp "$repo_root/outputs/COH-PRD.md" "$fixture/outputs/"
  cp "$repo_root/outputs/COH-Linear-Backlog.md" "$fixture/outputs/"
  cp "$repo_root/docs/design/product-contract.md" "$fixture/docs/design/"
  cp "$repo_root/docs/adr/0001-trust-boundaries.md" "$fixture/docs/adr/"
  cp "$repo_root/docs/adr/0001-trust-boundaries-verification.md" "$fixture/docs/adr/"
  cp "$repo_root/docs/security/action-tier-decision-table.md" "$fixture/docs/security/"
  printf '%s\n' "$fixture"
}

expect_failure() {
  local name=$1
  local expected_message=$2
  local fixture=$3
  local output="$tmp/$name.output"

  if "$verifier" "$fixture" >"$output" 2>&1; then
    printf 'error: negative test unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  rg -q "$expected_message" "$output" || {
    printf 'error: negative test %s returned the wrong diagnostic\n' "$name" >&2
    sed -n '1,80p' "$output" >&2
    exit 1
  }
  printf 'ok: %s rejected\n' "$name"
}

baseline=$(make_fixture baseline)
"$verifier" "$baseline"
printf 'ok: current numbered PRD outline accepted\n'

bad_mapping=$(make_fixture bad-mapping)
sed '/COH-E01-02 — Record architecture/ s/Requirements SEC-001, SEC-002, SEC-017, SEC-026/Requirements SEC-001/' \
  "$bad_mapping/outputs/COH-Linear-Backlog.md" > "$bad_mapping/outputs/backlog.new"
mv "$bad_mapping/outputs/backlog.new" "$bad_mapping/outputs/COH-Linear-Backlog.md"
expect_failure bad-mapping 'COH-E01-02 has a missing, extra, or duplicate backlog mapping' "$bad_mapping"

bad_heading=$(make_fixture bad-heading)
sed 's/^## Decision drivers$/## Design considerations/' \
  "$bad_heading/docs/adr/0001-trust-boundaries.md" > "$bad_heading/docs/adr/adr.new"
mv "$bad_heading/docs/adr/adr.new" "$bad_heading/docs/adr/0001-trust-boundaries.md"
expect_failure bad-heading "COH-E01-02 heading 'Decision drivers' is missing" "$bad_heading"

bad_trace=$(make_fixture bad-trace)
sed 's/`SEC-026`/`SEC-025`/' \
  "$bad_trace/docs/adr/0001-trust-boundaries.md" > "$bad_trace/docs/adr/adr.new"
mv "$bad_trace/docs/adr/adr.new" "$bad_trace/docs/adr/0001-trust-boundaries.md"
expect_failure bad-trace 'COH-E01-02 traceability table does not exactly match' "$bad_trace"

printf 'verify_prd_trace tests: 1 positive, 3 negative, failures=0\n'
