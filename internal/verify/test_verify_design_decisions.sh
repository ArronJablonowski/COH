#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
verifier="$root/scripts/verify_design_decisions.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/coh-design-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local name=$1
  local destination="$tmp/$name"
  mkdir -p "$destination/docs/design" "$destination/docs/adr" \
    "$destination/docs/security" "$destination/outputs"
  cp "$root/docs/design/product-contract.md" "$destination/docs/design/"
  cp "$root/docs/design/platform-support-matrix.md" "$destination/docs/design/"
  cp "$root/docs/adr/0001-trust-boundaries.md" "$destination/docs/adr/"
  cp "$root/docs/adr/0001-trust-boundaries-verification.md" "$destination/docs/adr/"
  cp "$root/docs/security/action-tier-decision-table.md" "$destination/docs/security/"
  cp "$root/outputs/COH-PRD.md" "$destination/outputs/"
  printf '%s\n' "$destination"
}

expect_failure() {
  local name=$1
  local fixture=$2
  if "$verifier" "$fixture" >"$tmp/$name.out" 2>&1; then
    printf 'FAIL %s: invalid fixture was accepted\n' "$name" >&2
    exit 1
  fi
  printf 'ok: %s rejected\n' "$name"
}

positive=$(make_fixture positive)
"$verifier" "$positive"
printf 'ok: current decisions accepted\n'

missing_tier=$(make_fixture missing-tier)
perl -0pi -e 's/^\| \*\*T4 —.*\n//m' \
  "$missing_tier/docs/security/action-tier-decision-table.md"
expect_failure missing-tier "$missing_tier"

missing_boundary=$(make_fixture missing-boundary)
perl -0pi -e 's/^\| Validator \|.*\n//m' \
  "$missing_boundary/docs/adr/0001-trust-boundaries.md"
expect_failure missing-boundary "$missing_boundary"

ambiguous_staffing=$(make_fixture ambiguous-staffing)
printf '\nT4 remains unavailable until a second eligible human is enrolled.\n' \
  >> "$ambiguous_staffing/docs/design/product-contract.md"
expect_failure ambiguous-staffing "$ambiguous_staffing"

bad_status=$(make_fixture bad-status)
perl -0pi -e 's/\| Status \| Ready for approval \|/| Status | Accepted |/' \
  "$bad_status/docs/security/action-tier-decision-table.md"
expect_failure bad-status "$bad_status"

missing_capability=$(make_fixture missing-capability)
perl -0pi -e 's/public capability-surface/public surface/' \
  "$missing_capability/docs/adr/0001-trust-boundaries-verification.md"
expect_failure missing-capability "$missing_capability"

missing_windows=$(make_fixture missing-windows)
perl -0pi -e 's/^\| Windows host \|.*\n//m' \
  "$missing_windows/docs/design/platform-support-matrix.md"
expect_failure missing-windows "$missing_windows"

docker_required=$(make_fixture docker-required)
perl -0pi -e 's/Docker absence must not alter native APIs/Docker availability may alter native APIs/' \
  "$docker_required/docs/design/platform-support-matrix.md"
expect_failure docker-required "$docker_required"

printf 'verify_design_decisions tests: 1 positive, 7 negative, failures=0\n'
