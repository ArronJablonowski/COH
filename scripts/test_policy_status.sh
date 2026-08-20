#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=lib/quality_status.sh
source "${repo_root}/scripts/lib/quality_status.sh"
temporary="$(/usr/bin/mktemp -d "${GOTMPDIR:?GOTMPDIR is required}/coh-status-contract.XXXXXX")"
cleanup() { /bin/rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM

expect_raw_finding_maps_to_denial() {
  local label=$1
  shift
  local status
  set +e
  "$@" > "${temporary}/${label}.log" 2>&1
  status=$?
  set -e
  [[ "${status}" -eq 1 ]] || { echo "${label} fixture returned ${status}; expected tool finding 1" >&2; exit 1; }
  [[ "$(coh_normalize_stage_status denial "${status}")" -eq 2 ]] || { echo "${label} did not normalize to denied" >&2; exit 1; }
}

fixture="${temporary}/fixture"
/bin/mkdir -p "${fixture}/unit" "${fixture}/vet" "${fixture}/static"
printf 'module example.invalid/coh-quality-fixture\n\ngo %s\n' "${COH_CI_GO_VERSION}" > "${fixture}/go.mod"
printf 'package unitfixture\n\nimport "testing"\n\nfunc TestSyntheticFailure(t *testing.T) { t.Fatal("synthetic") }\n' > "${fixture}/unit/fail_test.go"
printf 'package vetfixture\n\nimport "fmt"\n\nfunc BadFormat() { fmt.Printf("%%d", "not-an-integer") }\n' > "${fixture}/vet/bad.go"
printf 'package staticfixture\n\nfunc unusedSyntheticFunction() {}\n' > "${fixture}/static/unused.go"

expect_raw_finding_maps_to_denial unit env GOWORK=off "${COH_GO_BIN}" test -count=1 "${fixture}/unit"
expect_raw_finding_maps_to_denial vet env GOWORK=off "${COH_GO_BIN}" vet "${fixture}/vet"
if [[ "${COH_CI_LANE}" == baseline ]]; then
  expect_raw_finding_maps_to_denial static env GOWORK=off "${GOBIN}/staticcheck" -checks=all -go=1.26 -tests=true "${fixture}/static"
fi

tidy_fixture="${temporary}/tidy-fixture"
/bin/mkdir -p "${tidy_fixture}"
printf 'module example.invalid/coh-tidy-fixture\n\ngo %s\n\nrequire rsc.io/quote v1.5.2\n' "${COH_CI_GO_VERSION}" > "${tidy_fixture}/go.mod"
printf 'package fixture\n' > "${tidy_fixture}/fixture.go"
expect_raw_finding_maps_to_denial tidy env GOWORK=off "${COH_GO_BIN}" -C "${tidy_fixture}" mod tidy -diff

integrity_fixture="${temporary}/integrity-fixture"
/bin/mkdir -p "${integrity_fixture}"
printf 'module example.invalid/coh-integrity-fixture\n\ngo invalid\n' > "${integrity_fixture}/go.mod"
expect_raw_finding_maps_to_denial module-integrity env GOWORK=off "${COH_GO_BIN}" -C "${integrity_fixture}" list -mod=readonly -m all

printf 'github.com/ArronJablonowski/COH (main)\n' > "${temporary}/actual"
printf 'example.invalid/forbidden v1.0.0\n' > "${temporary}/allow"
set +e
"${repo_root}/scripts/check_dependency_allowlist.sh" "${temporary}/allow" "${temporary}/actual" >/dev/null 2>&1
status=$?
set -e
[[ "${status}" -eq 2 ]] || { echo "dependency allowlist drift returned ${status}; expected denial" >&2; exit 1; }

echo "Typed policy-status contract tests: passed"
