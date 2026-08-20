#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
temporary="$(/usr/bin/mktemp -d "${GOTMPDIR:?GOTMPDIR is required}/coh-license-contract.XXXXXX")"
cleanup() { /bin/rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM
canonical="${repo_root}/ci/licenses.allow"

expect_status() {
  local expected=$1
  local label=$2
  shift 2
  local status
  set +e
  "$@" > "${temporary}/${label}.out" 2>&1
  status=$?
  set -e
  [[ "${status}" -eq "${expected}" ]] || { echo "${label} returned ${status}; expected ${expected}" >&2; exit 1; }
}

malformed="${temporary}/malformed.allow"
/usr/bin/awk 'NR == 2 { print $1, $2, $3, $4; next } { print }' "${canonical}" > "${malformed}"
expect_status 64 malformed "${repo_root}/scripts/check_licenses.sh" "${malformed}"

duplicate="${temporary}/duplicate.allow"
/bin/cp "${canonical}" "${duplicate}"
/usr/bin/sed -n '2p' "${canonical}" >> "${duplicate}"
expect_status 64 duplicate "${repo_root}/scripts/check_licenses.sh" "${duplicate}"

extra="${temporary}/extra.allow"
/bin/cp "${canonical}" "${extra}"
printf 'artifact third_party/forbidden.bin MIT %064d https://example.invalid/\n' 0 >> "${extra}"
expect_status 2 extra "${repo_root}/scripts/check_licenses.sh" "${extra}"

digest_drift="${temporary}/digest-drift.allow"
/usr/bin/awk '$1 == "artifact" { $4=sprintf("%064d", 0) } { print }' "${canonical}" > "${digest_drift}"
expect_status 2 digest-drift "${repo_root}/scripts/check_licenses.sh" "${digest_drift}"

forbidden="${temporary}/forbidden.allow"
/usr/bin/awk '$1 == "module" { $3="GPL-3.0-only" } { print }' "${canonical}" > "${forbidden}"
expect_status 2 forbidden-license "${repo_root}/scripts/check_licenses.sh" "${forbidden}"

echo "License negative contract tests: passed"
