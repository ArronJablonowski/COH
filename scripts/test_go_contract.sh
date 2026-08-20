#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/go_ssd_env.sh
source "${repo_root}/scripts/lib/go_ssd_env.sh"
go_cmd="${COH_GO_ROOT}/bin/go"

cd "${repo_root}"

for go_path in "${GOCACHE}" "${GOMODCACHE}" "${GOPATH}" "${GOTMPDIR}" "${TMPDIR}"; do
  if [[ "${go_path}" != "${COH_TOOLCHAIN_ROOT}"/* ]]; then
    echo "Go mutable path escapes external toolchain root: ${go_path}" >&2
    exit 1
  fi
done
[[ "${TMPDIR}" == "${GOTMPDIR}" ]] || { echo "TMPDIR must equal the SSD-backed GOTMPDIR" >&2; exit 1; }

unformatted="$(${COH_GO_ROOT}/bin/gofmt -l cmd internal)"
if [[ -n "${unformatted}" ]]; then
  echo "Go formatting required:" >&2
  echo "${unformatted}" >&2
  exit 1
fi

"${go_cmd}" vet ./...
"${go_cmd}" test ./...
"${go_cmd}" test -race ./...
"${repo_root}/scripts/check_go_architecture.sh"

canonical_tmp="$(mktemp "${GOTMPDIR}/coh-canonical.XXXXXX")"
timeout_report="$(mktemp "${GOTMPDIR}/coh-timeout-report.XXXXXX")"
timeout_error="$(mktemp "${GOTMPDIR}/coh-timeout-error.XXXXXX")"
cleanup() {
  rm -f "${canonical_tmp}" "${timeout_report}" "${timeout_error}"
}
trap cleanup EXIT

"${repo_root}/scripts/check_go_architecture.sh" -mode canonical >"${canonical_tmp}"
expected_canonical="$(<contracts/architecture/v1/fixtures/valid/workspace-contract.canonical.json)"
actual_canonical="$(<"${canonical_tmp}")"
if [[ "${expected_canonical}" != "${actual_canonical}" ]]; then
  echo "Canonical workspace fixture differs from encoder output" >&2
  exit 1
fi

set +e
"${repo_root}/scripts/check_go_architecture.sh" -format json -timeout 1ns >"${timeout_report}" 2>"${timeout_error}"
timeout_status=$?
set -e
if [[ "${timeout_status}" -ne 130 ]]; then
  echo "Expected architecture timeout exit 130; got ${timeout_status}" >&2
  exit 1
fi
if ! grep -q '"outcome": "canceled"' "${timeout_report}" ||
  ! grep -q '"failure_code": "canceled"' "${timeout_report}" ||
  ! grep -q '"contract_digest":' "${timeout_report}"; then
  echo "Canceled architecture report lost required provenance" >&2
  exit 1
fi

echo "COH-E02-01 Go contract verification passed"
