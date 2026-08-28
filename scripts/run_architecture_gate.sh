#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_binary="${COH_GO_BIN:?COH_GO_BIN is required}"
temporary="$(mktemp "${GOTMPDIR}/archcheck-ci.XXXXXX")"
canonical="$(mktemp "${GOTMPDIR}/archcheck-canonical.XXXXXX")"
cancel_report="$(mktemp "${GOTMPDIR}/archcheck-cancel.XXXXXX")"
cancel_error="$(mktemp "${GOTMPDIR}/archcheck-cancel-error.XXXXXX")"
report="$(mktemp "${GOTMPDIR}/archcheck-report.XXXXXX")"
cleanup() { rm -f "${temporary}" "${canonical}" "${cancel_report}" "${cancel_error}" "${report}"; }
trap cleanup EXIT

cd "${repo_root}"
"${go_binary}" build -trimpath -o "${temporary}" ./cmd/archcheck
chmod 0500 "${temporary}"

"${temporary}" -root "${repo_root}" -go "${go_binary}" -mode canonical > "${canonical}"
fixture=contracts/architecture/v1/fixtures/valid/workspace-contract.canonical.json
expected_canonical="$(<"${fixture}")"
actual_canonical="$(<"${canonical}")"
fixture_bytes="$(/usr/bin/wc -c < "${fixture}" | /usr/bin/tr -d ' ')"
canonical_bytes="$(/usr/bin/wc -c < "${canonical}" | /usr/bin/tr -d ' ')"
trailing_byte="$(/usr/bin/tail -c 1 "${fixture}" | /usr/bin/od -An -tu1 | /usr/bin/tr -d ' ')"
if [[ "${expected_canonical}" != "${actual_canonical}" ]] ||
  ! { [[ "${fixture_bytes}" == "${canonical_bytes}" ]] ||
    { (( fixture_bytes == canonical_bytes + 1 )) && [[ "${trailing_byte}" == "10" ]]; }; }; then
  echo "Architecture canonical output differs from its locked fixture" >&2
  exit 2
fi

set +e
"${temporary}" -root "${repo_root}" -go "${go_binary}" -format json -timeout 1ns > "${cancel_report}" 2> "${cancel_error}"
cancel_status=$?
set -e
if (( cancel_status != 130 )) ||
  ! grep -q '"outcome": "canceled"' "${cancel_report}" ||
  ! grep -q '"failure_code": "canceled"' "${cancel_report}" ||
  ! grep -q '"contract_digest":' "${cancel_report}"; then
  echo "Architecture cancellation contract failed" >&2
  exit 2
fi

"${temporary}" -root "${repo_root}" -go "${go_binary}" -format json > "${report}"
cat "${report}"
"${repo_root}/scripts/check_model_surface_boundary.sh" "${repo_root}"
