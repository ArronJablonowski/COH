#!/bin/bash

set -euo pipefail

workflow=${COH_WORKFLOW_FILE:-.github/workflows/quality.yml}
expected_digest=8f20736011aa5724835459b24bbc02fe626e0859d17e93773011c05e1d23515a
test -f "${workflow}"
actual_digest="$("${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" -mode digest -input "${workflow}")"
[[ "${actual_digest}" == "${expected_digest}" ]] || { echo "Workflow differs from the reviewed closed contract" >&2; exit 2; }
"${GOBIN}/actionlint" -config-file /dev/null -shellcheck= -pyflakes= "${workflow}"
"${GOBIN}/shellcheck" --severity=warning --rcfile=/dev/null scripts/*.sh scripts/lib/*.sh

if grep -En 'pull_request_target|persist-credentials:[[:space:]]*true|permissions:[[:space:]]*write-all|id-token:[[:space:]]*write|contents:[[:space:]]*write' "${workflow}"; then
  echo "Workflow contains a forbidden privilege pattern" >&2
  exit 2
fi
if ! grep -Eq '^permissions:$' "${workflow}" || ! grep -Eq '^[[:space:]]+contents:[[:space:]]+read$' "${workflow}"; then
  echo "Workflow must declare contents: read" >&2
  exit 2
fi
if ! grep -Eq 'actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd' "${workflow}" ||
  ! grep -Eq 'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e' "${workflow}" ||
  ! grep -Eq 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' "${workflow}"; then
  echo "Workflow actions must use reviewed full-length pins" >&2
  exit 2
fi
if ! grep -Eq 'persist-credentials:[[:space:]]+false' "${workflow}"; then
  echo "Checkout credentials must not persist" >&2
  exit 2
fi
if ! grep -Eq 'fetch-depth:[[:space:]]+0' "${workflow}"; then
  echo "Secret history gate requires fetch-depth: 0" >&2
  exit 2
fi
if grep -En '\$\{\{[[:space:]]*secrets\.' "${workflow}"; then
  echo "Quality workflow cannot consume repository secrets" >&2
  exit 2
fi
while read -r action; do
  case "${action}" in
    actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd|actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e|actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a) ;;
    *) echo "Unapproved workflow action: ${action}" >&2; exit 2 ;;
  esac
done < <(grep -E '^[[:space:]]+uses:' "${workflow}" | sed -E 's/^[[:space:]]+uses:[[:space:]]*//; s/[[:space:]]+#.*$//')
if [[ "$(grep -Ec '^[[:space:]]+uses:' "${workflow}")" -ne 3 ]]; then
  echo "Quality workflow must use exactly the three reviewed actions" >&2
  exit 2
fi
if grep -En 'run:.*\$\{\{' "${workflow}"; then
  echo "GitHub expressions cannot be interpolated directly into shell commands" >&2
  exit 2
fi

echo "workflow-policy summary: syntax=passed permissions=least-privilege pins=passed"
