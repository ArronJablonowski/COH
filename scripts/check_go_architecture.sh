#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/go_ssd_env.sh
source "${repo_root}/scripts/lib/go_ssd_env.sh"

cd "${repo_root}"
archcheck_bin="$(mktemp "${GOTMPDIR}/coh-archcheck.XXXXXX")"
cleanup() {
  rm -f "${archcheck_bin}"
}
trap cleanup EXIT

"${COH_GO_ROOT}/bin/go" build -o "${archcheck_bin}" ./cmd/archcheck
set +e
"${archcheck_bin}" \
  -contract contracts/architecture/v1/workspace-contract.json \
  -go "${COH_GO_ROOT}/bin/go" \
  -root "${repo_root}" \
  "$@"
status=$?
set -e
exit "${status}"
