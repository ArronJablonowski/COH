#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export COH_CI_LANE="${1:-${COH_CI_LANE:-baseline}}"
# shellcheck source=lib/ci_env.sh
source "${repo_root}/scripts/lib/ci_env.sh"

artifact_root="${COH_CI_ARTIFACT_DIR}"
quality_binary="$(mktemp "${GOTMPDIR}/qualitygate.XXXXXX")"
cleanup() { rm -f "${quality_binary}"; }
trap cleanup EXIT

"${COH_GO_BIN}" build -trimpath -o "${quality_binary}" ./cmd/qualitygate
chmod 0500 "${quality_binary}"
export COH_QUALITYGATE_BIN="${quality_binary}"

"${repo_root}/scripts/bootstrap_ci_tools.sh"
# shellcheck source=prepare_vulndb.sh
source "${repo_root}/scripts/prepare_vulndb.sh"

run_directory="$(mktemp -d "${artifact_root}/run.XXXXXX")"
export COH_CI_ARTIFACT_DIR="${run_directory}"

set +e
"${quality_binary}" \
  -mode run \
  -root "${repo_root}" \
  -lane "${COH_CI_LANE}" \
  -artifact-dir "${run_directory}" \
  -output "${run_directory}/quality-report.json"
status=$?
set -e

echo "COH CI evidence: ${run_directory}"
exit "${status}"
