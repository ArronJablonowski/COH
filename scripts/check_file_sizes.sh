#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=lib/go_ssd_env.sh
source "${repo_root}/scripts/lib/go_ssd_env.sh"

root=${1:-${repo_root}}
artifact_dir=${COH_FILE_SIZE_ARTIFACT_DIR:-}
if [[ -z "${artifact_dir}" ]]; then
  artifact_dir="$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-file-size.XXXXXX")"
fi
binary="$(/usr/bin/mktemp "${GOTMPDIR}/qualitygate-file-size.XXXXXX")"
cleanup() { /bin/rm -f -- "${binary}"; }
trap cleanup EXIT HUP INT TERM

cd "${repo_root}"
"${COH_GO_ROOT}/bin/go" build -trimpath -o "${binary}" ./cmd/qualitygate
/bin/chmod 0500 "${binary}"
"${binary}" -mode file-size -root "${root}" \
  -input "${root}/ci/file-size-policy.json" \
  -artifact-dir "${artifact_dir}" \
  -output "${artifact_dir}/file-size-report.json"
printf 'file-size evidence: %s\n' "${artifact_dir}/file-size-report.json"
