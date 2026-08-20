#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/quality_status.sh
source "${repo_root}/scripts/lib/quality_status.sh"
artifact_dir="${COH_CI_ARTIFACT_DIR:?COH_CI_ARTIFACT_DIR is required}"
stage=${1:-}
mkdir -p "${artifact_dir}"
cd "${repo_root}"

run_logged() {
  local name=$1
  local classification=$2
  shift 2
  local temporary status byte_count
  temporary="$(mktemp "${GOTMPDIR}/coh-${name}.XXXXXX")"
  set +e
  "$@" 2>&1 | /usr/bin/head -c 8388609 > "${temporary}"
  status=${PIPESTATUS[0]}
  set -e
  byte_count="$(/usr/bin/wc -c < "${temporary}" | /usr/bin/tr -d ' ')"
  if (( byte_count > 8388608 )); then
    printf 'stage output exceeded the 8 MiB evidence limit\n' > "${temporary}"
    status=2
  fi
  mv "${temporary}" "${artifact_dir}/${name}.log"
  status="$(coh_normalize_stage_status "${classification}" "${status}")"
  if (( status != 0 )); then
    log_digest="$("${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" -mode digest -input "${artifact_dir}/${name}.log")"
    printf 'stage=%s status=%s bytes=%s sha256=%s\n' "${name}" "${status}" "${byte_count}" "${log_digest}" >&2
    return "${status}"
  fi
}

case "${stage}" in
  format)
    run_logged format preserve /bin/bash -c 'set -euo pipefail; files=$("$COH_GO_ROOT/bin/gofmt" -l cmd internal); test -z "$files" || { printf "%s\n" "$files"; exit 2; }'
    ;;
  file-size)
    run_logged file-size preserve "${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" \
      -mode file-size -root "${repo_root}" -input "${repo_root}/ci/file-size-policy.json" \
      -artifact-dir "${artifact_dir}" -output "${artifact_dir}/file-size-report.json"
    ;;
  vet) run_logged vet denial "${COH_GO_BIN}" vet ./... ;;
  static-analysis) run_logged static-analysis denial "${repo_root}/scripts/check_static_analysis.sh" ;;
  unit) run_logged unit denial "${COH_GO_BIN}" test -count=1 ./... ;;
  race) run_logged race denial "${COH_GO_BIN}" test -count=1 -race ./... ;;
  fuzz-seed) run_logged fuzz-seed preserve "${repo_root}/scripts/check_fuzz_seeds.sh" ;;
  architecture)
    run_logged architecture preserve "${repo_root}/scripts/run_architecture_gate.sh"
    cp "${artifact_dir}/architecture.log" "${artifact_dir}/architecture-report.json"
    ;;
  quality-contract) run_logged quality-contract preserve "${repo_root}/scripts/test_ci_quality.sh" ;;
  workflow) run_logged workflow preserve "${repo_root}/scripts/check_workflow_policy.sh" ;;
  secret-worktree) run_logged secret-worktree preserve "${repo_root}/scripts/check_secrets.sh" worktree ;;
  secret-history) run_logged secret-history preserve "${repo_root}/scripts/check_secrets.sh" history ;;
  license) run_logged license preserve "${repo_root}/scripts/check_licenses.sh" ;;
  dependency) run_logged dependency preserve "${repo_root}/scripts/check_dependencies.sh" ;;
  sbom) run_logged sbom preserve "${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" -mode sbom -root "${repo_root}" -output "${artifact_dir}/coh.cdx.json" ;;
  secret-evidence) run_logged secret-evidence preserve "${repo_root}/scripts/check_secrets.sh" evidence ;;
  provenance) run_logged provenance preserve "${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" -mode provenance -root "${repo_root}" -artifact-dir "${artifact_dir}" -output "${artifact_dir}/ci-provenance.json" ;;
  *) echo "Denied unknown CI stage: ${stage}" >&2; exit 64 ;;
esac

echo "stage ${stage}: passed"
