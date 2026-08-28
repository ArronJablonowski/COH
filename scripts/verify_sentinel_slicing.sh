#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export COH_NATIVE_STORAGE_ROOT="${COH_NATIVE_STORAGE_ROOT:-$(dirname "${repo_root}")}"
export COH_TOOLCHAIN_ROOT="${COH_TOOLCHAIN_ROOT:-$(dirname "${repo_root}")/COH-toolchains}"
# shellcheck source=lib/go_ssd_env.sh
source "${repo_root}/scripts/lib/go_ssd_env.sh"
export GOBIN="${GOBIN:-${COH_TOOLCHAIN_ROOT}/ci-tools/go${COH_GO_VERSION}/bin}"
export COH_GO_BIN="${COH_GO_ROOT}/bin/go"
export STATICCHECK_CACHE="${STATICCHECK_CACHE:-${COH_TOOLCHAIN_ROOT}/staticcheck-cache/sentinel-slicing}"
mkdir -p "${STATICCHECK_CACHE}"
cd "${repo_root}"

artifact_root="${COH_SENTINEL_SLICING_ARTIFACT_ROOT:-${COH_TOOLCHAIN_ROOT}/ci-artifacts/CYB-100}"
mkdir -p "${artifact_root}"
run_directory="$(mktemp -d "${artifact_root}/run.XXXXXX")"
comparison_directory="$(mktemp -d "${artifact_root}/compare.XXXXXX")"
evaluator="$(mktemp "${GOTMPDIR}/coh-sentinelsliceeval.XXXXXX")"
cleanup() {
  rm -f "${evaluator}"
  rm -rf "${comparison_directory}"
}
trap cleanup EXIT

jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema"' \
  contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-evaluation.schema.json >/dev/null
jq -e '.trials_per_task == 5 and (.tasks | length) == 11 and (.tasks | map(.boundary) | unique | length) == 9' \
  contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-corpus.json >/dev/null
jq -e '.network == "disabled" and .randomness == "none" and (.contracts | length) == 5 and (.fixtures | length) == 4' \
  contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-environment.json >/dev/null
if /usr/bin/grep -E -i -n 'authorization|bearer[[:space:]]|password|api[_-]?key|https?://' \
  contracts/evaluation/sentinel-slicing/v1/sentinel-recordings.json \
  contracts/sentinel-query/v1/fixtures/vendor/*.json; then
  echo "sensitive or network marker found in Sentinel fixtures" >&2
  exit 1
fi

"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/connector/sentinel ./internal/workflow/sentinelsliceeval
"${COH_GO_ROOT}/bin/go" test -race ./internal/connector/sentinel ./internal/workflow/sentinelsliceeval
"${COH_GO_ROOT}/bin/go" vet ./internal/connector/sentinel ./internal/workflow/sentinelsliceeval ./cmd/sentinelsliceeval
"${GOBIN}/staticcheck" ./internal/connector/sentinel ./internal/workflow/sentinelsliceeval ./cmd/sentinelsliceeval
"${repo_root}/scripts/run_architecture_gate.sh" | tee "${run_directory}/architecture.log"
"${repo_root}/scripts/check_file_sizes.sh" | tee "${run_directory}/file-size.log"

"${COH_GO_ROOT}/bin/go" build -trimpath -o "${evaluator}" ./cmd/sentinelsliceeval
chmod 0500 "${evaluator}"
"${evaluator}" --output "${run_directory}"
"${evaluator}" --output "${comparison_directory}"
for artifact in artifact-manifest.json corpus-manifest.json environment-report.json grader-report.json reproduction.txt threshold-result.json trial-traces.jsonl; do
  cmp "${run_directory}/${artifact}" "${comparison_directory}/${artifact}"
done
jq -e '.passed == true and .metrics.task_count == 11 and .metrics.trial_count == 55 and
  .metrics.false_complete == 0 and .metrics.released_denied_rows == 0 and .metrics.replay_rate == 1 and
  .metrics.outcome_grade_rate == 1 and .metrics.trajectory_grade_rate == 1 and .metrics.boundary_coverage_rate == 1' \
  "${run_directory}/threshold-result.json" >/dev/null
[[ "$(cat "${run_directory}/reproduction.txt")" == "./scripts/verify_sentinel_slicing.sh" ]]
(
  cd "${run_directory}"
  shasum -a 256 architecture.log artifact-manifest.json corpus-manifest.json environment-report.json \
    file-size.log grader-report.json reproduction.txt threshold-result.json trial-traces.jsonl > all-artifacts.sha256
)

echo "CYB-100 Sentinel slicing evidence: ${run_directory}"
echo "sentinel-slicing verification: adversarial=passed deterministic-artifacts=passed thresholds=passed"
