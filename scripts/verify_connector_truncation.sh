#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export COH_NATIVE_STORAGE_ROOT="${COH_NATIVE_STORAGE_ROOT:-$(dirname "${repo_root}")}"
export COH_TOOLCHAIN_ROOT="${COH_TOOLCHAIN_ROOT:-$(dirname "${repo_root}")/COH-toolchains}"
# shellcheck source=lib/go_ssd_env.sh
source "${repo_root}/scripts/lib/go_ssd_env.sh"
cd "${repo_root}"

artifact_root="${COH_TRUNCATION_EVAL_ARTIFACT_ROOT:-${COH_TOOLCHAIN_ROOT}/ci-artifacts/CYB-89}"
mkdir -p "${artifact_root}"
run_directory="$(mktemp -d "${artifact_root}/run.XXXXXX")"
comparison_directory="$(mktemp -d "${artifact_root}/compare.XXXXXX")"
evaluator="$(mktemp "${GOTMPDIR}/coh-truncationeval.XXXXXX")"
cleanup() {
  rm -f "${evaluator}"
  rm -rf "${comparison_directory}"
}
trap cleanup EXIT

for schema in contracts/evaluation/truncation/v1/*.schema.json; do
  jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema"' "${schema}" >/dev/null
done
jq -e '.trials_per_task == 5 and (.tasks | length) == 21 and (.tasks | map(.boundary) | unique | length) == 21' \
  contracts/evaluation/truncation/v1/connector-truncation-corpus.json >/dev/null
jq -e '.network == "disabled" and .randomness == "none" and (.contracts | length) == 7 and (.fixture_manifests | length) == 2' \
  contracts/evaluation/truncation/v1/connector-truncation-environment.json >/dev/null
if /usr/bin/grep -E -i -n 'authorization|bearer[[:space:]]|password|api[_-]?key|https?://' \
  internal/workflow/truncationeval/testdata/1.0.0/*.json; then
  echo "sensitive or network marker found in truncation recordings" >&2
  exit 1
fi

"${COH_GO_ROOT}/bin/go" test -count=20 ./internal/workflow/truncationeval
"${COH_GO_ROOT}/bin/go" test -race ./internal/workflow/truncationeval
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/truncationeval ./cmd/truncationeval
"${GOBIN}/staticcheck" ./internal/workflow/truncationeval ./cmd/truncationeval
"${repo_root}/scripts/check_go_architecture.sh" | tee "${run_directory}/architecture.log"
"${repo_root}/scripts/check_file_sizes.sh" | tee "${run_directory}/file-size.log"

"${COH_GO_ROOT}/bin/go" build -trimpath -o "${evaluator}" ./cmd/truncationeval
chmod 0500 "${evaluator}"
"${evaluator}" --output "${run_directory}"
"${evaluator}" --output "${comparison_directory}"

for artifact in artifact-manifest.json corpus-manifest.json environment-report.json grader-report.json reproduction.txt threshold-result.json trial-traces.jsonl; do
  cmp "${run_directory}/${artifact}" "${comparison_directory}/${artifact}"
done
jq -e '.outcome == "passed" and .metrics.task_count == 21 and .metrics.trial_count == 105 and
  .metrics.false_complete == 0 and .metrics.duplicate_rows == 0 and .metrics.missing_rows == 0 and
  .metrics.replay_rate == 1 and .metrics.outcome_grade_rate == 1 and .metrics.trajectory_grade_rate == 1 and
  .metrics.boundary_coverage_rate == 1' "${run_directory}/threshold-result.json" >/dev/null
[[ "$(cat "${run_directory}/reproduction.txt")" == "./scripts/verify_connector_truncation.sh" ]]
(
  cd "${run_directory}"
  shasum -a 256 architecture.log artifact-manifest.json corpus-manifest.json environment-report.json \
    file-size.log grader-report.json reproduction.txt threshold-result.json trial-traces.jsonl > all-artifacts.sha256
)

echo "CYB-89 connector truncation evidence: ${run_directory}"
echo "connector-truncation verification: adversarial=passed deterministic-artifacts=passed thresholds=passed"
