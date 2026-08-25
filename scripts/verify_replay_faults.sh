#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker_bin="$(command -v docker || true)"
[[ -n "${docker_bin}" && "${docker_bin}" == /* && -x "${docker_bin}" ]] || {
  echo "Docker is required for the PostgreSQL crash-fault trials" >&2
  exit 1
}
export COH_NATIVE_STORAGE_ROOT="${COH_NATIVE_STORAGE_ROOT:-$(dirname "${repo_root}")}"
export COH_TOOLCHAIN_ROOT="${COH_TOOLCHAIN_ROOT:-$(dirname "${repo_root}")/COH-toolchains}"
# shellcheck source=lib/go_ssd_env.sh
source "${repo_root}/scripts/lib/go_ssd_env.sh"

artifact_root="${COH_REPLAY_EVAL_ARTIFACT_ROOT:-${COH_TOOLCHAIN_ROOT}/ci-artifacts/CYB-44}"
mkdir -p "${artifact_root}"
run_directory="$(mktemp -d "${artifact_root}/run.XXXXXX")"
comparison_directory="$(mktemp -d "${artifact_root}/compare.XXXXXX")"
cleanup() { rm -rf "${comparison_directory}"; }
trap cleanup EXIT

{
  "${COH_GO_ROOT}/bin/go" test -count=1 -race \
    "${repo_root}/internal/workflow" \
    "${repo_root}/internal/workflow/temporaladapter" \
    "${repo_root}/internal/workflow/replayeval"
  "${COH_GO_ROOT}/bin/go" test -count=1 -race \
    "${repo_root}/internal/persistence/sqlite" \
    "${repo_root}/internal/persistence/storetest"
  PATH="$(dirname "${docker_bin}"):/usr/bin:/bin" "${repo_root}/scripts/verify_postgres_store.sh"
} 2>&1 | /usr/bin/tee "${run_directory}/actual-boundary-tests.log"

evaluator="$(mktemp "${GOTMPDIR}/coh-replayeval.XXXXXX")"
trap 'rm -f "${evaluator}"; cleanup' EXIT
"${COH_GO_ROOT}/bin/go" build -trimpath -o "${evaluator}" "${repo_root}/cmd/replayeval"
chmod 0500 "${evaluator}"
"${evaluator}" -root "${repo_root}" -output "${run_directory}"
"${evaluator}" -root "${repo_root}" -output "${comparison_directory}"

for artifact in artifact-manifest.json corpus-manifest.json environment-report.json grader-report.json reproduction.txt threshold-result.json trial-traces.jsonl; do
  /usr/bin/cmp "${run_directory}/${artifact}" "${comparison_directory}/${artifact}"
done
(
  cd "${run_directory}"
  /usr/bin/shasum -a 256 actual-boundary-tests.log artifact-manifest.json corpus-manifest.json \
    environment-report.json grader-report.json reproduction.txt threshold-result.json trial-traces.jsonl \
    > all-artifacts.sha256
)

echo "CYB-44 replay evidence: ${run_directory}"
echo "replay-fault verification: actual-boundaries=passed deterministic-artifacts=passed thresholds=passed"
