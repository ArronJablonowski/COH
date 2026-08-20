#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export COH_CI_LANE="${COH_CI_LANE:-baseline}"
# shellcheck source=lib/ci_env.sh
source "${repo_root}/scripts/lib/ci_env.sh"

temporary="$(mktemp -d "${GOTMPDIR}/coh-ci-contract.XXXXXX")"
cleanup() { rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM
quality_binary="${temporary}/qualitygate"
"${COH_GO_BIN}" build -trimpath -o "${quality_binary}" ./cmd/qualitygate
chmod 0500 "${quality_binary}"
export COH_QUALITYGATE_BIN="${quality_binary}"

"${repo_root}/scripts/test_ci_storage.sh"
"${repo_root}/scripts/test_secret_contract.sh"
"${repo_root}/scripts/test_policy_status.sh"
"${repo_root}/scripts/test_license_contract.sh"
"${repo_root}/scripts/test_tool_promotion.sh"

while IFS= read -r script; do
  if [[ ! -x "${script}" ]]; then
    echo "Executable mode is required: ${script}" >&2
    exit 2
  fi
done < <(find "${repo_root}/scripts" -type f -name '*.sh' | sort)

expect_status() {
  local expected=$1
  shift
  set +e
  "$@" > "${temporary}/command.out" 2> "${temporary}/command.err"
  local actual=$?
  set -e
  if (( actual != expected )); then
    echo "Expected status ${expected}, received ${actual}" >&2
    exit 1
  fi
}

workflow_index=0
for mutation in \
  '# byte drift' \
  'permissions: write-all' \
  'uses: owner/unreviewed@main' \
  'run: echo ${{ toJSON(secrets) }}' \
  'continue-on-error: true' \
  'fetch-depth: 1'; do
  workflow_copy="${temporary}/quality-${workflow_index}.yml"
  /bin/cp "${repo_root}/.github/workflows/quality.yml" "${workflow_copy}"
  printf '\n%s\n' "${mutation}" >> "${workflow_copy}"
  expect_status 2 env COH_WORKFLOW_FILE="${workflow_copy}" "${repo_root}/scripts/check_workflow_policy.sh"
  workflow_index=$((workflow_index + 1))
done

empty_manifest="${temporary}/empty-fuzz-targets.txt"
printf '# no targets\n' > "${empty_manifest}"
expect_status 2 "${quality_binary}" -mode verify-fuzz-manifest -root "${repo_root}" -input "${empty_manifest}"
expect_status 64 "${quality_binary}" -mode unsupported
"${quality_binary}" -mode verify-fuzz-manifest -root "${repo_root}" -input "${repo_root}/ci/fuzz-targets.txt" > "${temporary}/fuzz-targets.out"

failed_formatter_root="${temporary}/failed-formatter"
failed_formatter_artifacts="${temporary}/failed-formatter-artifacts"
mkdir -p "${failed_formatter_root}/bin" "${failed_formatter_artifacts}"
ln -s /usr/bin/false "${failed_formatter_root}/bin/gofmt"
expect_status 1 env GITHUB_ACTIONS=true COH_GO_ROOT="${failed_formatter_root}" \
  COH_CI_ARTIFACT_DIR="${failed_formatter_artifacts}" COH_QUALITYGATE_BIN="${quality_binary}" \
  "${repo_root}/scripts/ci_stage.sh" format
grep -Eq '^::error file=scripts/ci_stage\.sh,title=COH quality stage denied::stage=format status=1 bytes=[0-9]+ sha256=[0-9a-f]{64}$' \
  "${temporary}/command.err" || { echo "Missing bounded formatter-failure annotation" >&2; exit 1; }
if grep -Fq 'stage format: passed' "${temporary}/command.out"; then
  echo "Failing formatter was reported as passed" >&2
  exit 1
fi

offline_root="${temporary}/offline-toolchain"
mkdir -p "${offline_root}"
expect_status 2 env COH_CI_OFFLINE=true COH_TOOLCHAIN_ROOT="${offline_root}" \
  COH_GO_ROOT="${COH_GO_ROOT}" COH_CI_ARTIFACT_DIR="${offline_root}/artifacts" \
  COH_QUALITYGATE_BIN="${quality_binary}" "${repo_root}/scripts/bootstrap_ci_tools.sh"

echo "CI quality contract tests: passed"
