#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
design="${root}/docs/design/e11-integration.md"
package="${root}/internal/domain/e11integration"
leaf_reports=(
  "${root}/docs/evidence/CYB-80-normalized-event-envelope-report.md"
  "${root}/docs/evidence/CYB-81-mapping-registry-report.md"
  "${root}/docs/evidence/CYB-82-time-precision-report.md"
  "${root}/docs/evidence/CYB-83-entity-resolution-report.md"
  "${root}/docs/evidence/CYB-86-investigation-projection-report.md"
)
leaf_checksums=(
  "${root}/docs/evidence/CYB-80-artifacts.sha256"
  "${root}/docs/evidence/CYB-81-artifacts.sha256"
  "${root}/docs/evidence/CYB-82-artifacts.sha256"
  "${root}/docs/evidence/CYB-83-artifacts.sha256"
  "${root}/docs/evidence/CYB-86-artifacts.sha256"
)

for path in "${design}" "${package}/README.md" "${package}/binding.go" "${package}/integration_test.go" \
  "${leaf_reports[@]}" "${leaf_checksums[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: CYB-15 artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

for term in FR-021 FR-022 FR-024 FR-025 FR-067 EVAL-017 COH-E10 CYB-80 CYB-81 CYB-82 CYB-83 CYB-86 \
  OCSF ECS timezone precision skew duplicate uncertainty migration recovery rollback privacy compatibility bounded; do
  /usr/bin/grep -Fiq "${term}" "${design}" "${package}/README.md" || {
    echo "error: CYB-15 integration documentation is missing ${term}" >&2
    exit 2
  }
done

for report in "${leaf_reports[@]}"; do
  /usr/bin/grep -Fq 'No unresolved blocking finding remains' "${report}" || {
    echo "error: child report does not close blocking findings: ${report}" >&2
    exit 2
  }
done

if /usr/bin/grep -R -n -E '"(net/http|os|os/exec|database/sql|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: COH-E11 integration imports forbidden authority or direct I/O" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

artifact_dir=${COH_FOCUSED_ARTIFACT_DIR:-$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-e11-integration.XXXXXX")}
/bin/mkdir -p "${artifact_dir}"
packages=(
  ./internal/domain/normalizedevent
  ./internal/domain/mappingregistry
  ./internal/domain/temporaltime
  ./internal/domain/entityresolution
  ./internal/domain/investigationprojection
  ./internal/domain/e11integration
)

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/domain/e11integration | /usr/bin/tee "${artifact_dir}/integration.log"
"${COH_GO_ROOT}/bin/go" test -count=10 "${packages[@]}" | /usr/bin/tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${packages[@]}" | /usr/bin/tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet "${packages[@]}"
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh" | /usr/bin/tee "${artifact_dir}/architecture.log"
file_size_artifact_dir=$(/usr/bin/mktemp -d "${artifact_dir}/file-size.XXXXXX")
COH_FILE_SIZE_ARTIFACT_DIR="${file_size_artifact_dir}" "${root}/scripts/check_file_sizes.sh" | /usr/bin/tee "${artifact_dir}/file-size.log"
"${root}/scripts/check_markdown_links.sh" "${design}" "${package}/README.md" "${leaf_reports[@]}"
/usr/bin/git diff --check

(
  cd "${artifact_dir}"
  /usr/bin/shasum -a 256 architecture.log file-size.log integration.log race.log repeat.log > SHA256SUMS
)

echo "COH-E11 integration summary: issue=CYB-15 requirements=FR-021+FR-022+FR-024+FR-025+FR-067+EVAL-017 leaves=5 vendor-fields=recoverable time=uncertainty-preserved projections=reproducible binding-drifts=denied failures=0 artifacts=${artifact_dir}"
