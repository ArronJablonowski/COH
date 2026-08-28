#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"
cd "${root}"

quality_binary="$(mktemp "${GOTMPDIR}/model-surface-qualitygate.XXXXXX")"
cleanup() { rm -f "${quality_binary}"; }
trap cleanup EXIT
"${COH_GO_ROOT}/bin/go" build -trimpath -o "${quality_binary}" ./cmd/qualitygate
chmod 0500 "${quality_binary}"
export COH_QUALITYGATE_BIN="${quality_binary}"

"${root}/scripts/verify_model_surface_contract.sh"
"${root}/scripts/verify_provider_contract.sh"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/domain/modelsurface ./internal/domain/providercontract ./internal/provider/...
"${COH_GO_ROOT}/bin/go" test -count=20 ./internal/domain/modelsurface ./internal/domain/providercontract
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/modelsurface ./internal/domain/providercontract ./internal/provider/...
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/modelsurface ./internal/domain/providercontract ./internal/provider/... ./cmd/archcheck
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_secrets.sh" worktree
"${root}/scripts/check_licenses.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_fuzz_seeds.sh"
"${root}/scripts/check_supply_chain.sh"
"${root}/scripts/check_markdown_links.sh" "${root}/contracts/model-surface/v1/README.md" \
  "${root}/contracts/model-surface/v1/compatibility-matrix.md" \
  "${root}/docs/design/durable-model-surface-provenance.md"
/usr/bin/git diff --check

echo "model-surface evidence: issue=CYB-186 requirements=FR-014+FR-027+FR-038+FR-044+SEC-011+SEC-015+SEC-016+SEC-020 projection=deterministic dispatch=sealed stream=durable compaction=source-covering recovery=reprojected adversarial=complete supply_chain=reproducible failures=0"
