#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for path in \
  "${root}/internal/broker/predispatch_gate.go" \
  "${root}/internal/broker/predispatch_validate.go" \
  "${root}/internal/broker/predispatch_audit.go" \
  "${root}/internal/broker/predispatch_gate_test.go" \
  "${root}/docs/design/predispatch-integration-gate.md"; do
  [[ -e "${path}" ]] || {
    echo "error: pre-dispatch integration input is missing: ${path}" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 -run 'TestPreDispatch' "${root}/internal/broker"
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run 'TestPreDispatch' "${root}/internal/broker"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/broker"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"

echo "predispatch summary: order=manifest-policy-roe-approval-audit tiers=T2-T4 manifest=ed25519 policy=fresh approval=single-use roe=T4-required audit=fail-closed replay=denied failures=0"
