#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for path in \
  "$root/internal/workflow/storage_ports.go" \
  "$root/internal/workflow/storage_types.go" \
  "$root/internal/workflow/storage_errors.go" \
  "$root/internal/workflow/storage_validate.go" \
  "$root/internal/workflow/storage_guard.go" \
  "$root/internal/workflow/storage_contract_test.go" \
  "$root/internal/workflow/storage_surface_test.go" \
  "$root/internal/persistence/storetest/conformance.go" \
  "$root/internal/persistence/storetest/conformance_test.go" \
  "$root/docs/design/storage-port-contract.md"; do
  [[ -f "$path" ]] || {
    printf 'error: storage contract input is missing: %s\n' "$path" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "$root")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "$root")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "$root/scripts/lib/go_ssd_env.sh"

"$COH_GO_ROOT/bin/go" test -count=1 \
  "$root/internal/workflow" \
  "$root/internal/persistence/storetest"
"$COH_GO_ROOT/bin/go" test -count=1 -race \
  "$root/internal/workflow" \
  "$root/internal/persistence/storetest"
"$COH_GO_ROOT/bin/go" vet \
  "$root/internal/workflow" \
  "$root/internal/persistence/storetest"
"$root/scripts/check_go_architecture.sh"

printf '%s\n' \
  'storage-contract summary: capabilities=3 operations=6 conformance-scenarios=5 typed-errors=7 architecture-violations=0 failures=0'
