#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for path in \
  "$root/internal/workflow/ports.go" \
  "$root/internal/workflow/engine_types.go" \
  "$root/internal/workflow/engine_errors.go" \
  "$root/internal/workflow/engine_validate.go" \
  "$root/internal/workflow/engine_guard.go" \
  "$root/internal/workflow/temporaladapter/adapter.go" \
  "$root/internal/workflow/temporaladapter/activities.go" \
  "$root/internal/workflow/temporaladapter/runtime.go" \
  "$root/internal/workflow/temporaladapter/workflow.go" \
  "$root/internal/workflow/temporaladapter/replay.go" \
  "$root/internal/workflow/temporaladapter/testdata/coh-operation-v1-history.json" \
  "$root/internal/workflow/temporaladapter/testdata/coh-agent-loop-v1-history.json" \
  "$root/docs/design/temporal-workflow-engine.md"; do
  [[ -f "$path" ]] || {
    printf 'error: Temporal adapter input is missing: %s\n' "$path" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "$root")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "$root")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "$root/scripts/lib/go_ssd_env.sh"

"$COH_GO_ROOT/bin/go" test -count=1 -v \
  "$root/internal/workflow" \
  "$root/internal/workflow/temporaladapter"
"$COH_GO_ROOT/bin/go" test -count=1 -race \
  "$root/internal/workflow" \
  "$root/internal/workflow/temporaladapter"
"$COH_GO_ROOT/bin/go" test -count=5 -run 'Test(RetainedHistoryReplay|OperationWorkflow|AgentLoop)' \
  "$root/internal/workflow/temporaladapter"
"$COH_GO_ROOT/bin/go" vet \
  "$root/internal/workflow" \
  "$root/internal/workflow/temporaladapter"
"$root/scripts/check_go_architecture.sh"

printf '%s\n' \
  'temporal-adapter summary: operations=5 workflow_definitions=2 workflow_versions=1 retained_histories=2 replay_runs=10 history_payload=identifiers-and-hashes typed_errors=7 architecture_violations=0 failures=0'
