#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/runbudget"
agentloop="${root}/internal/workflow/agentloop"
contract="${root}/contracts/workflow/v1/run-budget.schema.json"
agent_contract="${root}/contracts/workflow/v1/agent-loop.schema.json"
plan_fixture="${root}/contracts/workflow/v1/fixtures/run-budget-plan.json"
ledger_fixture="${root}/contracts/workflow/v1/fixtures/run-budget-ledger.json"
design="${root}/docs/design/run-task-budget-enforcement.md"

paths=(
  "${package}/types.go"
  "${package}/controller.go"
  "${package}/validate.go"
  "${package}/wire.go"
  "${agentloop}/loop.go"
  "${contract}"
  "${agent_contract}"
  "${plan_fixture}"
  "${ledger_fixture}"
  "${design}"
  "${root}/contracts/workflow/v1/README.md"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: run-budget artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (."$defs".plan.properties.schema_version.const == "coh.run-budget/v1")
  and (."$defs".plan.properties.contract_version.const == "1.0.0")
  and (."$defs".plan.additionalProperties == false)
  and (."$defs".ledger.additionalProperties == false)
  and (."$defs".reservation.additionalProperties == false)
  and (."$defs".reservation.required | index("parent_task_id")) != null
  and (."$defs".reservation.required | index("settlement_idempotency_digest")) != null
  and (."$defs".ledger.required | index("active_concurrency")) != null
  and (."$defs".ledger.required | index("previous_provenance_digest")) != null
  and (."$defs".ledger.properties.reservations.maxItems == 4096)
  and ((."$defs".limit_vector.required | sort) == ["concurrency","cost_micros","delegation_depth","evidence_bytes","fanout","query_rows","tokens","tool_calls","wall_time_nanoseconds"])
  and ((."$defs".claim_vector.required | sort) == (.["$defs"].limit_vector.required | sort))
  and ((."$defs".actual_vector.required | sort) == (.["$defs"].limit_vector.required | sort))
  and ((."$defs".charged_vector.required | sort) == (.["$defs"].limit_vector.required | sort))
  and (."$defs".reservation.allOf | length == 2)
' "${contract}" >/dev/null

/usr/bin/jq -e '
  (."$defs".run_data.required | index("budget_plan_digest")) != null
  and (."$defs".step_data.required | index("budget_reservation_digest")) != null
  and (."$defs".step_data.required | index("budget_settlement_digest")) != null
  and (."$defs".run_data.properties.budget_plan_digest."$ref" == "#/$defs/digest")
  and (."$defs".step_data.properties.budget_reservation_digest."$ref" == "#/$defs/digest")
' "${agent_contract}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.run-budget/v1"
  and .contract_version == "1.0.0"
  and .limits.concurrency == 2
  and .limits.wall_time_nanoseconds == 3600000000000
  and (.policy_digest | test("^sha256:[0-9a-f]{64}$"))
' "${plan_fixture}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.run-budget/v1"
  and .revision == 1
  and .active_concurrency == 1
  and .charged.tokens == 10
  and .charged.wall_time_nanoseconds == 0
  and (.reservations | length) == 1
  and .reservations[0].parent_task_id == ""
  and .reservations[0].claim.delegation_depth == 0
  and .reservations[0].status == "active"
  and (.plan_digest | test("^sha256:[0-9a-f]{64}$"))
  and (.provenance_digest | test("^sha256:[0-9a-f]{64}$"))
' "${ledger_fixture}" >/dev/null

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|provider|transport|persistence|connector))"' "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: budget authority imports a forbidden action or infrastructure capability" >&2
  exit 2
fi

if /usr/bin/grep -R -n -E 'runbudget[.](Controller|Store)|[*]runbudget[.]Controller' "${agentloop}" --include='*.go' >/dev/null; then
  echo "error: agent loop bypasses the narrow runbudget.Authority capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/workflow/runbudget ./internal/workflow/agentloop ./internal/workflow/agentphase
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/workflow/runbudget ./internal/workflow/agentloop ./internal/workflow/agentphase
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/runbudget ./internal/workflow/agentloop ./internal/workflow/agentphase
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/runbudget ./internal/workflow/agentloop ./internal/workflow/agentphase
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${root}/contracts/workflow/v1/README.md"
/usr/bin/git diff --check

echo "run-budget summary: contract=coh.run-budget/v1 dimensions=9 reserve=atomic worst_case=durable hierarchy=derived settlement=exact recovery=fail_closed failures=0"
