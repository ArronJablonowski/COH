#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/recoverycontrol"
adapter="${root}/internal/workflow/agentloop"
contract="${root}/contracts/workflow/v1/recovery-control.schema.json"
recovery_fixture="${root}/contracts/workflow/v1/fixtures/recovery-control-recovery.json"
cancellation_fixture="${root}/contracts/workflow/v1/fixtures/recovery-control-cancellation.json"
fallback_fixture="${root}/contracts/workflow/v1/fixtures/recovery-control-fallback.json"
design="${root}/docs/design/recovery-cancellation-provider-fallback.md"

paths=(
  "${package}/types.go"
  "${package}/controller.go"
  "${package}/recover.go"
  "${package}/cancel.go"
  "${package}/fallback.go"
  "${package}/route.go"
  "${package}/validate.go"
  "${package}/wire.go"
  "${adapter}/recovery_control.go"
  "${contract}"
  "${recovery_fixture}"
  "${cancellation_fixture}"
  "${fallback_fixture}"
  "${design}"
  "${root}/contracts/workflow/v1/README.md"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: recovery-control artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .properties.schema_version.const == "coh.recovery-control/v1"
  and .properties.contract_version.const == "1.0.0"
  and .additionalProperties == false
  and (.required | length) == 30
  and (.properties.kind.enum == ["recovery","cancellation","fallback"])
  and (.properties.status.enum | index("uncertain")) != null
  and (.properties.targets.maxItems == 512)
  and (.properties.attempts.maxItems == 2)
  and (."$defs".references.uniqueItems == true)
  and (."$defs".tokens.uniqueItems == true)
  and (."$defs".case.additionalProperties == false)
  and (."$defs".work.additionalProperties == false)
  and (."$defs".cancel_target.additionalProperties == false)
  and (."$defs".cancellation_ack.additionalProperties == false)
  and (."$defs".capability_profile.additionalProperties == false)
  and (."$defs".route.additionalProperties == false)
  and (."$defs".provider_attempt.additionalProperties == false)
  and (.allOf | length) == 3
' "${contract}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.recovery-control/v1"
  and .kind == "recovery"
  and .status == "completed"
  and .observed_work.side_effect == "none"
  and .observed_work.status == "running"
  and .result_work.status == "waiting"
  and (.targets | length) == 0
  and (.attempts | length) == 0
' "${recovery_fixture}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.recovery-control/v1"
  and .kind == "cancellation"
  and .status == "completed"
  and (.targets | length) == 2
  and (.acknowledgments | length) == 2
  and .targets[0].kind == "child_task"
  and .targets[1].kind == "tool_job"
  and ([.acknowledgments[].evidence_digest] | all(test("^sha256:[0-9a-f]{64}$")))
' "${cancellation_fixture}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.recovery-control/v1"
  and .kind == "fallback"
  and .status == "completed"
  and (.input_refs | length) > 0
  and (.budget_reservation_digest | test("^sha256:[0-9a-f]{64}$"))
  and .route.primary.data_route == "local"
  and .route.fallback.data_route == "local"
  and .route.primary.state_mode != "provider_managed"
  and .route.fallback.cancellation == true
  and (.attempts | length) == 2
  and .attempts[0].outcome == "unavailable"
  and .attempts[1].outcome == "succeeded"
' "${fallback_fixture}" >/dev/null

for forbidden in prompt instruction raw_content credential secret policy_authority tool_authority connector executor callback function; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" "${recovery_fixture}" "${cancellation_fixture}" "${fallback_fixture}" >/dev/null; then
    echo "error: recovery-control public contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|transport|persistence|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: recovery control imports a forbidden authority or infrastructure capability" >&2
  exit 2
fi

if ! /usr/bin/grep -q 'PlanningActivityName.*coh.agent-loop.plan.v2' "${adapter}/activities.go"; then
  echo "error: recovery-bound planning payload is not registered under plan.v2" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/workflow/recoverycontrol ./internal/workflow/agentloop ./internal/workflow/agentphase ./internal/workflow/temporaladapter
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/workflow/recoverycontrol ./internal/workflow/agentloop
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/recoverycontrol ./internal/workflow/agentloop
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/recoverycontrol ./internal/workflow/agentloop ./internal/workflow/agentphase ./internal/workflow/temporaladapter
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${root}/contracts/workflow/v1/README.md" "${adapter}/README.md"
/usr/bin/git diff --check

echo "recovery-control summary: contract=coh.recovery-control/v1 recovery=fail_closed cancellation=durable_ordered fallback=approved_equivalent_nonbroader attempts=exact migration=plan.v2 failures=0"
