#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/agentloop"
adapter="${root}/internal/workflow/temporaladapter"
contract="${root}/contracts/workflow/v1/agent-loop.schema.json"
domain_contract="${root}/contracts/domain/v1/workflow-payloads.schema.json"
history="${adapter}/testdata/coh-agent-loop-v1-history.json"

paths=(
  "${package}/README.md"
  "${package}/activities.go"
  "${package}/loop.go"
  "${package}/repository_store.go"
  "${package}/validate.go"
  "${adapter}/activities.go"
  "${contract}"
  "${domain_contract}"
  "${history}"
  "${root}/contracts/workflow/v1/README.md"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: durable agent-loop input is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (."$defs".references.uniqueItems == true)
  and (."$defs".references.maxItems == 128)
  and (."$defs".run.required == ["schema","kind","id","organization_id","tenant_id","case_id","revision","created_at","data"])
  and (."$defs".step.required == ["schema","kind","id","organization_id","tenant_id","case_id","revision","created_at","data"])
  and (."$defs".run.properties.data["$ref"] == "#/$defs/run_data")
  and (."$defs".step.properties.data["$ref"] == "#/$defs/step_data")
  and (."$defs".run_data.properties.contract_version.const == "coh.agent-loop/v1")
  and (."$defs".run_data.properties.workflow_type.const == "coh.agent-loop.v1")
  and (."$defs".run_data.properties.workflow_version.const == "1.0.0")
  and (."$defs".step_data.properties.activity_kind.enum == ["planning","authorized_action"])
  and (."$defs".step_data.allOf | length == 2)
  and (."$defs".run.additionalProperties == false)
  and (."$defs".step.additionalProperties == false)
  and (."$defs".run_data.additionalProperties == false)
  and (."$defs".step_data.additionalProperties == false)
' "${contract}" >/dev/null

/usr/bin/jq -e '
  (."$defs".run.properties.status.enum | index("waiting")) != null
  and (."$defs".run.properties.status.enum | index("timeout")) != null
  and (."$defs".run.properties.contract_version.pattern == "^coh[.]agent-loop/v1$")
  and (."$defs".task.properties.status.enum | index("dispatching")) != null
  and (."$defs".task.properties.status.enum | index("denied")) != null
  and (."$defs".task.properties.activity_kind.enum == ["planning","authorized_action"])
' "${domain_contract}" >/dev/null

/usr/bin/jq -e '
  (.events | length) == 3
  and .events[0].eventType == "WorkflowExecutionStarted"
  and .events[0].workflowExecutionStartedEventAttributes.workflowType.name == "coh.agent-loop.v1"
  and .events[0].workflowExecutionStartedEventAttributes.input.payloads[0].metadata.encoding == "anNvbi9wbGFpbg=="
' "${history}" >/dev/null

history_payload=$(/usr/bin/jq -r '.events[0].workflowExecutionStartedEventAttributes.input.payloads[0].data | @base64d' "${history}")
[[ "${#history_payload}" -le 2048 ]] || {
  echo "error: retained agent-loop history payload exceeds 2048 bytes" >&2
  exit 2
}
if printf '%s' "${history_payload}" | /usr/bin/grep -E -i 'prompt|credential|secret|evidence[_ ]?bytes|tool[_ ]?output|connector[_ ]?response' >/dev/null; then
  echo "error: retained agent-loop history contains prohibited data" >&2
  exit 2
fi
printf '%s' "${history_payload}" | /usr/bin/jq -e '
  .Kind == "agent_loop"
  and .Version == "coh.agent-loop.v1"
  and (.InputDigest | test("^sha256:[0-9a-f]{64}$"))
  and (.StartDigest | test("^sha256:[0-9a-f]{64}$"))
' >/dev/null

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|provider|transport|persistence))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: agent loop imports a forbidden action-capable dependency" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${root}/scripts/verify_domain_contract.sh"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/workflow/agentloop ./internal/workflow/temporaladapter ./internal/workflow
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/workflow/agentloop ./internal/workflow/temporaladapter
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/agentloop ./internal/workflow/temporaladapter
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/agentloop ./internal/workflow/temporaladapter ./internal/workflow
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${package}/README.md" "${root}/contracts/workflow/v1/README.md"
/usr/bin/git diff --check

echo "agent-loop summary: contract=coh.agent-loop/v1 workflow=coh.agent-loop.v1 activities=2 states=run8+step9 persistence=atomic-run-step-outbox recovery=no-action-replay history=bounded-digests-only domain-envelope=strict failures=0"
