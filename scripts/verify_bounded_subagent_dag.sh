#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/subagentdag"
contract="${root}/contracts/workflow/v1/subagent-dag.schema.json"
design="${root}/docs/design/bounded-subagent-dag.md"
sqlite_test="${root}/internal/persistence/sqlite/subagentdag_integration_test.go"

for path in "${package}/types.go" "${package}/controller.go" "${package}/execute.go" \
  "${package}/cancel.go" "${package}/recover.go" "${package}/repository_store.go" \
  "${contract}" "${design}" "${sqlite_test}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: bounded subagent DAG artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 3
  and (."$defs".role.enum == ["coordinator","alert_triage","siem_query","timeline_correlation","hunting","cti_attack","detection","vulnerability","validation","ir_planner","reviewer","report_writer"])
  and (."$defs".graph.properties.schema_version.const == "coh.subagent-dag/v1")
  and (."$defs".decision.properties.schema_version.const == "coh.subagent-dag-decision/v1")
  and (."$defs".graph.properties.contract_version.const == "1.0.0")
  and (."$defs".graph.additionalProperties == false)
  and (."$defs".task.additionalProperties == false)
  and (."$defs".structured_result.additionalProperties == false)
  and (."$defs".decision.additionalProperties == false)
  and (."$defs".structured_result.anyOf | length) == 2
' "${contract}" >/dev/null

for forbidden in prompt raw_content raw_bytes payload_bytes credential_value secret_value approval scope_override policy_source callback connector executor command shell; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" >/dev/null; then
    echo "error: subagent DAG contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'There is exactly one root' "${design}"
/usr/bin/grep -Fq 'deepest descendant first' "${design}"
/usr/bin/grep -Fq 'without redispatch' "${design}"
/usr/bin/grep -Fq 'runbudget.Authority' "${package}/controller.go"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: subagent DAG imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/workflow/subagentdag ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/workflow/subagentdag
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/subagentdag ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/subagentdag ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${root}/contracts/workflow/v1/README.md"
/usr/bin/git diff --check

echo "bounded-subagent-DAG summary: roles=12 graph=durable bounds=depth,fanout,concurrency,total,deadline budget=external results=typed cancellation=descendant-first recovery=no-redispatch failures=0"
