#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/retrievalguard"
contract="${root}/contracts/workflow/v1/retrieval-inspection.schema.json"
design="${root}/docs/design/hostile-content-retrieval.md"

for path in "${package}/types.go" "${package}/controller.go" "${package}/repository_store.go" \
  "${package}/deterministic/inspector.go" "${contract}" "${design}" \
  "${root}/internal/workflow/agentloop/skill_discovery.go" \
  "${root}/internal/workflow/agentloop/memory_lookup.go" \
  "${root}/internal/persistence/sqlite/retrievalguard_integration_test.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: hostile-content artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 4
  and (."$defs".source_kind.enum == ["log","document","feed","query_output","tool_output","tool_error","memory","report","attachment"])
  and (."$defs".source.properties.trust.const == "untrusted_content")
  and (."$defs".inspection.properties.trust.const == "untrusted_content")
  and (."$defs".inspection.properties.complete.const == true)
  and (."$defs".profile.properties.deny_active_formats.const == true)
  and (."$defs".profile.properties.redact_secrets.const == true)
  and (."$defs".profile.properties.neutralize_directives.const == true)
  and (."$defs".request.additionalProperties == false)
  and (."$defs".decision.additionalProperties == false)
  and (."$defs".inspection.additionalProperties == false)
  and (."$defs".record.additionalProperties == false)
' "${contract}" >/dev/null

for forbidden in prompt raw_content raw_bytes payload_bytes credential_value secret_value approval scope_override policy_source path uri url callback connector executor command; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" >/dev/null; then
    echo "error: retrieval contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'Their text can describe evidence, but it cannot grant an' "${design}"
/usr/bin/grep -Fq 'absence of a finding never' "${design}"
/usr/bin/grep -Fq 'without reading the hostile source a second time' "${design}"
/usr/bin/grep -Fq 'Source: retrievalguard.Source{Kind: retrievalguard.DocumentSource' "${root}/internal/workflow/agentloop/skill_discovery.go"
/usr/bin/grep -Fq 'Source: retrievalguard.Source{Kind: retrievalguard.MemorySource' "${root}/internal/workflow/agentloop/memory_lookup.go"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: retrieval guard imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/workflow/retrievalguard/... ./internal/workflow/agentloop ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=5 ./internal/workflow/retrievalguard/...
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/retrievalguard/... ./internal/workflow/agentloop ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/retrievalguard/... ./internal/workflow/agentloop ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${root}/contracts/workflow/v1/README.md"
/usr/bin/git diff --check

echo "hostile-content summary: sources=9 trust=untrusted_content authority=separate inspection=data-only active=neutralized secrets=redacted audit=fail-closed replay=reauthorized provenance=chained model-paths=guarded failures=0"
