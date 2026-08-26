#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/contextcompact"
contract="${root}/contracts/workflow/v1/context-compaction.schema.json"
intent_fixture="${root}/contracts/workflow/v1/fixtures/context-compaction-intent.json"
state_fixture="${root}/contracts/workflow/v1/fixtures/context-compaction-state.json"
design="${root}/docs/design/evidence-safe-context-compaction.md"

paths=(
  "${package}/types.go"
  "${package}/controller.go"
  "${package}/validate.go"
  "${package}/wire.go"
  "${contract}"
  "${intent_fixture}"
  "${state_fixture}"
  "${design}"
  "${root}/contracts/workflow/v1/README.md"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: context-compaction artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (."$defs".intent.properties.schema_version.const == "coh.context-compaction/v1")
  and (."$defs".intent.properties.contract_version.const == "1.0.0")
  and (."$defs".intent.additionalProperties == false)
  and (."$defs".state.additionalProperties == false)
  and (."$defs".source.additionalProperties == false)
  and (."$defs".sources.maxItems == 512)
  and (."$defs".source.properties.trust.const == "untrusted_evidence")
  and (."$defs".state.properties.summary_trust.const == "untrusted_evidence")
  and (."$defs".source.properties.result_state.enum | index("negative")) != null
  and (."$defs".source.properties.result_state.enum | index("gap")) != null
  and (."$defs".source.properties.completeness.enum | index("truncated")) != null
  and (."$defs".source.properties.order_confidence.enum | index("overlap")) != null
  and (."$defs".source.properties.precision.enum | index("unknown")) != null
  and (."$defs".state.properties.status.enum == ["writing","completed","uncertain"])
  and (."$defs".state.allOf | length == 3)
' "${contract}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.context-compaction/v1"
  and .contract_version == "1.0.0"
  and (.sources | length) == 3
  and .sources[0].sequence == 1
  and .sources[0].precision == "second"
  and .sources[1].result_state == "negative"
  and .sources[1].order_confidence == "overlap"
  and .sources[2].result_state == "gap"
  and .sources[2].completeness == "truncated"
  and ([.sources[].trust] | unique) == ["untrusted_evidence"]
' "${intent_fixture}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.context-compaction/v1"
  and .status == "completed"
  and .summary.media_type == "application/json"
  and .summary_trust == "untrusted_evidence"
  and (.summary.digest | test("^sha256:[0-9a-f]{64}$"))
  and (.source_manifest_digest | test("^sha256:[0-9a-f]{64}$"))
  and (.intent_digest | test("^sha256:[0-9a-f]{64}$"))
  and (.provenance_digest | test("^sha256:[0-9a-f]{64}$"))
  and (.sources | length) == 3
' "${state_fixture}" >/dev/null

for forbidden in prompt instruction raw_content credential secret approval tool_authority policy_authority connector executor callback; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" "${intent_fixture}" "${state_fixture}" >/dev/null; then
    echo "error: context-compaction public contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|persistence|connector))"' "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: context compaction imports a forbidden authority or infrastructure capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/workflow/contextcompact
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/workflow/contextcompact
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/contextcompact
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/contextcompact
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${root}/contracts/workflow/v1/README.md"
/usr/bin/git diff --check

echo "context-compaction summary: contract=coh.context-compaction/v1 sources=ordered+resolvable trust=untrusted summary=separate replay=exact recovery=fail_closed failures=0"
