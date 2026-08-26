#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/memorynamespace"
contract="${root}/contracts/workflow/v1/memory-namespace.schema.json"
design="${root}/docs/design/session-case-memory-namespaces.md"

for path in "${package}/types.go" "${package}/controller.go" "${package}/repository_store.go" \
  "${contract}" "${design}" "${root}/internal/workflow/agentloop/memory_lookup.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: memory-namespace artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 7
  and (."$defs".namespace.enum == ["session","case","analyst_preference","reviewed_organization"])
  and (."$defs".record.properties.schema_version.const == "coh.memory-namespace/v1")
  and (."$defs".record.properties.value["$ref"] == "#/$defs/artifact")
  and (."$defs".record.properties.provenance_digest["$ref"] == "#/$defs/digest")
  and (."$defs".record.additionalProperties == false)
  and (."$defs".put_request.properties.schema_version.const == "coh.memory-write/v1")
  and (."$defs".get_request.properties.schema_version.const == "coh.memory-read/v1")
  and (."$defs".access_request.properties.schema_version.const == "coh.memory-access/v1")
  and (."$defs".access_request.properties.retention_digest["$ref"] == "#/$defs/digest")
  and (."$defs".access_request.properties.deadline["$ref"] == "#/$defs/timestamp")
  and (."$defs".review_request.properties.writer_actor_id["$ref"] == "#/$defs/uuid_v7")
  and (."$defs".artifact.properties.length.maximum == 1073741824)
' "${contract}" >/dev/null

for forbidden in content bytes prompt instruction credential secret query_handle path uri url callback connector executor; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" >/dev/null; then
    echo "error: memory contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq '| `session` | organization + tenant + case + session + actor' "${design}"
/usr/bin/grep -Fq 'Exact replay recovers the receipt and rechecks current authorization' "${design}"
/usr/bin/grep -Fq 'The agent loop receives `BoundedMemoryLookup`, a one-method read-only port.' "${design}"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: memory namespace imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/workflow/memorynamespace ./internal/workflow/agentloop ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=5 ./internal/workflow/memorynamespace
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/memorynamespace ./internal/workflow/agentloop ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/memorynamespace ./internal/workflow/agentloop ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${root}/contracts/workflow/v1/README.md"
/usr/bin/git diff --check

echo "memory-namespace summary: classes=4 stores=class-bound values=immutable-references access=recomputed retention=independent review=current-independent replay=durable-exact provenance=chained orchestration=read-only failures=0"
