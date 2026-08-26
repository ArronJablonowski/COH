#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/skill/v1/skill-discovery.schema.json"

for path in \
  "${contract}" \
  "${root}/contracts/skill/v1/README.md" \
  "${root}/docs/design/progressive-skill-discovery.md" \
  "${root}/internal/workflow/skilldiscovery" \
  "${root}/internal/workflow/skillregistry/catalog.go" \
  "${root}/internal/workflow/agentloop/skill_discovery.go"; do
  [[ -e "${path}" ]] || {
    echo "error: progressive skill-discovery input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 9
  and .["$defs"].search_request.additionalProperties == false
  and .["$defs"].search_request.properties.limit.maximum == 32
  and .["$defs"].search_request.properties.cursor["$ref"] == "#/$defs/optional_digest"
  and .["$defs"].compact_skill.additionalProperties == false
  and (.["$defs"].compact_skill.properties | has("content") | not)
  and (.["$defs"].compact_skill.properties | has("resources") | not)
  and .["$defs"].decision.properties.phase.enum == ["compact_search", "detail_expand", "resource_fetch"]
  and .["$defs"].decision.properties.request_id["$ref"] == "#/$defs/uuid_v7"
  and .["$defs"].decision.properties.page_limit.maximum == 32
  and .["$defs"].decision.properties.parent_result_digest["$ref"] == "#/$defs/optional_digest"
  and .["$defs"].decision.properties.deadline["$ref"] == "#/$defs/timestamp"
  and .["$defs"].record.properties.idempotency_digest["$ref"] == "#/$defs/digest"
  and .["$defs"].record.properties.provenance_digest["$ref"] == "#/$defs/digest"
  and .["$defs"].catalog_snapshot.properties.entries.maxItems == 4096
  and .["$defs"].resource_result.properties.artifact["$ref"] == "#/$defs/artifact"
' "${contract}" >/dev/null

/usr/bin/grep -Fq 'Exact replay re-runs current authorization' \
  "${root}/docs/design/progressive-skill-discovery.md"
/usr/bin/grep -Fq 'The sequence is enforced through durable parent records' \
  "${root}/docs/design/progressive-skill-discovery.md"
/usr/bin/grep -Fq 'no HTTP, shell, filesystem-write, connector, executor' \
  "${root}/contracts/skill/v1/README.md"

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -v -count=1 \
  "${root}/internal/workflow/skilldiscovery" \
  "${root}/internal/workflow/agentloop"
"${COH_GO_ROOT}/bin/go" test -count=10 \
  "${root}/internal/workflow/skilldiscovery"
"${COH_GO_ROOT}/bin/go" test -race -count=1 \
  "${root}/internal/workflow/skilldiscovery" \
  "${root}/internal/workflow/agentloop" \
  "${root}/internal/workflow/skillregistry" \
  "${root}/internal/persistence/sqlite"
"${COH_GO_ROOT}/bin/go" vet \
  "${root}/internal/workflow/skilldiscovery" \
  "${root}/internal/workflow/agentloop" \
  "${root}/internal/workflow/skillregistry"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"

echo "skill-discovery summary: phases=compact-detail-resource scope=actor-tenant-case-task policy=recomputed cursor=snapshot-bound catalog=durable-promoted replay=current-state-rechecked retrieval=immutable-reference failures=0"
