#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/skill/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/skill-manifest.schema.json" \
  "${contract}/signed-skill-manifest.schema.json" \
  "${contract}/skill-registry.schema.json" \
  "${contract}/compatibility-matrix.md" \
  "${root}/docs/design/signed-skill-registry.md" \
  "${root}/internal/workflow/skillregistry" \
  "${root}/internal/workflow/agentloop/skill_lookup.go"; do
  [[ -e "${path}" ]] || {
    echo "error: signed skill-registry input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 22
  and .properties.schema_version.const == "coh.skill-manifest/v1"
  and .properties.skill_version["$ref"] == "#/$defs/version"
  and .properties.review_decision.const == "approved"
  and .properties.resources.maxItems == 128
  and .properties.permissions.maxItems == 64
  and .["$defs"].resource.additionalProperties == false
  and (.properties | has("content") | not)
  and (.properties | has("credential") | not)
  and (.properties | has("path") | not)
  and (.properties | has("url") | not)
  and (.properties | has("executor") | not)
' "${contract}/skill-manifest.schema.json" >/dev/null

/usr/bin/jq -e '
  .type == "object"
  and .additionalProperties == false
  and (.required | length) == 6
  and .properties.schema_version.const == "coh.signed-skill-manifest/v1"
  and .properties.manifest["$ref"] == "skill-manifest.schema.json"
  and .properties.publisher_signature["$ref"] == "#/$defs/signature"
  and .properties.review_signatures.minItems == 1
  and .["$defs"].signature.properties.signature_algorithm.const == "ed25519"
  and .["$defs"].signature.properties.approval_revision.minimum == 1
' "${contract}/signed-skill-manifest.schema.json" >/dev/null

/usr/bin/jq -e '
  .["$defs"].command.properties.action["$ref"] == "#/$defs/action"
  and .["$defs"].signed_change.properties.schema_version.const == "coh.signed-skill-change/v1"
  and .["$defs"].state.properties.status.enum == ["promoted", "revoked"]
  and .["$defs"].state.properties.idempotency_digest["$ref"] == "#/$defs/digest"
  and .["$defs"].state.properties.provenance_digest["$ref"] == "#/$defs/digest"
  and .["$defs"].policy_decision.properties.outcome.const == "allow"
  and .["$defs"].resolve_request.properties.expected_manifest_digest["$ref"] == "#/$defs/digest"
  and .["$defs"].access_decision.properties.outcome.const == "allow"
  and .["$defs"].access_decision.properties.permission["$ref"] == "#/$defs/token"
' "${contract}/skill-registry.schema.json" >/dev/null

/usr/bin/grep -Fq 'Same-key changed replay' "${contract}/README.md"
/usr/bin/grep -Fq 'Return raw content, paths, URLs, credentials, or execution handles' \
  "${contract}/compatibility-matrix.md"
/usr/bin/grep -Fq 'Audit must succeed before the copied result is returned' \
  "${root}/docs/design/signed-skill-registry.md"

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -v -count=1 "${root}/internal/workflow/skillregistry"
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run '^TestSkillRegistrySurvivesSQLiteCloseAndReopen$' \
  "${root}/internal/persistence/sqlite"
"${COH_GO_ROOT}/bin/go" test -count=10 "${root}/internal/workflow/skillregistry"
"${COH_GO_ROOT}/bin/go" test -race -count=1 \
  "${root}/internal/workflow/skillregistry" \
  "${root}/internal/workflow/agentloop"
"${COH_GO_ROOT}/bin/go" vet \
  "${root}/internal/workflow/skillregistry" \
  "${root}/internal/workflow/agentloop"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"

echo "skill-registry summary: schemas=3 domains=publisher-reviewer-owner policy=exact-digest scope=actor-tenant-case-task audit=fail-closed durability=optimistic-idempotent versions=immutable resolution=read-only rollback=immediate-predecessor revocation=live failures=0"
