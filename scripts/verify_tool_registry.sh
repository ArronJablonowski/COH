#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/tool/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/tool-manifest.schema.json" \
  "${contract}/signed-tool-manifest.schema.json" \
  "${contract}/compatibility-matrix.md" \
  "${contract}/fixtures/valid/query-tool.manifest.json" \
  "${contract}/fixtures/valid/query-tool.signed.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/toolregistry" \
  "${root}/docs/design/signed-tool-registry.md"; do
  [[ -e "${path}" ]] || {
    echo "error: signed tool-registry input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 17
  and .properties.maximum_action_tier["$ref"] == "#/$defs/tier"
  and .properties.review_decision.const == "approved"
  and .["$defs"].operation.additionalProperties == false
  and .["$defs"].operation.properties.input_schema_version.const == "coh.tool-input/v1"
  and .["$defs"].operation.properties.isolation_class.enum == ["native_restricted", "oci_sandbox", "remote_isolated", "t4_dedicated"]
  and .["$defs"].network_policy.properties.public_internet_allowed.const == false
  and .["$defs"].network_policy.properties.metadata_allowed.const == false
  and (.properties | has("credential") | not)
  and (.properties | has("arguments") | not)
  and (.properties | has("private_key") | not)
' "${contract}/tool-manifest.schema.json" >/dev/null

/usr/bin/jq -e '
  .type == "object"
  and .additionalProperties == false
  and (.required | length) == 9
  and .properties.schema_version.const == "coh.signed-tool-manifest/v1"
  and .properties.signature_algorithm.const == "ed25519"
  and .properties.manifest["$ref"] == "tool-manifest.schema.json"
' "${contract}/signed-tool-manifest.schema.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.tool-manifest/v1"
  and .contract_version == "1.0.0"
  and .review_decision == "approved"
  and .maximum_action_tier == "T2"
  and (.operations | length) == 1
  and .operations[0].baseline_action_tier == "T1"
  and .operations[0].maximum_action_tier == "T2"
  and .operations[0].network_policy.public_internet_allowed == false
  and .operations[0].network_policy.metadata_allowed == false
' "${contract}/fixtures/valid/query-tool.manifest.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.signed-tool-manifest/v1"
  and .signature_algorithm == "ed25519"
  and (.signature | length) == 86
  and (.manifest_digest | startswith("sha256:"))
  and .publisher_id == .manifest.publisher_id
' "${contract}/fixtures/valid/query-tool.signed.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.tool-registry-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 12
  and ([.cases[].name] | unique | length) == 12
  and ([.cases[].name] | contains(["unreviewed", "operation-above-tool-ceiling", "native-t3", "public-internet", "publisher-revoked", "tool-identity-collision", "policy-ceiling-elevation"]))
  and all(.cases[]; (.name | length) > 0 and (.reason | test("^[a-z][a-z0-9_.-]{0,127}$")))
' "${contract}/fixtures/denial-corpus.json" >/dev/null

/usr/bin/grep -Fq 'Changed canonicalization or signature domain' "${contract}/compatibility-matrix.md"
/usr/bin/grep -Fq 'runtime policy cannot perform it' "${contract}/compatibility-matrix.md"

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/toolregistry"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/toolregistry"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/toolregistry"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"

echo "tool-registry summary: schemas=2 fixtures=2 denials=12 canonical=COH-CJ-1 signature=ed25519 publishers=current-approved review=required tiers=baseline-and-ceiling policy=narrow-only snapshots=immutable replay=exact revocation=live failures=0"
