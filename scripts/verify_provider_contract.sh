#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/provider/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/compatibility-matrix.md" \
  "${contract}/capability.schema.json" \
  "${contract}/inference-request.schema.json" \
  "${contract}/inference-response.schema.json" \
  "${contract}/stream-event.schema.json" \
  "${contract}/qualification-record.schema.json" \
  "${contract}/signed-qualification.schema.json" \
  "${contract}/fixtures/valid/capability.json" \
  "${contract}/fixtures/valid/qualification.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/providercontract"; do
  [[ -e "${path}" ]] || {
    echo "error: provider-contract input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .additionalProperties == false
  and .properties.schema_version.const == "coh.provider-capability/v1"
  and (.required | length) == 8
  and (.properties.provider["$ref"] == "#/$defs/provider_identity")
  and (."$defs".provider_identity.required | length) == 21
  and (."$defs".features.properties.tool_calls.type == "boolean")
  and (."$defs".features.properties.structured_output.type == "boolean")
  and (."$defs".features.properties.streaming.type == "boolean")
  and (."$defs".features.properties.cancellation.type == "boolean")
' "${contract}/capability.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.provider-request/v1"
  and (.required | contains(["messages", "tools", "output_constraint", "sampling", "state", "deadline"]))
  and (."$defs".content_item.oneOf | length) == 5
  and (.properties | has("options") | not)
  and (.properties | has("headers") | not)
  and (.properties | has("passthrough") | not)
' "${contract}/inference-request.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.provider-response/v1"
  and (.properties.outcome.enum == ["succeeded", "denied", "canceled", "timeout", "failed", "uncertain"])
  and (."$defs".error.properties.code.enum | contains(["invalid_input", "denied", "unsupported", "canceled", "timeout", "unavailable", "conflict", "internal"]))
' "${contract}/inference-response.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.provider-stream-event/v1"
  and (.properties.kind.enum == ["text_delta", "item", "usage_delta", "completed", "error"])
  and (.oneOf | length) == 5
' "${contract}/stream-event.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.provider-qualification/v1"
  and .properties.cases.minItems == 6
  and .properties.cases.maxItems == 6
  and (."$defs".case.properties.kind.enum == ["capability", "structured_output", "tool_call", "cancellation", "identity_provenance", "policy_route"])
' "${contract}/qualification-record.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.signed-provider-qualification/v1"
  and .properties.signature_algorithm.const == "ed25519"
  and .properties.signature.minLength == 86
  and (.required | contains(["qualification", "qualification_digest", "qualifier_identity_digest", "qualifier_key_id", "qualifier_key_revision", "qualifier_approval_revision", "signature"]))
' "${contract}/signed-qualification.schema.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.provider-contract-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 8
  and ([.cases[].name] | unique | length) == 8
  and ([.cases[].name] | contains(["unknown-field", "malformed-content-item", "unsupported-capability", "provider-identity-drift", "expired-qualification", "exact-replay", "changed-id-collision", "stream-sequence-tamper"]))
' "${contract}/fixtures/denial-corpus.json" >/dev/null

if /usr/bin/jq -s -e '
  [.[] | .. | objects | .properties? // {} | keys[]]
  | any(. == "options" or . == "headers" or . == "passthrough" or . == "api_key" or . == "private_key" or . == "credential" or . == "secret")
' "${contract}"/*.schema.json >/dev/null; then
  echo "error: generic vendor passthrough or secret field found" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-provider-contract.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/domain/providercontract | tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/domain/providercontract | tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/providercontract | tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/providercontract
"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" "${contract}/compatibility-matrix.md"
/usr/bin/git diff --check

echo "provider-contract summary: schemas=6 canonical=COH-CJ-1 identity=exact qualification=ed25519+six-case+expiring admission=fail-closed replay=exact collision=denied messages=typed tools=typed structured=typed streaming=ordered cancellation=canceled+timeout state=explicit provenance=complete denials=8 failures=0"
