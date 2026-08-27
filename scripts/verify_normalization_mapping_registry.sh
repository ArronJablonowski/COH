#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/mapping/v1"
schema="${contract}/normalization-mapping.schema.json"
corpus="${contract}/fixtures/vendor-corpus.json"
design="${root}/docs/design/normalization-mapping-registry.md"
package="${root}/internal/domain/mappingregistry"
package_readme="${package}/README.md"

for path in "${contract}/README.md" "${schema}" "${corpus}" "${design}" "${package_readme}" \
  "${package}/service.go" "${package}/lifecycle.go" "${package}/vendor_fixture_test.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: CYB-81 artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 4
  and (["signed_mapping", "command", "outcome", "receipt"] |
    all(. as $name | $schema."$defs"[$name].additionalProperties == false))
  and (."$defs".command.properties.operation.enum == ["register", "promote", "rollback", "revoke", "apply"])
  and (."$defs".signed_mapping.properties.signature_algorithm.const == "ed25519")
  and (."$defs".rule.properties.operation.enum == ["copy", "constant", "enum", "to_integer", "to_string", "timestamp_reference"])
  and (."$defs".source_matcher.required | contains(["source_kind", "product", "product_digest", "source_schema", "source_schema_version", "source_schema_digest", "collection_method", "collection_method_version", "source_identity_digest"]))
  and (."$defs".reason_code.enum | contains(["manifest_revoked", "source_mismatch", "mapping_ambiguous", "mapping_downgrade", "unmapped_field_denied", "reverse_validation_failed", "idempotency_conflict", "context_canceled", "context_deadline"]))
' --argjson schema "$(/usr/bin/jq -c . "${schema}")" "${schema}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.mapping-vendor-corpus/v1"
  and (.cases | length) == 6
  and ([.cases[].name] | unique | length) == 6
  and ([.cases[].mutation] | contains(["none", "remove-message-rule", "lossy-event-code", "source-mismatch", "registry-revoked", "signature-revoked"]))
  and all(.cases[]; .envelope == "../../../normalization/v1/fixtures/valid/event.canonical.json")
' "${corpus}" >/dev/null

if /usr/bin/jq -e '
  [.. | objects | .properties? // {} | keys[]]
  | any(. == "private_key" or . == "credential" or . == "policy_source" or . == "callback" or
    . == "command_line" or . == "filesystem_path" or . == "network_client" or . == "shell_command" or
    . == "url" or . == "sql" or . == "executor" or . == "connector")
' "${schema}" >/dev/null; then
  echo "error: unsafe authority or direct-access surface found in CYB-81 schema" >&2
  exit 2
fi

for term in FR-021 FR-025 COH-E10 CYB-80 compatibility signing rotation migration recovery rollback privacy extension; do
  /usr/bin/grep -Fiq "${term}" "${design}" "${package_readme}" || {
    echo "error: CYB-81 documentation is missing ${term}" >&2
    exit 2
  }
done

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: mapping registry imports forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

artifact_dir=${COH_FOCUSED_ARTIFACT_DIR:-$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-mapping-registry.XXXXXX")}
/bin/mkdir -p "${artifact_dir}"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/domain/mappingregistry | /usr/bin/tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run TestExecutableVendorCorpus ./internal/domain/mappingregistry | /usr/bin/tee "${artifact_dir}/vendor.log"
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/domain/mappingregistry | /usr/bin/tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/mappingregistry | /usr/bin/tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/mappingregistry
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh" | /usr/bin/tee "${artifact_dir}/architecture.log"
file_size_artifact_dir=$(/usr/bin/mktemp -d "${artifact_dir}/file-size.XXXXXX")
COH_FILE_SIZE_ARTIFACT_DIR="${file_size_artifact_dir}" "${root}/scripts/check_file_sizes.sh" | /usr/bin/tee "${artifact_dir}/file-size.log"
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" "${design}" "${package_readme}"
/usr/bin/git diff --check

(
  cd "${artifact_dir}"
  /usr/bin/shasum -a 256 architecture.log file-size.log race.log repeat.log unit.log vendor.log > SHA256SUMS
)

echo "normalization-mapping-registry summary: issue=CYB-81 requirements=FR-021+FR-025 contract=1.0.0 mappings=signed+source-exact language=data-only replay=exact recovery=restart+lost-response rollback=immediate-predecessor vendor-cases=6 failures=0 artifacts=${artifact_dir}"
