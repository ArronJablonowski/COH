#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/entity/v1"
schema="${contract}/entity-resolution.schema.json"
identity_fixture="${contract}/fixtures/identity-method-v1.json"
confidence_fixture="${contract}/fixtures/confidence-method-v1.json"
design="${root}/docs/design/evidence-linked-entity-resolution.md"
package="${root}/internal/domain/entityresolution"

for path in "${contract}/README.md" "${schema}" "${identity_fixture}" "${confidence_fixture}" "${design}" \
  "${package}/service.go" "${package}/persistence.go" "${package}/replay.go" "${package}/service_adversarial_test.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: CYB-83 artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 8
  and (["observation", "candidate", "entity", "decision", "history", "command", "outcome", "receipt"] |
    all(. as $name | $schema."$defs"[$name].additionalProperties == false))
  and (."$defs".command.required | contains(["candidate_id", "decision_id", "history_id", "history_sequence", "output_entity_id", "confidence", "confidence_assessments"]))
  and (."$defs".entity.required | contains(["previous_provenance_digests"]))
  and (."$defs".partition.required | contains(["confidence", "confidence_assessments"]))
  and (."$defs".command.properties.operation.enum == ["observe", "resolve", "merge", "split", "reject", "reindex"])
  and (."$defs".outcome.properties.status.enum | contains(["observed", "resolved", "merged", "split", "denied", "canceled", "timeout", "dependency_unavailable"]))
' --argjson schema "$(/usr/bin/jq -c . "${schema}")" "${schema}" >/dev/null

identity_digest="sha256:$(/usr/bin/jq -cjS . "${identity_fixture}" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
confidence_digest="sha256:$(/usr/bin/jq -cjS . "${confidence_fixture}" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
[[ "${identity_digest}" == "sha256:2ba2c987ef57b7edc98650985727890fe69224be794a7a1095375fe4d052132c" ]] || {
  echo "error: identity fixture digest changed: ${identity_digest}" >&2
  exit 2
}
[[ "${confidence_digest}" == "sha256:8d23a955b9dbe1421912110420558383bf903112aa56e3c4e231fef94c09e2d6" ]] || {
  echo "error: confidence fixture digest changed: ${confidence_digest}" >&2
  exit 2
}

if /usr/bin/jq -e '
  [.. | objects | .properties? // {} | keys[]]
  | any(. == "raw_identifier" or . == "identifier_value" or . == "private_key" or . == "credential" or
    . == "policy_source" or . == "callback" or . == "filesystem_path" or . == "network_client" or
    . == "shell_command" or . == "url" or . == "sql" or . == "executor" or . == "connector")
' "${schema}" >/dev/null; then
  echo "error: unsafe authority, identifier, or direct-access surface found in CYB-83 schema" >&2
  exit 2
fi

for term in FR-025 COH-E10 CYB-80 CYB-81 compatibility confidence migration recovery rollback privacy extension; do
  /usr/bin/grep -Fiq "${term}" "${contract}/README.md" "${design}" || {
    echo "error: CYB-83 documentation is missing ${term}" >&2
    exit 2
  }
done

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: entity resolution imports forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

artifact_dir=${COH_FOCUSED_ARTIFACT_DIR:-$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-entity-resolution.XXXXXX")}
/bin/mkdir -p "${artifact_dir}"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/domain/entityresolution | /usr/bin/tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run 'TestIdentityMethodFixture|TestConfidenceMethodFixture' \
  ./internal/domain/entityresolution | /usr/bin/tee "${artifact_dir}/fixtures.log"
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/domain/entityresolution | /usr/bin/tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/entityresolution | /usr/bin/tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/entityresolution
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh" | /usr/bin/tee "${artifact_dir}/architecture.log"
file_size_artifact_dir=$(/usr/bin/mktemp -d "${artifact_dir}/file-size.XXXXXX")
COH_FILE_SIZE_ARTIFACT_DIR="${file_size_artifact_dir}" "${root}/scripts/check_file_sizes.sh" | /usr/bin/tee "${artifact_dir}/file-size.log"
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" "${design}"
/usr/bin/git diff --check

(
  cd "${artifact_dir}"
  /usr/bin/shasum -a 256 architecture.log file-size.log fixtures.log race.log repeat.log unit.log > SHA256SUMS
)

echo "entity-resolution summary: issue=CYB-83 requirement=FR-025 contract=1.0.0 scope=case-local identity=typed+hmac confidence=bounded+recomputable history=merge+split+reversal provenance=multi-parent replay=exact recovery=restart+lost-response failures=0 artifacts=${artifact_dir}"
