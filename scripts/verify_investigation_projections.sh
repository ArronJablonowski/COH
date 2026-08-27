#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/projection/v1"
schema="${contract}/investigation-projection.schema.json"
design="${root}/docs/design/deterministic-investigation-projections.md"
package="${root}/internal/domain/investigationprojection"

for path in "${contract}/README.md" "${schema}" "${design}" "${package}/reducer.go" "${package}/service.go" \
  "${package}/adversarial_test.go" "${package}/boundary_test.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: CYB-86 artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 6
  and (["fact", "projection", "checkpoint", "watermark_record", "query", "cache_entry"] |
    all(. as $name | $schema."$defs"[$name].additionalProperties == false))
  and (."$defs".fact.required | contains(["hypothesis_disposition", "time_relation", "order_confidence_millionths", "duplicate_of", "gap_digests", "conflict_digests"]))
  and (."$defs".timeline_entry.required | contains(["unknowns", "duplicate_of", "gap_digests", "conflict_digests"]))
  and (."$defs".projection.properties.kind.enum == ["correlation", "hypothesis", "timeline"])
  and (."$defs".query.properties.consistency.enum == ["current", "exact"])
' --argjson schema "$(/usr/bin/jq -c . "${schema}")" "${schema}" >/dev/null

if /usr/bin/jq -e '
  [.. | objects | .properties? // {} | keys[]]
  | any(. == "raw_event" or . == "evidence_bytes" or . == "private_key" or . == "credential" or
    . == "secret" or . == "policy_source" or . == "grant" or . == "callback" or . == "filesystem_path" or
    . == "network_client" or . == "shell_command" or . == "url" or . == "sql" or . == "executor" or
    . == "connector" or . == "model")
' "${schema}" >/dev/null; then
  echo "error: unsafe authority, content, or direct-access surface found in CYB-86 schema" >&2
  exit 2
fi

for term in FR-024 FR-025 FR-067 EVAL-017 COH-E10 CYB-80 CYB-81 CYB-82 CYB-83 checkpoint watermark \
  cache migration recovery rollback privacy extension; do
  /usr/bin/grep -Fiq "${term}" "${contract}/README.md" "${design}" || {
    echo "error: CYB-86 documentation is missing ${term}" >&2
    exit 2
  }
done

if /usr/bin/grep -R -n -E '"(net/http|os|os/exec|database/sql|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: investigation projection imports forbidden authority or direct I/O" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

artifact_dir=${COH_FOCUSED_ARTIFACT_DIR:-$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-investigation-projection.XXXXXX")}
/bin/mkdir -p "${artifact_dir}"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/domain/investigationprojection | /usr/bin/tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run 'TestEVAL017|TestService' \
  ./internal/domain/investigationprojection | /usr/bin/tee "${artifact_dir}/corpus.log"
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/domain/investigationprojection | /usr/bin/tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/investigationprojection | /usr/bin/tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" test -run '^$' -bench . -benchmem -benchtime=1s \
  ./internal/domain/investigationprojection | /usr/bin/tee "${artifact_dir}/benchmark.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/investigationprojection
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh" | /usr/bin/tee "${artifact_dir}/architecture.log"
file_size_artifact_dir=$(/usr/bin/mktemp -d "${artifact_dir}/file-size.XXXXXX")
COH_FILE_SIZE_ARTIFACT_DIR="${file_size_artifact_dir}" "${root}/scripts/check_file_sizes.sh" | /usr/bin/tee "${artifact_dir}/file-size.log"
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" "${design}"
/usr/bin/git diff --check

(
  cd "${artifact_dir}"
  /usr/bin/shasum -a 256 architecture.log benchmark.log corpus.log file-size.log race.log repeat.log unit.log > SHA256SUMS
)

echo "investigation-projection summary: issue=CYB-86 requirements=FR-024+FR-025+FR-067+EVAL-017 contract=1.0.0 reducers=correlation+hypothesis+timeline checkpoint=verified+tail-replay cache=exact+zero-io uncertainty=preserved failures=0 artifacts=${artifact_dir}"
