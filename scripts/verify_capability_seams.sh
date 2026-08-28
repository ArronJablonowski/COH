#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/capability-seam/v1"
package="${root}/internal/domain/capabilityseam"
design="${root}/docs/design/typed-capability-seams.md"

paths=(
  "${contract}/capability-seam-bundle.schema.json"
  "${contract}/resolved-capability-graph.schema.json"
  "${contract}/compatibility-matrix.md"
  "${contract}/fixtures/bundle.valid.json"
  "${contract}/fixtures/graph.valid.json"
  "${contract}/fixtures/denial-corpus.json"
  "${package}/types.go"
  "${package}/decode.go"
  "${package}/validate.go"
  "${package}/resolver.go"
  "${package}/qualification_authority.go"
  "${package}/authority_catalog.go"
  "${package}/adversarial_test.go"
  "${root}/contracts/architecture/v1/fixtures/invalid/capability-composition-bypass.json"
  "${design}"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: capability-seam artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .properties.schema_version.const == "coh.capability-seam-bundle/v1"
  and .properties.contract_version.const == "1.0.0"
  and .additionalProperties == false
  and (.required == ["schema_version","contract_version","bundle_id","revision","profile_digest","definitions","providers","consumers"])
  and (."$defs".definition.properties.access_policy.enum == ["broker_intent_only","read_only_service"])
  and (."$defs".definition.additionalProperties == false)
  and (."$defs".provider.additionalProperties == false)
  and (."$defs".consumer.additionalProperties == false)
' "${contract}/capability-seam-bundle.schema.json" >/dev/null

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .properties.schema_version.const == "coh.resolved-capability-graph/v1"
  and .properties.contract_version.const == "1.0.0"
  and .additionalProperties == false
  and (.required | index("bundle_digest") != null)
  and (.required | index("profile_digest") != null)
  and (.required | index("resolution_order") != null)
  and (.required | index("graph_digest") != null)
' "${contract}/resolved-capability-graph.schema.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.capability-seam-bundle/v1"
  and .contract_version == "1.0.0"
  and (.definitions | length) == 1
  and (.providers | length) == 1
  and (.consumers | length) == 1
' "${contract}/fixtures/bundle.valid.json" >/dev/null
/usr/bin/jq -e '
  .schema_version == "coh.resolved-capability-graph/v1"
  and .contract_version == "1.0.0"
  and (.graph_digest | test("^sha256:[0-9a-f]{64}$"))
' "${contract}/fixtures/graph.valid.json" >/dev/null
/usr/bin/jq -e '
  .schema_version == "coh.capability-seam-denial-corpus/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 10
  and ([.cases[].name] | unique | length) == 10
' "${contract}/fixtures/denial-corpus.json" >/dev/null

for forbidden in callback function_pointer credential_value secret_value raw_config prompt evidence_bytes private_path network_endpoint executable_payload; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}/capability-seam-bundle.schema.json" \
    "${contract}/resolved-capability-graph.schema.json" >/dev/null; then
    echo "error: capability-seam contract contains forbidden authority or payload field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'Any model-originated operation remains a typed broker intent' "${contract}/README.md"
/usr/bin/grep -Fq 'maximum-five-minute trusted registry snapshot' "${contract}/README.md"
/usr/bin/grep -Fq 'ARCH-003' "${root}/contracts/architecture/v1/README.md"

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
quality_binary="$(mktemp "${GOTMPDIR}/capability-seam-qualitygate.XXXXXX")"
cleanup() { rm -f "${quality_binary}"; }
trap cleanup EXIT
"${COH_GO_ROOT}/bin/go" build -trimpath -o "${quality_binary}" ./cmd/qualitygate
chmod 0500 "${quality_binary}"
export COH_QUALITYGATE_BIN="${quality_binary}"

"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/domain/capabilityseam
"${COH_GO_ROOT}/bin/go" test -count=20 ./internal/domain/capabilityseam
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/capabilityseam ./cmd/archcheck
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/capabilityseam ./cmd/archcheck
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_secrets.sh" worktree
"${root}/scripts/check_licenses.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" \
  "${contract}/compatibility-matrix.md" "${design}"
"${root}/scripts/check_fuzz_seeds.sh"
/usr/bin/git diff --check

echo "capability-seam summary: issue=CYB-182 contract=v1 roles=definition+provider+consumer graph=closed+deterministic qualification=live+revocation-aware authority=nonreplaceable routing=broker-intent-only adversarial=complete failures=0"
