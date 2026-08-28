#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/profile-composition/v1"
composition="${root}/internal/domain/profilecomposition"
activation="${root}/internal/domain/profileactivation"
design="${root}/docs/design/signed-deterministic-profile-composition.md"

paths=(
  "${contract}/signed-profile-layer.schema.json"
  "${contract}/resolved-profile.schema.json"
  "${contract}/profile-inspection.schema.json"
  "${contract}/profile-activation-transition.schema.json"
  "${contract}/active-profile.schema.json"
  "${contract}/compatibility-matrix.md"
  "${contract}/fixtures/layer.signed.valid.json"
  "${contract}/fixtures/denial-corpus.json"
  "${composition}/types.go"
  "${composition}/verify.go"
  "${composition}/merge.go"
  "${composition}/finalize.go"
  "${composition}/inspection.go"
  "${composition}/adversarial_test.go"
  "${activation}/controller.go"
  "${activation}/validate.go"
  "${activation}/adversarial_test.go"
  "${root}/internal/command/profile_parity_test.go"
  "${root}/internal/command/profile_rollback_test.go"
  "${root}/internal/persistence/sqlite/profile_activation.go"
  "${root}/internal/persistence/sqlite/profile_activation_integration_test.go"
  "${design}"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: profile-composition artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

schemas=(
  "signed-profile-layer.schema.json:coh.signed-profile-layer/v1"
  "resolved-profile.schema.json:coh.resolved-profile/v1"
  "profile-inspection.schema.json:coh.profile-inspection/v1"
  "profile-activation-transition.schema.json:coh.profile-activation-transition/v1"
  "active-profile.schema.json:coh.active-profile/v1"
)
for entry in "${schemas[@]}"; do
  schema=${entry%%:*}
  version=${entry#*:}
  /usr/bin/jq -e --arg version "${version}" '
    .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    and .properties.schema_version.const == $version
    and .properties.contract_version.const == "1.0.0"
    and .additionalProperties == false
    and (.required | index("schema_version") != null)
    and (.required | index("contract_version") != null)
  ' "${contract}/${schema}" >/dev/null
done

/usr/bin/jq -e '
  .schema_version == "coh.signed-profile-layer/v1"
  and .contract_version == "1.0.0"
  and (.signatures | length) >= 2
' "${contract}/fixtures/layer.signed.valid.json" >/dev/null
/usr/bin/jq -e '
  .schema_version == "coh.profile-composition-denial-corpus/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 15
  and ([.cases[].name] | unique | length) == 15
' "${contract}/fixtures/denial-corpus.json" >/dev/null

for forbidden in credential_value secret_value raw_evidence prompt_content private_path raw_config executable_payload callback function_pointer; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}"/*.schema.json >/dev/null; then
    echo "error: profile-composition contract contains forbidden payload or authority field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'COH-E25-02 / CYB-183' "${contract}/README.md"
for requirement in NFR-003 NFR-019 SEC-018 SEC-033 SEC-034 EVAL-029; do
  /usr/bin/grep -Fq "${requirement}" "${contract}/README.md"
done
/usr/bin/grep -Fq 'Live hot reload' "${contract}/README.md"
for mode in workstation 'native server' Compose connected restricted air-gap Web CLI API headless test; do
  /usr/bin/grep -Fq "${mode}" "${contract}/README.md"
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
quality_binary="$(mktemp "${GOTMPDIR}/profile-composition-qualitygate.XXXXXX")"
cleanup() { rm -f "${quality_binary}"; }
trap cleanup EXIT
"${COH_GO_ROOT}/bin/go" build -trimpath -o "${quality_binary}" ./cmd/qualitygate
chmod 0500 "${quality_binary}"
export COH_QUALITYGATE_BIN="${quality_binary}"

focused=(
  ./internal/domain/profilecomposition
  ./internal/domain/profileactivation
  ./internal/command
  ./internal/persistence/sqlite
)
"${COH_GO_ROOT}/bin/go" test -v -count=1 "${focused[@]}"
"${COH_GO_ROOT}/bin/go" test -count=20 "${focused[@]}"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${focused[@]}"
"${COH_GO_ROOT}/bin/go" vet "${focused[@]}" ./cmd/archcheck
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_secrets.sh" worktree
"${root}/scripts/check_licenses.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" \
  "${contract}/compatibility-matrix.md" "${design}"
"${root}/scripts/check_fuzz_seeds.sh"
/usr/bin/git diff --check

echo "profile-composition summary: issue=CYB-183 contract=v1 signatures=ed25519 composition=deterministic inspection=redacted activation=quiescent+durable parity=native+compose+airgap+all-surfaces rollback=reauthorized adversarial=complete failures=0"
