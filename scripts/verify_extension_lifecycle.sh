#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/extension-lifecycle/v1"
domain="${root}/internal/domain/extensionlifecycle"

paths=(
  "${contract}/signed-extension-manifest.schema.json"
  "${contract}/extension-activation-intent.schema.json"
  "${contract}/extension-revocation-handle.schema.json"
  "${contract}/extension-registration-receipt.schema.json"
  "${contract}/extension-lifecycle-transition.schema.json"
  "${contract}/active-extension.schema.json"
  "${contract}/compatibility-matrix.md"
  "${domain}/verify.go"
  "${domain}/activation.go"
  "${domain}/deactivation.go"
  "${domain}/control_authority.go"
  "${domain}/lineage_test.go"
  "${root}/internal/command/extension_lifecycle.go"
  "${root}/internal/broker/extension_lifecycle.go"
  "${root}/internal/persistence/sqlite/extension_lifecycle.go"
  "${root}/internal/persistence/sqlite/extension_lifecycle_atomic.go"
  "${root}/internal/persistence/sqlite/extension_lifecycle_integration_test.go"
  "${root}/internal/persistence/sqlite/extension_lifecycle_adversarial_test.go"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: extension-lifecycle artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

schemas=(
  "signed-extension-manifest.schema.json:coh.signed-extension-manifest/v1"
  "extension-activation-intent.schema.json:coh.extension-activation-intent/v1"
  "extension-revocation-handle.schema.json:coh.extension-revocation-handle/v1"
  "extension-registration-receipt.schema.json:coh.extension-registration-receipt/v1"
  "extension-lifecycle-transition.schema.json:coh.extension-lifecycle-transition/v1"
  "active-extension.schema.json:coh.active-extension/v1"
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

for forbidden in credential_value secret_value raw_evidence prompt_content private_path executable_payload callback function_pointer authority_object; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}"/*.schema.json >/dev/null; then
    echo "error: extension lifecycle contract contains forbidden payload or authority field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'COH-E25-03 / CYB-184' "${contract}/README.md"
for requirement in FR-014 FR-015 FR-042 FR-043 SEC-018 SEC-020; do
  /usr/bin/grep -Fq "${requirement}" "${contract}/README.md"
done
/usr/bin/grep -Fq 'Production agents' "${contract}/README.md"
/usr/bin/grep -Fq 'ARCH-005' "${contract}/README.md"

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
quality_binary="$(mktemp "${GOTMPDIR}/extension-lifecycle-qualitygate.XXXXXX")"
cleanup() { rm -f "${quality_binary}"; }
trap cleanup EXIT
"${COH_GO_ROOT}/bin/go" build -trimpath -o "${quality_binary}" ./cmd/qualitygate
chmod 0500 "${quality_binary}"
export COH_QUALITYGATE_BIN="${quality_binary}"

focused=(
  ./internal/domain/extensionlifecycle
  ./internal/command
  ./internal/broker
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
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" "${contract}/compatibility-matrix.md"
"${root}/scripts/check_fuzz_seeds.sh"
/usr/bin/git diff --check

echo "extension-lifecycle summary: issue=CYB-184 contract=v1 signatures=ed25519 activation=transactional unwind=reverse deactivation=scoped recovery=restart+crash authority=command-root+broker agents=denied upgrade=durable rollback=reauthorized adversarial=complete failures=0"
