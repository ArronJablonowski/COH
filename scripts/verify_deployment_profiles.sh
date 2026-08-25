#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/deployment/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/deployment-profile.schema.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/deploymentprofile" \
  "${root}/docs/design/deployment-profile-validation.md"; do
  [[ -e "${path}" ]] || {
    echo "error: deployment-profile input is missing: ${path}" >&2
    exit 2
  }
done

valid=("${contract}"/fixtures/valid/*.json)
[[ ${#valid[@]} -eq 5 ]] || {
  echo "error: expected five valid deployment-profile fixtures" >&2
  exit 2
}

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 10
  and (.properties.deployment.properties.kind.enum == ["native_workstation", "native_server", "compose"])
  and (.properties.connectivity.properties.mode.enum == ["connected", "restricted_connected", "air_gapped"])
  and (.properties | has("password") | not)
  and (.properties | has("credential") | not)
  and (.properties | has("secret_value") | not)
' "${contract}/deployment-profile.schema.json" >/dev/null

/usr/bin/jq -s -e '
  length == 5
  and ([.[].deployment.kind] | unique | sort) == ["compose", "native_server", "native_workstation"]
  and ([.[].connectivity.mode] | unique | sort) == ["air_gapped", "connected", "restricted_connected"]
  and all(.[]; .schema_version == "coh.deployment-profile/v1" and .contract_version == "1.0.0")
' "${valid[@]}" >/dev/null

/usr/bin/jq -e '
  .schema == "coh.deployment-profile-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 16
  and ([.cases[].name] | unique | length) == 16
  and all(.cases[]; (.expected_code == "denied" or .expected_code == "invalid_input") and (.reason | length) > 0)
' "${contract}/fixtures/denial-corpus.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/deploymentprofile"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/deploymentprofile"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/deploymentprofile"
"${root}/scripts/check_go_architecture.sh"

echo "deployment-profile summary: valid=5 denials=16 deployments=3 connectivity=3 authority=bound audit=fail-closed docker-native=absent failures=0"
