#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/identity/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/actor.schema.json" \
  "${contract}/authorization-request.schema.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/localidentity" \
  "${root}/internal/transport/localauth" \
  "${root}/docs/design/local-authentication-rbac.md"; do
  [[ -e "${path}" ]] || {
    echo "error: local-auth input is missing: ${path}" >&2
    exit 2
  }
done

actors=("${contract}"/fixtures/valid/*.actor.json)
requests=("${contract}"/fixtures/valid/*.request.json)
[[ ${#actors[@]} -eq 4 && ${#requests[@]} -eq 5 ]] || {
  echo "error: expected four actor and five request fixtures" >&2
  exit 2
}

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 10
  and (.properties.roles.items.enum == ["administrator", "analyst", "approver", "auditor", "service"])
  and (.properties | has("private_key") | not)
  and (.properties | has("signature") | not)
  and (.properties | has("session_token") | not)
  and (.properties | has("password") | not)
' "${contract}/actor.schema.json" >/dev/null

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 9
  and (.properties.channel.enum == ["api", "cli"])
  and (.properties.context.required == ["organization_id", "tenant_id", "case_id", "actor_id"])
  and (.properties | has("signature") | not)
  and (.properties | has("session_token") | not)
  and (.properties | has("password") | not)
' "${contract}/authorization-request.schema.json" >/dev/null

/usr/bin/jq -s -e '
  length == 4
  and ([.[].roles[]] | unique | sort) == ["administrator", "analyst", "approver", "auditor", "service"]
  and all(.[]; .schema_version == "coh.local-identity/v1" and .contract_version == "1.0.0" and .revision > 0)
' "${actors[@]}" >/dev/null

/usr/bin/jq -s -e '
  length == 5
  and ([.[].channel] | unique | sort) == ["api", "cli"]
  and all(.[]; .schema_version == "coh.local-identity/v1" and .contract_version == "1.0.0")
  and all(.[]; (.context | keys | sort) == ["actor_id", "case_id", "organization_id", "tenant_id"])
' "${requests[@]}" >/dev/null

/usr/bin/jq -e '
  .schema == "coh.local-identity-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 22
  and ([.cases[].name] | unique | length) == 22
  and all(.cases[];
    (.document == "actor" or .document == "request")
    and (.expected_code == "denied" or .expected_code == "invalid_input")
    and (.reason | length) > 0)
' "${contract}/fixtures/denial-corpus.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/localidentity" "${root}/internal/transport/localauth"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/localidentity" "${root}/internal/transport/localauth"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/localidentity" "${root}/internal/transport/localauth"
"${root}/scripts/check_go_architecture.sh"

echo "local-auth summary: actors=4 requests=5 denials=22 channels=2 roles=5 proof=ed25519 sessions=digest-only replay=atomic audit=fail-closed failures=0"
