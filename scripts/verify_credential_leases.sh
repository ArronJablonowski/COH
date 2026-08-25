#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/credential/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/issuance-request.schema.json" \
  "${contract}/fixtures/valid/connector.request.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/credentiallease" \
  "${root}/internal/broker/credentiallease" \
  "${root}/internal/broker/secretresolver" \
  "${root}/docs/design/credential-leases.md"; do
  [[ -e "${path}" ]] || {
    echo "error: credential-lease input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 13
  and (.properties.context.required == ["organization_id", "tenant_id", "case_id", "actor_id"])
  and (.properties.audience.required == ["kind", "id", "transport_identity_digest"])
  and (.properties.target_digests.minItems == 1)
  and (.properties.target_digests.maxItems == 64)
  and (.properties.target_digests.uniqueItems == true)
  and (.properties.requested_ttl_seconds.minimum == 1)
  and (.properties.requested_ttl_seconds.maximum == 300)
  and (.properties | has("secret_value") | not)
  and (.properties | has("lease_token") | not)
  and (.properties | has("capability") | not)
  and (.properties | has("password") | not)
  and (.properties | has("private_key") | not)
' "${contract}/issuance-request.schema.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.credential-lease/v1"
  and .contract_version == "1.0.0"
  and (.target_digests == (.target_digests | sort | unique))
  and (.target_digests | length) > 0
  and (.audience.kind == "connector" or .audience.kind == "runner")
  and (.audience.transport_identity_digest | startswith("sha256:"))
  and .requested_ttl_seconds >= 1
  and .requested_ttl_seconds <= 300
  and (.reference.version > 0)
' "${contract}/fixtures/valid/connector.request.json" >/dev/null

/usr/bin/jq -e '
  .schema == "coh.credential-lease-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 24
  and ([.cases[].name] | unique | length) == 24
  and ([.cases[].name] | contains(["secret-value-field", "lease-token-field", "unsorted-targets", "unknown-audience-kind", "excessive-ttl", "forbidden-inline-backend"]))
  and all(.cases[]; (.operation == "set" or .operation == "remove") and (.reason | length) > 0)
' "${contract}/fixtures/denial-corpus.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/credentiallease" "${root}/internal/broker/credentiallease"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/credentiallease" "${root}/internal/broker/credentiallease"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/credentiallease" "${root}/internal/broker/credentiallease"
"${root}/scripts/check_go_architecture.sh"

echo "credential-lease summary: requests=1 denials=24 ttl_max=300 capability=private issuance=atomic dispatch=single-use rotation=live revocation=immediate mtls=bound audit=fail-closed failures=0"
