#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/identity/oidc/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/provider.schema.json" \
  "${contract}/token-claims.schema.json" \
  "${contract}/fixtures/valid/native-server.provider.json" \
  "${contract}/fixtures/valid/analyst.claims.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/oidcidentity" \
  "${root}/internal/transport/oidcauth" \
  "${root}/internal/command/server_oidc.go" \
  "${root}/docs/design/server-oidc-authentication.md"; do
  [[ -e "${path}" ]] || {
    echo "error: server OIDC input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 11
  and (.properties.profile_kind.enum == ["native_server", "compose"])
  and (.properties.allowed_algorithms.items.enum == ["EdDSA", "ES256", "RS256"])
  and (.properties.transport_security.const == "mtls")
  and (.properties | has("client_secret") | not)
  and (.properties | has("token") | not)
  and (.properties | has("password") | not)
' "${contract}/provider.schema.json" >/dev/null

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 12
  and (.properties.coh_roles.items.enum == ["administrator", "analyst", "approver", "auditor", "service"])
  and (.properties | has("access_token") | not)
  and (.properties | has("refresh_token") | not)
  and (.properties | has("password") | not)
' "${contract}/token-claims.schema.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.server-oidc/v1"
  and .contract_version == "1.0.0"
  and .profile_kind == "native_server"
  and .transport_security == "mtls"
  and .issuer == "https://identity.example.invalid/tenant-a"
  and .audiences == ["coh-server"]
  and .allowed_algorithms == ["EdDSA", "ES256", "RS256"]
' "${contract}/fixtures/valid/native-server.provider.json" >/dev/null

/usr/bin/jq -e '
  .iss == "https://identity.example.invalid/tenant-a"
  and .aud == ["coh-server"]
  and .coh_roles == ["analyst"]
  and (.coh_tenant_ids | length) == 1
  and (.nonce | length) == 43
  and .exp > .iat
  and .nbf <= .iat
' "${contract}/fixtures/valid/analyst.claims.json" >/dev/null

/usr/bin/jq -e '
  .schema == "coh.server-oidc-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 24
  and ([.cases[].name] | unique | length) == 24
  and ([.cases[].name] | contains(["provider-none-algorithm", "provider-no-mtls", "claims-bad-nonce", "claims-service-mixed", "claims-token-field"]))
  and all(.cases[]; (.document == "provider" or .document == "claims") and (.reason | length) > 0)
' "${contract}/fixtures/denial-corpus.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/oidcidentity" "${root}/internal/transport/oidcauth" "${root}/internal/command"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/oidcidentity" "${root}/internal/transport/oidcauth" "${root}/internal/command"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/oidcidentity" "${root}/internal/transport/oidcauth" "${root}/internal/command"
"${root}/scripts/check_go_architecture.sh"

echo "server-oidc summary: profiles=2 algorithms=3 denials=24 state=single-use sessions=digest-only request-scope=full rotation=live audit=fail-closed composition=decision-bound failures=0"
