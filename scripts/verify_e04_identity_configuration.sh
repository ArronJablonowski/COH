#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for path in \
  "${root}/scripts/verify_local_auth.sh" \
  "${root}/scripts/verify_deployment_profiles.sh" \
  "${root}/scripts/verify_secret_backends.sh" \
  "${root}/scripts/verify_credential_leases.sh" \
  "${root}/scripts/verify_server_oidc.sh" \
  "${root}/docs/evidence/CYB-41-local-auth-report.md" \
  "${root}/docs/evidence/CYB-42-deployment-profile-report.md" \
  "${root}/docs/evidence/CYB-43-secret-backend-report.md" \
  "${root}/docs/evidence/CYB-45-credential-lease-report.md" \
  "${root}/docs/evidence/CYB-174-server-oidc-report.md"; do
  [[ -e "${path}" ]] || {
    echo "error: E04 integration input is missing: ${path}" >&2
    exit 2
  }
done

local_log=$(mktemp)
profile_log=$(mktemp)
secret_log=$(mktemp)
lease_log=$(mktemp)
oidc_log=$(mktemp)
trap 'rm -f "${local_log}" "${profile_log}" "${secret_log}" "${lease_log}" "${oidc_log}"' EXIT

"${root}/scripts/verify_local_auth.sh" "${root}" >"${local_log}"
"${root}/scripts/verify_deployment_profiles.sh" "${root}" >"${profile_log}"
"${root}/scripts/verify_secret_backends.sh" "${root}" >"${secret_log}"
"${root}/scripts/verify_credential_leases.sh" "${root}" >"${lease_log}"
"${root}/scripts/verify_server_oidc.sh" "${root}" >"${oidc_log}"

/usr/bin/grep -Fq 'local-auth summary:' "${local_log}"
/usr/bin/grep -Fq 'request-scope=full' "${oidc_log}"
/usr/bin/grep -Fq 'deployment-profile summary:' "${profile_log}"
/usr/bin/grep -Fq 'secret-backend summary:' "${secret_log}"
/usr/bin/grep -Fq 'rotation=live revocation=immediate' "${lease_log}"

[[ $(/usr/bin/grep -F 'localidentity.EvaluateRBAC' \
  "${root}/internal/transport/localauth/authorize.go" \
  "${root}/internal/transport/oidcauth/authorize.go" | /usr/bin/wc -l | /usr/bin/tr -d ' ') -eq 2 ]] || {
  echo 'error: local and server authorization do not share the RBAC evaluator' >&2
  exit 1
}

/usr/bin/jq -e '
  .properties.context.required == ["organization_id", "tenant_id", "case_id", "actor_id"]
' "${root}/contracts/identity/v1/authorization-request.schema.json" >/dev/null

/usr/bin/jq -e '
  .deployment.kind == "native_workstation"
  and .services.authentication == "local"
  and .services.transport_security == "loopback"
' "${root}/contracts/deployment/v1/fixtures/valid/native-workstation-connected.json" >/dev/null

/usr/bin/jq -e '
  (.deployment.kind == "native_server" or .deployment.kind == "compose")
  and .services.authentication == "oidc"
  and .services.transport_security == "mtls"
' "${root}/contracts/deployment/v1/fixtures/valid/native-server-restricted.json" \
  "${root}/contracts/deployment/v1/fixtures/valid/compose-connected.json" \
  "${root}/contracts/deployment/v1/fixtures/valid/compose-air-gap.json" >/dev/null

for ledger in \
  "${root}/docs/evidence/CYB-41-artifacts.sha256" \
  "${root}/docs/evidence/CYB-42-artifacts.sha256" \
  "${root}/docs/evidence/CYB-43-artifacts.sha256" \
  "${root}/docs/evidence/CYB-45-artifacts.sha256" \
  "${root}/docs/evidence/CYB-174-artifacts.sha256"; do
  (cd "${root}" && /usr/bin/shasum -a 256 -c "${ledger}" >/dev/null)
done

echo 'E04 integration summary: children=5 profiles=local+native-server+compose request-scope=organization+tenant+actor+case+role+permission+tier rbac=shared secrets=opaque+redacted leases=expiry+rotation+revocation-live audit=fail-closed failures=0'
