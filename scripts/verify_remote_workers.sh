#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/worker/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/capability-attestation.schema.json" \
  "${contract}/signed-capability-attestation.schema.json" \
  "${contract}/enrollment-request.schema.json" \
  "${contract}/runner-lease-request.schema.json" \
  "${contract}/dispatch-request.schema.json" \
  "${contract}/revocation-request.schema.json" \
  "${contract}/decision.schema.json" \
  "${root}/internal/domain/remoteworker" \
  "${root}/internal/broker/remoteworker" \
  "${root}/internal/transport/workeridentity" \
  "${root}/docs/design/remote-worker-enrollment-and-leases.md"; do
  [[ -e "${path}" ]] || {
    echo "error: remote-worker input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 19
  and (.properties.maximum_action_tier.enum == ["T0", "T1", "T2", "T3"])
  and (.properties.isolation_classes.items.enum | index("t4_dedicated") | not)
  and (.properties.isolation_classes.uniqueItems == true)
  and (.properties.network_modes.uniqueItems == true)
  and (.properties | has("private_key") | not)
  and (.properties | has("lease_token") | not)
' "${contract}/capability-attestation.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.signature_algorithm.const == "ed25519"
  and (.required | length) == 8
' "${contract}/signed-capability-attestation.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.requested_ttl_seconds.minimum == 1
  and .properties.requested_ttl_seconds.maximum == 300
  and (.properties.scope.required | index("isolation_class") != null)
  and (.properties.scope.required | index("resource_policy_digest") != null)
  and (.properties.scope.required | index("network_policy_digest") != null)
  and (.properties | has("capability") | not)
  and (.properties | has("lease_token") | not)
' "${contract}/runner-lease-request.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.runner-dispatch/v1"
  and (.properties | has("lease_token") | not)
  and (.properties | has("capability") | not)
' "${contract}/dispatch-request.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.remote-worker-revocation/v1"
  and (.properties.kind.enum | length) == 4
  and (.allOf | length) == 2
' "${contract}/revocation-request.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.remote-worker-decision/v1"
  and (.properties | has("signature") | not)
  and (.properties | has("enrollment_nonce") | not)
  and (.properties | has("lease_token") | not)
' "${contract}/decision.schema.json" >/dev/null

if /usr/bin/grep -R -E 'json:"(token|lease_token|capability|private_key|secret)"' \
  "${root}/internal/domain/remoteworker" --include='*.go' >/dev/null; then
  echo "error: serializable secret or capability field found" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-remote-workers.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

cd "${root}"
packages=(./internal/domain/remoteworker ./internal/broker/remoteworker ./internal/transport/workeridentity)
"${COH_GO_ROOT}/bin/go" test -count=1 "${packages[@]}" | tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -count=3 "${packages[@]}" | tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${packages[@]}" | tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet "${packages[@]}"

GOOS=linux GOARCH=amd64 "${COH_GO_ROOT}/bin/go" test -c -o "${artifact_dir}/remoteworker-linux.test" ./internal/broker/remoteworker
GOOS=windows GOARCH=amd64 "${COH_GO_ROOT}/bin/go" test -c -o "${artifact_dir}/remoteworker-windows.test.exe" ./internal/broker/remoteworker

"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
/usr/bin/git diff --check

echo "remote-worker summary: attestation=ed25519-software freshness=5m remote_transport=mtls local_transport=authenticated-socket tiers=T0-T3 t4=denied enrollment=immutable+rotatable lease=random+short-lived+single-use claim=atomic isolation=exact resources=bounded network=bound revocation=immediate audit=fail-closed failures=0"
