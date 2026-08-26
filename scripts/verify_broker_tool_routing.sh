#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/tool/v1/tool-route.schema.json"
intent_fixture="${root}/contracts/tool/v1/fixtures/tool-route-intent.json"
state_fixture="${root}/contracts/tool/v1/fixtures/tool-route-state.json"
receipt_fixture="${root}/contracts/tool/v1/fixtures/tool-route-receipt.json"

paths=(
  "${contract}"
  "${intent_fixture}"
  "${state_fixture}"
  "${receipt_fixture}"
  "${root}/contracts/tool/v1/README.md"
  "${root}/docs/design/broker-only-tool-routing.md"
  "${root}/internal/domain/toolroute/types.go"
  "${root}/internal/domain/toolroute/canonical.go"
  "${root}/internal/broker/toolroute_authority.go"
  "${root}/internal/broker/toolroute_validate.go"
  "${root}/internal/broker/toolroute_audit.go"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: broker route input is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (."$defs".intent.properties.schema_version.const == "coh.tool-route/v1")
  and (."$defs".state.properties.record_type.const == "state")
  and (."$defs".state.properties.status.enum == ["pending","authorizing","dispatching","succeeded","denied","canceled","timeout","failed","uncertain"])
  and (."$defs".state.allOf | length == 3)
  and (."$defs".receipt.properties.outcome.enum == ["succeeded","denied","canceled","timeout","failed","uncertain"])
  and (."$defs".intent.additionalProperties == false)
  and (."$defs".state.additionalProperties == false)
  and (."$defs".receipt.additionalProperties == false)
  and (.oneOf | length == 3)
' "${contract}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.tool-route/v1"
  and .tool == "query_host"
  and (.target_digest | test("^sha256:[0-9a-f]{64}$"))
' "${intent_fixture}" >/dev/null
/usr/bin/jq -e '
  .schema_version == "coh.tool-route/v1"
  and .record_type == "state"
  and .status == "pending"
  and .approval_revision == 0
  and .previous_provenance_digest == ""
' "${state_fixture}" >/dev/null
/usr/bin/jq -e '
  .schema_version == "coh.tool-route/v1"
  and .outcome == "succeeded"
  and (.evidence_digest | test("^sha256:[0-9a-f]{64}$"))
' "${receipt_fixture}" >/dev/null

for boundary in workflow provider transport ui command; do
  directory="${root}/internal/${boundary}"
  [[ -d "${directory}" ]] || continue
  if /usr/bin/grep -R -n -E '"github[.]com/ArronJablonowski/COH/internal/(connector|broker/(nativeexecutor|ociexecutor|remoteworker|credentiallease|secretresolver))' \
    "${directory}" --include='*.go' >/dev/null; then
    echo "error: ${boundary} has a direct connector, executor, runner, credential, or secret route" >&2
    exit 2
  fi
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
packages=(./internal/domain/toolroute ./internal/broker ./internal/workflow/agentloop ./internal/workflow/agentphase)
"${COH_GO_ROOT}/bin/go" test -count=1 "${packages[@]}"
"${COH_GO_ROOT}/bin/go" test -count=3 "${packages[@]}"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${packages[@]}"
"${COH_GO_ROOT}/bin/go" vet "${packages[@]}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./cmd/archcheck
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${root}/contracts/tool/v1/README.md" \
  "${root}/docs/design/broker-only-tool-routing.md"
/usr/bin/git diff --check

echo "broker-route summary: contract=coh.tool-route/v1 ingress=ToolIntent authority=broker-only policy=fresh approval=exact audit=fail-closed state=durable replay=idempotent tamper=denied revocation=checked dispatch-replay=false failures=0"
