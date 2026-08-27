#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
workflow_package="${root}/internal/workflow/evidenceingest"
cas_package="${root}/internal/persistence/encryptedcas"
contract="${root}/contracts/evidence/v1/immutable-cas-ingestion.schema.json"
contract_readme="${root}/contracts/evidence/v1/README.md"
design="${root}/docs/design/immutable-cas-ingestion.md"
sqlite_test="${root}/internal/persistence/sqlite/evidenceingest_integration_test.go"

for path in "${workflow_package}/types.go" "${workflow_package}/controller.go" \
  "${workflow_package}/repository_store.go" "${workflow_package}/repository_reconcile.go" \
  "${cas_package}/store.go" "${cas_package}/verify.go" "${cas_package}/filesystem_fault_test.go" \
  "${contract}" "${contract_readme}" "${design}" "${sqlite_test}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: immutable-CAS artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 6
  and (.oneOf == [
    {"$ref":"#/$defs/command"},
    {"$ref":"#/$defs/authorization_request"},
    {"$ref":"#/$defs/decision"},
    {"$ref":"#/$defs/artifact_manifest"},
    {"$ref":"#/$defs/encrypted_object"},
    {"$ref":"#/$defs/receipt"}
  ])
  and (."$defs".status.enum == ["staged","verified","published"])
  and (."$defs".source_kind.enum == ["upload","connector","query","tool","model","derived","import"])
  and (."$defs".component_kind.enum == ["tool","query","model"])
  and (."$defs".transport_mode.enum == ["in_process","mtls"])
  and (."$defs".command.additionalProperties == false)
  and (."$defs".authorization_request.additionalProperties == false)
  and (."$defs".decision.additionalProperties == false)
  and (."$defs".artifact_manifest.additionalProperties == false)
  and (."$defs".encrypted_object.additionalProperties == false)
  and (."$defs".published_object.additionalProperties == false)
  and (."$defs".receipt.additionalProperties == false)
  and (."$defs".receipt.properties.encrypted_artifact["$ref"] == "#/$defs/published_object")
  and (."$defs".receipt.properties.encrypted_manifest["$ref"] == "#/$defs/published_object")
' "${contract}" >/dev/null

for forbidden in content bytes prompt instruction credential secret policy_source approval executor callback shell http url uri path raw_key raw_evidence; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" >/dev/null; then
    echo "error: immutable-CAS contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'Pending identities are recorded' "${contract_readme}"
/usr/bin/grep -Fq 'in-place rewrap is not part of this contract' "${contract_readme}"
/usr/bin/grep -Fq 'The v1 surface provides no deletion operation' "${design}"
/usr/bin/grep -Fq 'receipt and both reference markers while deleting pending identities' "${design}"
/usr/bin/grep -Fq 'old decrypt-only key revisions' "${design}"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${workflow_package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: evidence ingestion imports a forbidden authority or execution capability" >&2
  exit 2
fi

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${cas_package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: encrypted CAS imports a forbidden network or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/workflow/evidenceingest ./internal/persistence/encryptedcas
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run Evidence ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/workflow/evidenceingest ./internal/persistence/encryptedcas
"${COH_GO_ROOT}/bin/go" test -count=5 -run Evidence ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/evidenceingest ./internal/persistence/encryptedcas
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run Evidence ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/evidenceingest ./internal/persistence/encryptedcas ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${contract_readme}"
/usr/bin/git diff --check

echo "immutable-cas summary: requirements=FR-019+FR-020+NFR-011+EVAL-012+SEC-023 stream=bounded-once encryption=aes-256-gcm-chunked publish=link+fsync manifest=encrypted receipt=atomic replay=reauthorized reconciliation=evidence-based sqlite=restart-safe concurrency=convergent failures=0"
