#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/evidencelifecycle"
schema="${root}/contracts/evidence-lifecycle/v1/evidence-lifecycle.schema.json"
contract_readme="${root}/contracts/evidence-lifecycle/v1/README.md"
compatibility="${root}/contracts/evidence-lifecycle/v1/compatibility-matrix.md"
design="${root}/docs/design/signed-evidence-lifecycle.md"
sqlite_test="${root}/internal/persistence/sqlite/evidencelifecycle_integration_test.go"

for path in "${package}/types.go" "${package}/export_service.go" "${package}/import_service.go" \
  "${package}/hold_service.go" "${package}/delete_service.go" "${package}/repository_store.go" \
  "${package}/repository_codec.go" "${schema}" "${contract_readme}" "${compatibility}" \
  "${design}" "${sqlite_test}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: signed-evidence-lifecycle artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf == [
    {"$ref":"#/$defs/command"},
    {"$ref":"#/$defs/export_manifest"},
    {"$ref":"#/$defs/detached_signature"},
    {"$ref":"#/$defs/package_header"},
    {"$ref":"#/$defs/import_verification"},
    {"$ref":"#/$defs/authorization_request"},
    {"$ref":"#/$defs/decision"},
    {"$ref":"#/$defs/progress"},
    {"$ref":"#/$defs/disposition_attestation"},
    {"$ref":"#/$defs/record"},
    {"$ref":"#/$defs/receipt"}
  ])
  and (."$defs".operation.enum == ["export","import","place_hold","release_hold","delete"])
  and (."$defs".phase.enum == ["planned","quarantined","verified","authorized","packaged",
    "published","case_recorded","tombstoned","disposed","custodied","completed"])
  and (."$defs".verification_outcome.enum == ["valid","invalid","incomplete"])
  and (."$defs".package_header.properties.compression.const == "none")
  and (."$defs".detached_signature.properties.algorithm.const == "ed25519")
  and (."$defs".disposition_attestation.properties.mechanism.enum ==
    ["encrypted_object_removal","cryptographic_erasure_and_removal"])
  and (["command","export_manifest","detached_signature","package_header","import_verification",
    "authorization_request","decision","progress","disposition_attestation","record","receipt"] |
    all(. as $name | $schema."$defs"[$name].additionalProperties == false))
  and (."$defs".receipt.required | index("authorization_custody_receipt_digest") != null)
' --argjson schema "$(/usr/bin/jq -c . "${schema}")" "${schema}" >/dev/null

for forbidden in private_key credential policy_source callback command_line filesystem_path \
  network_client shell_command archive_path extraction_path; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${schema}" >/dev/null; then
    echo "error: signed evidence lifecycle contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq '| Status | Implemented and verified |' "${design}"
/usr/bin/grep -Fq 'The production `Store` adapter persists progress' "${design}"
/usr/bin/grep -Fq '## Operator runbook' "${design}"
/usr/bin/grep -Fq 'key revision, validity interval, and revocation status. Offline verification' "${design}"
/usr/bin/grep -Fq 'The production `PackageReader` runs in a dedicated import worker process with a' "${design}"
/usr/bin/grep -Fq 'Rollback disables new imports, exports, hold releases, and physical disposition' "${design}"
/usr/bin/grep -Fq 'Rotation never rewrites an old signature. Backup and disaster recovery must' "${design}"
/usr/bin/grep -Fq 'foreign authorization never implies a local allow decision. Exact replay needs' "${contract_readme}"
/usr/bin/grep -Fq 'Rollback to a binary without V1 writers' "${compatibility}"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" "${root}/internal/workflow/evidencepackage" "${root}/internal/workflow/evidencesigning" \
  "${root}/internal/workflow/importingest" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: signed evidence lifecycle imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
packages=(./internal/workflow/evidencelifecycle ./internal/workflow/evidencepackage \
  ./internal/workflow/evidencesigning ./internal/workflow/importingest)
"${COH_GO_ROOT}/bin/go" test -v -count=1 "${packages[@]}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run EvidenceLifecycle ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=10 "${packages[@]}"
"${COH_GO_ROOT}/bin/go" test -count=10 -run EvidenceLifecycle ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${packages[@]}"
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run EvidenceLifecycle ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet "${packages[@]}" ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${contract_readme}" "${compatibility}"
/usr/bin/git diff --check

echo "signed-evidence-lifecycle summary: issue=CYB-77 requirements=FR-028+FR-029+SEC-037+SEC-042 package=pathless+bounded+signed import=isolated+verified retention=current hold=fail-closed deletion=authorized+attested persistence=sqlite-restart+concurrent replay=exact adversarial=complete failures=0"
