#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/custody"
contract="${root}/contracts/custody/v1/chain-of-custody.schema.json"
contract_readme="${root}/contracts/custody/v1/README.md"
design="${root}/docs/design/chain-of-custody.md"
sqlite_restart="${root}/internal/persistence/sqlite/custody_integration_test.go"
sqlite_concurrency="${root}/internal/persistence/sqlite/custody_concurrency_test.go"

for path in "${package}/types.go" "${package}/controller.go" "${package}/repository_store.go" \
  "${package}/verifier.go" "${package}/denial_test.go" "${package}/operations_test.go" \
  "${package}/verifier_test.go" "${contract}" "${contract_readme}" "${design}" \
  "${sqlite_restart}" "${sqlite_concurrency}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: custody artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf == [
    {"$ref":"#/$defs/command"},
    {"$ref":"#/$defs/authorization_request"},
    {"$ref":"#/$defs/decision"},
    {"$ref":"#/$defs/record"},
    {"$ref":"#/$defs/receipt"},
    {"$ref":"#/$defs/verification_report"}
  ])
  and (."$defs".operation.enum == ["acquire","access","transform","redact","transfer","export","place_hold","release_hold","delete"])
  and (."$defs".phase.enum == ["authorized","completed"])
  and (."$defs".decision_outcome.enum == ["allow","deny"])
  and (."$defs".command.additionalProperties == false)
  and (."$defs".authorization_request.additionalProperties == false)
  and (."$defs".decision.additionalProperties == false)
  and (."$defs".record.additionalProperties == false)
  and (."$defs".receipt.additionalProperties == false)
  and (."$defs".verification_report.additionalProperties == false)
' "${contract}" >/dev/null

for forbidden in content bytes prompt instruction credential secret policy_source connector executor callback shell http url uri path raw_key raw_evidence; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" >/dev/null; then
    echo "error: custody contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'The implemented `custody.Verifier` is read-only.' "${design}"
/usr/bin/grep -Fq 'Checkpoint private keys never enter the custody workflow or verifier.' "${design}"
/usr/bin/grep -Fq 'CYB-77 owns that' "${design}"
/usr/bin/grep -Fq 'Recovery never edits a record' "${design}"
/usr/bin/grep -Fq 'digests and timing can be linkable' "${design}"
/usr/bin/grep -Fq 'existing guarded metadata repository with a new validated' "${design}"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: custody imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/workflow/custody
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run Custody ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/workflow/custody
"${COH_GO_ROOT}/bin/go" test -count=10 -run Custody ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/custody
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run Custody ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/custody ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${contract_readme}"
/usr/bin/git diff --check

echo "chain-of-custody summary: issue=CYB-79 requirements=FR-020+FR-023+SEC-020+EVAL-013 operations=9 chain=append-only receipts=atomic replay=reauthorized audit=fail-closed sqlite=restart-safe concurrency=single-winner verifier=genesis+adversarial failures=0"
