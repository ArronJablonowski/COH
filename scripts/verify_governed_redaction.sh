#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/redaction"
contract="${root}/contracts/redaction/v1/governed-redaction.schema.json"
contract_readme="${root}/contracts/redaction/v1/README.md"
compatibility="${root}/contracts/redaction/v1/compatibility-matrix.md"
design="${root}/docs/design/governed-evidence-redaction.md"
sqlite_test="${root}/internal/persistence/sqlite/redaction_integration_test.go"

for path in "${package}/types.go" "${package}/preflight.go" "${package}/derive_publish.go" \
  "${package}/orchestrator.go" "${package}/orchestrator_denial.go" \
  "${package}/orchestrator_recovery.go" "${package}/repository_store.go" \
  "${contract}" "${contract_readme}" "${compatibility}" "${design}" "${sqlite_test}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: governed-redaction artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf == [
    {"$ref":"#/$defs/command"},
    {"$ref":"#/$defs/rule_set"},
    {"$ref":"#/$defs/approved_plan"},
    {"$ref":"#/$defs/mapping"},
    {"$ref":"#/$defs/authorization_request"},
    {"$ref":"#/$defs/decision"},
    {"$ref":"#/$defs/record"},
    {"$ref":"#/$defs/receipt"}
  ])
  and (."$defs".replacement_mode.enum == ["remove","mask","token"])
  and (."$defs".approval_state.enum == ["granted","consumed"])
  and (."$defs".command.additionalProperties == false)
  and (."$defs".rule_set.additionalProperties == false)
  and (."$defs".approved_plan.additionalProperties == false)
  and (."$defs".mapping.additionalProperties == false)
  and (."$defs".authorization_request.additionalProperties == false)
  and (."$defs".decision.additionalProperties == false)
  and (."$defs".record.additionalProperties == false)
  and (."$defs".receipt.additionalProperties == false)
' "${contract}" >/dev/null

for forbidden in plaintext selected_text replacement_text credential policy_source callback shell command_line filesystem_path network_client; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" >/dev/null; then
    echo "error: redaction contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/jq -e '
  ."$defs".command.properties.governing_decision_digest == {"$ref":"#/$defs/nullable_digest"}
  and (."$defs".command.required | index("governing_decision_digest") != null)
' "${root}/contracts/custody/v1/chain-of-custody.schema.json" >/dev/null

/usr/bin/grep -Fq '| Status | Implemented and verified |' "${design}"
/usr/bin/grep -Fq 'Mapping authorization is independent of derived-artifact authorization.' "${design}"
/usr/bin/grep -Fq 'V1 adds a validated `redaction_record` metadata kind' "${design}"
/usr/bin/grep -Fq 'A derived CAS reference alone' "${design}"
/usr/bin/grep -Fq 'Exact replay reauthorizes, verifies the stored audit' "${contract_readme}"
/usr/bin/grep -Fq 'governing-decision field' "${compatibility}"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: governed redaction imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/workflow/redaction \
  ./internal/workflow/redactioncustody ./internal/workflow/redactioningest ./internal/persistence/encryptedcas
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run Redaction ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/workflow/redaction \
  ./internal/workflow/redactioncustody ./internal/workflow/redactioningest ./internal/persistence/encryptedcas
"${COH_GO_ROOT}/bin/go" test -count=10 -run Redaction ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/redaction \
  ./internal/workflow/redactioncustody ./internal/workflow/redactioningest ./internal/persistence/encryptedcas
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run Redaction ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/redaction ./internal/workflow/redactioncustody \
  ./internal/workflow/redactioningest ./internal/persistence/encryptedcas ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${contract_readme}" "${compatibility}"
/usr/bin/git diff --check

echo "governed-redaction summary: issue=CYB-78 requirements=FR-030+SEC-036 spans=bounded-two-pass source=immutable mapping=encrypted approval=exact custody=verified audit=fail-closed recovery=sqlite-restart+concurrent replay=exact adversarial=complete failures=0"
