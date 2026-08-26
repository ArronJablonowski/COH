#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/caselifecycle"
contract="${root}/contracts/case/v1/case-lifecycle.schema.json"
contract_readme="${root}/contracts/case/v1/README.md"
design="${root}/docs/design/case-lifecycle.md"
sqlite_test="${root}/internal/persistence/sqlite/caselifecycle_integration_test.go"

for path in "${package}/types.go" "${package}/controller.go" "${package}/repository_store.go" \
  "${package}/boundary_test.go" "${contract}" "${contract_readme}" "${design}" "${sqlite_test}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: case-lifecycle artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 5
  and (.["$defs"].operation.enum == ["create","classify","assign","place_hold","release_hold","close","reopen","export","delete"])
  and (.["$defs"].state.enum == ["open","closed","deleted"])
  and (.["$defs"].classification.enum == ["public","internal","confidential","restricted"])
  and (.["$defs"].command.additionalProperties == false)
  and (.["$defs"].authorization_request.additionalProperties == false)
  and (.["$defs"].decision.additionalProperties == false)
  and (.["$defs"].record.additionalProperties == false)
  and (.["$defs"].receipt.additionalProperties == false)
  and (.["$defs"].receipt.properties.command["$ref"] == "#/$defs/command")
  and (.["$defs"].receipt.properties.record["$ref"] == "#/$defs/record")
' "${contract}" >/dev/null

for forbidden in content bytes prompt instruction credential secret policy_source approval connector executor callback shell http url uri path; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}" >/dev/null; then
    echo "error: case lifecycle contract contains forbidden field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'Deletion is a durable tombstone transition.' "${design}"
/usr/bin/grep -Fq 'Authorization is evaluated for the initial command and again on exact replay.' "${design}"
/usr/bin/grep -Fq 'The metadata record is not physically deleted.' "${design}"
/usr/bin/grep -Fq 'generic guarded metadata repository already stores canonical typed' "${design}"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport|connector))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: case lifecycle imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -v -count=1 ./internal/workflow/caselifecycle
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run TestCaseLifecycle ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=5 ./internal/workflow/caselifecycle
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/caselifecycle
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run TestCaseLifecycle ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/caselifecycle ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${contract_readme}"
/usr/bin/git diff --check

echo "case-lifecycle summary: operations=9 scope=tenant+case actor=revision-bound state=optimistic hold=fail-closed deletion=tombstone replay=reauthorized audit=before-release provenance=chained sqlite=restart-safe failures=0"
