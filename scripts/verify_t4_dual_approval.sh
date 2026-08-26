#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/approval/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/approval-lifecycle-state-machine.md" \
  "${contract}/fixtures/t4-denial-corpus.json" \
  "${root}/contracts/domain/v1/approval-lifecycle.schema.json" \
  "${root}/internal/broker/approval_fingerprint.go" \
  "${root}/internal/broker/approval_transition.go" \
  "${root}/docs/design/t4-dual-approval.md"; do
  [[ -e "${path}" ]] || {
    echo "error: T4 dual-approval input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .schema_version == "coh.t4-dual-approval-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 26
  and ([.cases[].name] | unique | length) == 26
  and ([.cases[].name] | contains(["zero-approvers", "one-approver", "duplicate-human-principal", "requestor-principal-alias", "service-identity", "unenrolled-approver", "revoked-approver", "concurrent-grant-conflict", "audit-unavailable"]))
  and all(.cases[]; (.name | length) > 0 and (.reason | test("^[a-z][a-z0-9_.-]{0,127}$")))
' "${contract}/fixtures/t4-denial-corpus.json" >/dev/null

/usr/bin/jq -e '
  .["$defs"].approval.properties.schema_version.enum == ["coh.approval-lifecycle/v2"]
  and .["$defs"].approval.properties.contract_version.enum == ["2.0.0"]
  and .["$defs"].approval.properties.action_tier.enum == ["T0", "T1", "T2", "T3", "T4"]
  and (.["$defs"].approval.required | contains(["requestor_principal_id", "action_tier"]))
  and (.["$defs"].grant.required | contains(["principal_id", "enrollment_revision"]))
' "${root}/contracts/domain/v1/approval-lifecycle.schema.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 -run 'TestT4' "${root}/internal/broker"
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run 'TestT4' "${root}/internal/broker"
"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/approvallifecycle" "${root}/internal/persistence/storetest" "${root}/internal/persistence/sqlite" "${root}/internal/persistence/postgres"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/broker" "${root}/internal/domain/approvallifecycle"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"

echo "t4-dual-approval summary: threshold=2 distinct=actor-and-principal human=required enrollment=fresh partial=unavailable consume=revalidated concurrency=cas denials=26 failures=0"
