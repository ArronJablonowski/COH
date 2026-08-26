#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/approval/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/approval-lifecycle-state-machine.md" \
  "${contract}/fixtures/valid/approval-lifecycle-requested.json" \
  "${contract}/fixtures/lifecycle-denial-corpus.json" \
  "${root}/contracts/domain/v1/approval-lifecycle.schema.json" \
  "${root}/internal/domain/approvallifecycle" \
  "${root}/internal/broker/approval_service.go" \
  "${root}/docs/design/approval-lifecycle.md"; do
  [[ -e "${path}" ]] || {
    echo "error: approval-lifecycle input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .schema_version == "coh.approval-lifecycle-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 26
  and ([.cases[].name] | unique | length) == 26
  and ([.cases[].name] | contains(["self-approval", "stale-revision", "consume-after-limit", "fingerprint-binding-tamper", "audit-unavailable", "request-canceled", "request-timeout"]))
  and all(.cases[]; (.name | length) > 0 and (.reason | test("^[a-z][a-z0-9_.-]{0,127}$")))
' "${contract}/fixtures/lifecycle-denial-corpus.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.approval-lifecycle/v2"
  and .contract_version == "2.0.0"
  and .state == "requested"
  and .revision == 1
  and .required_grant_count == 1
  and .maximum_use_count == 1
  and .use_count == 0
  and (.grants | length) == 0
  and (.last_operation_digest | startswith("sha256:"))
' "${contract}/fixtures/valid/approval-lifecycle-requested.json" >/dev/null

/usr/bin/jq -e '
  .["$defs"].approval.additionalProperties == false
  and (.["$defs"].approval.properties.state.enum | length) == 6
  and .["$defs"].approval.properties.required_grant_count.maximum == 16
  and .["$defs"].approval.properties.maximum_use_count.maximum == 1000
' "${root}/contracts/domain/v1/approval-lifecycle.schema.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/approvallifecycle" "${root}/internal/broker" "${root}/internal/persistence/storetest" "${root}/internal/persistence/sqlite" "${root}/internal/persistence/postgres"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/approvallifecycle" "${root}/internal/broker"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/approvallifecycle" "${root}/internal/broker" "${root}/internal/persistence/storetest"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"

echo "approval-lifecycle summary: states=6 transitions=10 denials=26 storage_adapters=2 concurrency=cas idempotency=exact audit=atomic-outbox terminal=default-deny failures=0"
