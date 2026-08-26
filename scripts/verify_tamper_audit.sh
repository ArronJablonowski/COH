#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/audit/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/audit-event.schema.json" \
  "${contract}/audit-record.schema.json" \
  "${contract}/audit-checkpoint.schema.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/tamperaudit" \
  "${root}/internal/workflow/auditlog" \
  "${root}/internal/broker/auditsigner" \
  "${root}/docs/design/tamper-evident-audit.md"; do
  [[ -e "${path}" ]] || {
    echo "error: tamper-audit input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .type == "object"
  and .additionalProperties == false
  and .properties.schema_version.const == "coh.audit-event/v1"
  and (.required | contains(["event_id", "organization_id", "tenant_id", "source_schema", "operation", "outcome", "reason_code", "evidence_digests"]))
  and (.properties | has("secret") | not)
  and (.properties | has("payload") | not)
  and (.properties | has("arguments") | not)
' "${contract}/audit-event.schema.json" >/dev/null

/usr/bin/jq -e '
  .properties.schema_version.const == "coh.audit-checkpoint/v1"
  and .properties.signature_algorithm.const == "ed25519"
  and .properties.record_count.maximum == 10000
  and (.properties.reason.enum == ["daily", "record_limit", "manual_final"])
' "${contract}/audit-checkpoint.schema.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.audit-denial-corpus/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 34
  and ([.cases[].name] | unique | length) == 34
  and ([.cases[].name] | contains(["sequence-gap", "record-deletion", "forked-chain-head", "checkpoint-signature-tamper", "post-revocation-checkpoint", "record-store-unavailable", "crash-after-commit-response-loss"]))
  and all(.cases[]; (.name | length) > 0 and (.reason | test("^[a-z][a-z0-9_.-]{0,127}$")))
' "${contract}/fixtures/denial-corpus.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/tamperaudit" "${root}/internal/workflow/auditlog" "${root}/internal/broker/auditsigner" "${root}/internal/persistence/storetest" "${root}/internal/persistence/sqlite" "${root}/internal/persistence/postgres"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/tamperaudit" "${root}/internal/workflow/auditlog" "${root}/internal/broker/auditsigner"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/tamperaudit" "${root}/internal/workflow/auditlog" "${root}/internal/broker/auditsigner" "${root}/internal/persistence/sqlite" "${root}/internal/persistence/postgres"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"

echo "tamper-audit summary: chains=tenant-scoped append=immutable hash=sha256 checkpoints=daily-or-10000 signature=ed25519 replay=exact concurrency=cas adapters=sqlite+postgres denials=34 failures=0"
