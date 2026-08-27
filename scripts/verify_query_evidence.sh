#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

schema="contracts/query-evidence/v1/query-evidence-record.schema.json"
fixture="contracts/query-evidence/v1/fixtures/record.canonical.json"

jq -e '.additionalProperties == false and .properties.schema_version.const == "coh.query-evidence-record/v1"' "$schema" >/dev/null
jq -e '
  .schema_version == "coh.query-evidence-record/v1"
  and .contract_version == "1.0.0"
  and .event == "started"
  and .completeness == "running"
  and ((has("native_text") or has("rows") or has("credential") or has("key_reference") or has("locator")) | not)
' "$fixture" >/dev/null

go test -count=10 ./internal/workflow/queryevidence
go test -race ./internal/workflow/queryevidence
go vet ./internal/workflow/queryevidence
"${GOBIN}/staticcheck" ./internal/workflow/queryevidence
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-query-evidence: passed"
