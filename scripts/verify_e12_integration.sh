#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

for verifier in verify_query_connector.sh verify_schema_cache.sh verify_query_bounds.sh verify_query_runtime.sh verify_query_evidence.sh; do
  "${root}/scripts/${verifier}"
done

go test -count=10 -run '^TestE12' ./internal/workflow/queryevidence
go test -race -run '^TestE12' ./internal/workflow/queryevidence
go vet ./internal/domain/queryconnector ./internal/domain/schemacache ./internal/domain/querybounds ./internal/domain/queryruntime ./internal/workflow/queryevidence
"${GOBIN}/staticcheck" ./internal/domain/queryconnector ./internal/domain/schemacache ./internal/domain/querybounds ./internal/domain/queryruntime ./internal/workflow/queryevidence
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_file_sizes.sh"

echo "verify-e12-integration: passed"
