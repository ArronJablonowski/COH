#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

schema="contracts/elastic-esql/v1/elastic-esql-definition.schema.json"
definition="contracts/elastic-esql/v1/fixtures/definition.valid.json"
denials="contracts/elastic-esql/v1/fixtures/denial-corpus.json"
error_trace="contracts/elastic-esql/v1/fixtures/redacted-error.trace.json"
vendor_manifest="internal/connector/elastic/testdata/elastic-8.19/esql-fixture-manifest.json"

shasum -a 256 -c docs/evidence/CYB-91-artifacts.sha256 >/dev/null

jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.elastic-esql-definition/v1"
  and ((.properties | keys | any(. == "credential" or . == "endpoint" or . == "headers" or . == "body" or . == "script")) | not)
' "$schema" >/dev/null
jq -e '
  .schema_version == "coh.elastic-esql-definition/v1"
  and .hard_maximum_rows > 0
  and (.resources | length) == 1
  and (.fields | all(.vendor_name != "*"))
' "$definition" >/dev/null
jq -e '
  .schema_version == "coh.elastic-esql-denials/v1"
  and (.cases | length) >= 9
  and (.cases | all(.reason != "" and .covered_by != ""))
' "$denials" >/dev/null
jq -e '
  .schema_version == "coh.elastic-esql-redacted-error/v1"
  and .credential_exposed == false
  and .native_text_exposed == false
  and .parameter_exposed == false
  and .result_row_exposed == false
  and .vendor_body_exposed == false
  and ((has("credential") or has("native_text") or has("parameters") or has("rows") or has("vendor_body")) | not)
' "$error_trace" >/dev/null
jq -e '
  .schema_version == "coh.elastic-esql-vendor-fixture/v1"
  and .vendor == "elastic"
  and .sensitive_values == "none"
' "$vendor_manifest" >/dev/null

go test -count=10 ./internal/connector/elasticesql ./internal/connector/elastic
go test -race ./internal/connector/elasticesql ./internal/connector/elastic
go vet ./internal/connector/elasticesql ./internal/connector/elastic
"${GOBIN}/staticcheck" ./internal/connector/elasticesql ./internal/connector/elastic
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-elastic-esql: passed"
