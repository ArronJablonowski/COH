#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

schema="contracts/elastic-querydsl/v1/elastic-querydsl-definition.schema.json"
definition="contracts/elastic-querydsl/v1/fixtures/definition.valid.json"
capability="contracts/elastic-querydsl/v1/fixtures/capability.snapshot.json"
denials="contracts/elastic-querydsl/v1/fixtures/denial-corpus.json"
error_trace="contracts/elastic-querydsl/v1/fixtures/redacted-error.trace.json"
vendor_manifest="internal/connector/elastic/testdata/elastic-8.19/querydsl-fixture-manifest.json"

shasum -a 256 -c docs/evidence/CYB-94-artifacts.sha256 >/dev/null

jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.elastic-querydsl-definition/v1"
  and ((.properties | keys | any(. == "credential" or . == "endpoint" or . == "headers" or . == "body" or . == "script" or . == "runtime_mappings")) | not)
' "$schema" >/dev/null
jq -e '
  .schema_version == "coh.elastic-querydsl-definition/v1"
  and .hard_maximum_rows > 0
  and .hard_maximum_pages > 0
  and .hard_page_rows > 0
  and (.resources | length) == 1
  and (.fields | all(.vendor_name != "*"))
  and (.stable_sort | length) >= 2
' "$definition" >/dev/null
jq -e '
  .schema_version == "coh.query-capability/v1"
  and .features.read_only == true
  and .features.validation == true
  and .features.polling == true
  and .features.paging == true
  and .features.cancellation == true
  and .query_languages == ["elastic-query-dsl", "esql"]
' "$capability" >/dev/null
jq -e '
  .schema_version == "coh.elastic-querydsl-denials/v1"
  and (.cases | length) >= 12
  and (.cases | all(.reason != "" and .class != "" and .covered_by != ""))
' "$denials" >/dev/null
jq -e '
  .schema_version == "coh.elastic-querydsl-redacted-error/v1"
  and .credential_exposed == false
  and .pit_id_exposed == false
  and .native_text_exposed == false
  and .literal_exposed == false
  and .result_row_exposed == false
  and .vendor_body_exposed == false
  and ((has("credential") or has("pit_id") or has("native_text") or has("literal") or has("rows") or has("vendor_body")) | not)
' "$error_trace" >/dev/null
jq -e '
  .schema_version == "coh.elastic-querydsl-vendor-fixture/v1"
  and .vendor == "elastic"
  and .sensitive_values == "none"
  and (.records | length) == 4
' "$vendor_manifest" >/dev/null

go test -count=10 ./internal/connector/elasticquerydsl ./internal/connector/elastic
go test -race ./internal/connector/elasticquerydsl ./internal/connector/elastic
go vet ./internal/connector/elasticquerydsl ./internal/connector/elastic
"${GOBIN}/staticcheck" ./internal/connector/elasticquerydsl ./internal/connector/elastic
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-elastic-querydsl: passed"
