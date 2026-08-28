#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

config="contracts/sentinel-discovery/v1/fixtures/config.valid.json"
metadata="contracts/sentinel-discovery/v1/fixtures/metadata.snapshot.json"
qualification="contracts/sentinel-discovery/v1/fixtures/qualification.snapshot.json"
denials="contracts/sentinel-discovery/v1/fixtures/denial-corpus.json"
redacted="contracts/sentinel-discovery/v1/fixtures/redacted-error.trace.json"
manifest="internal/connector/sentinel/testdata/azure-monitor-v1/fixture-manifest.json"
capability="docs/evidence/CYB-97-capability.snapshot.json"
trace="docs/evidence/CYB-97-adversarial-trace.json"

shasum -a 256 -c docs/evidence/CYB-97-artifacts.sha256 >/dev/null
jq -e '.deployment == "azure_public" and .endpoint == "https://api.loganalytics.azure.com" and .api_version == "v1" and .token_audience == "https://api.loganalytics.io/.default" and (.resources | length) == 2 and (.fields | length) == 3' "${config}" >/dev/null
jq -e '.api_version == "v1" and (.tables | length) == 2 and (.digest | startswith("sha256:"))' "${metadata}" >/dev/null
jq -e '.api_version == "v1" and (.receipts | length) == 1 and (.digest | startswith("sha256:"))' "${qualification}" >/dev/null
jq -e '(.cases | length) == 14 and ([.cases[].covered_by] | all(startswith("Test")))' "${denials}" >/dev/null
jq -e '.credential_exposed == false and .bearer_exposed == false and .tenant_secret_exposed == false and .workspace_url_exposed == false and .native_text_exposed == false and .result_row_exposed == false and .vendor_body_exposed == false' "${redacted}" >/dev/null
jq -e '.api_version == "v1" and .oauth_audience == "https://api.loganalytics.io/.default" and .sensitive_values == "none" and (.records | length) == 4' "${manifest}" >/dev/null
jq -e '.features.read_only and .features.schema_discovery and .features.validation and (.features.polling | not) and (.features.paging | not) and (.features.cancellation | not) and (.features.statistics | not)' "${capability}" >/dev/null
jq -e '.issue == "CYB-97" and .stable_key == "COH-E14-04" and .requirements == ["FR-045","FR-046","SEC-013"] and .outcome == "passed" and .coverage.typed_vendor_operations == 1 and .coverage.denial_corpus_cases == 14 and .coverage.recorded_vendor_cases == 4 and .credential_exposed == false and .bearer_exposed == false and .tenant_secret_exposed == false and .workspace_url_exposed == false and .native_text_exposed == false and .result_row_exposed == false and .vendor_body_exposed == false and .hidden_partial_success == false and (.blocking_findings | length) == 0' "${trace}" >/dev/null

go test -count=3 ./internal/connector/sentinel ./internal/domain/queryconnector
go test -race ./internal/connector/sentinel ./internal/domain/queryconnector
go vet ./internal/connector/sentinel ./internal/domain/queryconnector
"${GOBIN}/staticcheck" ./internal/connector/sentinel ./internal/domain/queryconnector
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-sentinel-discovery: passed"
