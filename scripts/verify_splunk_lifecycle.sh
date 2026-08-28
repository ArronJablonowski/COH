#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

policy="contracts/splunk-lifecycle/v1/fixtures/lifecycle-policy.json"
denials="contracts/splunk-lifecycle/v1/fixtures/denial-corpus.json"
redacted="contracts/splunk-lifecycle/v1/fixtures/redacted-error.trace.json"
manifest="internal/connector/splunk/testdata/lifecycle-fixture-manifest.json"
capability="docs/evidence/CYB-96-capability.snapshot.json"
trace="docs/evidence/CYB-96-adversarial-trace.json"

shasum -a 256 -c docs/evidence/CYB-96-artifacts.sha256 >/dev/null
jq -e '.execution_mode == "normal" and .allow_previews == false and .status_buckets == 0 and .maximum_page_rows == 1000 and .minimum_poll_interval_millis == 500 and .cancellation_wait_millis == 5000 and (.operations | length) == 4 and (.allowed_states | length) == 11' "${policy}" >/dev/null
jq -e '(.cases | length) == 13' "${denials}" >/dev/null
jq -e '.credential_exposed == false and .bearer_exposed == false and .sid_exposed == false and .native_text_exposed == false and .result_row_exposed == false and .vendor_body_exposed == false' "${redacted}" >/dev/null
jq -e '.sensitive_values == "none" and ([.fixtures[].minor] == ["9.4","10.0"]) and (.records | length) == 4' "${manifest}" >/dev/null
jq -e '.features.read_only and .features.schema_discovery and .features.validation and .features.polling and .features.paging and .features.cancellation and .features.statistics' "${capability}" >/dev/null
jq -e '.issue == "CYB-96" and .stable_key == "COH-E14-03" and .requirements == ["FR-051","FR-054"] and .outcome == "passed" and .coverage.typed_operations == 4 and .coverage.denial_corpus_cases == 13 and .native_text_exposed == false and .credential_exposed == false and .bearer_exposed == false and .sid_exposed == false and .result_row_exposed == false and .vendor_body_exposed == false and .hidden_partial_success == false and (.blocking_findings | length) == 0' "${trace}" >/dev/null

go test -count=3 ./internal/connector/splunk ./internal/connector/splunkparser ./internal/domain/queryconnector
go test -race ./internal/connector/splunk ./internal/connector/splunkparser ./internal/domain/queryconnector
go vet ./internal/connector/splunk ./internal/connector/splunkparser ./internal/domain/queryconnector
"${GOBIN}/staticcheck" ./internal/connector/splunk ./internal/connector/splunkparser ./internal/domain/queryconnector
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-splunk-lifecycle: passed"
