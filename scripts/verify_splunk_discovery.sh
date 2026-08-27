#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

config_schema="contracts/splunk-discovery/v1/splunk-discovery-config.schema.json"
capability="contracts/splunk-discovery/v1/fixtures/capability.snapshot.json"
qualification="contracts/splunk-discovery/v1/fixtures/qualification.snapshot.json"
error_trace="contracts/splunk-discovery/v1/fixtures/redacted-error.trace.json"
vendor_manifest="internal/connector/splunk/testdata/splunk-10.0/fixture-manifest.json"

shasum -a 256 -c docs/evidence/CYB-95-artifacts.sha256 >/dev/null
jq -e '.additionalProperties == false and .properties.deployment.const == "enterprise"' "$config_schema" >/dev/null
jq -e '.schema_version == "coh.query-capability/v1" and .features.read_only == true and .features.schema_discovery == true and .query_languages == ["spl"]' "$capability" >/dev/null
jq -e '.schema_version == "coh.splunk-qualification/v1" and .product_type == "enterprise" and (.digest | startswith("sha256:"))' "$qualification" >/dev/null
jq -e '.credential_exposed == false and .bearer_exposed == false and .sid_exposed == false and .native_text_exposed == false and .result_row_exposed == false and .vendor_body_exposed == false' "$error_trace" >/dev/null
jq -e '.schema_version == "coh.splunk-vendor-fixture/v1" and .vendor == "splunk" and .sensitive_values == "none" and (.records | length == 6)' "$vendor_manifest" >/dev/null

go test -count=10 ./internal/connector/splunk
go test -race ./internal/connector/splunk
go vet ./internal/connector/splunk
"${GOBIN}/staticcheck" ./internal/connector/splunk
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-splunk-discovery: passed"
