#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

schema="contracts/elastic-discovery/v1/elastic-discovery-config.schema.json"
capability="contracts/elastic-discovery/v1/fixtures/capability.snapshot.json"
error_trace="contracts/elastic-discovery/v1/fixtures/redacted-error.trace.json"
vendor_manifest="internal/connector/elastic/testdata/elastic-8.19/fixture-manifest.json"

jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.elastic-discovery-config/v1"
  and ((.properties | keys | any(. == "credential" or . == "api_key" or . == "headers" or . == "passthrough")) | not)
' "$schema" >/dev/null
jq -e '
  .schema_version == "coh.query-capability/v1"
  and .features.read_only == true
  and .features.schema_discovery == true
  and (.source_identity_digest | startswith("sha256:"))
' "$capability" >/dev/null
jq -e '
  .schema_version == "coh.elastic-redacted-error/v1"
  and .credential_exposed == false
  and .vendor_body_exposed == false
  and ((has("credential") or has("api_key") or has("authorization") or has("vendor_body")) | not)
' "$error_trace" >/dev/null
jq -e '
  .schema_version == "coh.elastic-vendor-fixture/v1"
  and .vendor == "elastic"
  and .sensitive_values == "none"
  and (.records | length == 4)
' "$vendor_manifest" >/dev/null

go test -count=10 ./internal/connector/elastic
go test -race ./internal/connector/elastic
go vet ./internal/connector/elastic
"${GOBIN}/staticcheck" ./internal/connector/elastic
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-elastic-discovery: passed"
