#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

schema="contracts/security-onion/v1/security-onion-config.schema.json"
oql="contracts/security-onion/v1/security-onion-oql.schema.json"
config="contracts/security-onion/v1/fixtures/config.valid.json"
capability="contracts/security-onion/v1/fixtures/capability.snapshot.json"
denials="contracts/security-onion/v1/fixtures/denial-corpus.json"
trace="contracts/security-onion/v1/fixtures/redacted-error.trace.json"
manifest="internal/connector/securityonion/testdata/security-onion-3.x/fixture-manifest.json"

shasum -a 256 -c docs/evidence/CYB-90-artifacts.sha256 >/dev/null
jq -e '.additionalProperties == false and .properties.permissions.const == ["events/read"] and .properties.endpoint.pattern != ""' "$schema" >/dev/null
jq -e '.additionalProperties == false and .properties.mode.enum == ["events", "metrics"] and ([.. | strings | select(. == "script" or . == "pipeline")] | length) == 0' "$oql" >/dev/null
jq -e '.schema_version == "coh.security-onion-config/v1" and .permissions == ["events/read"] and (.endpoint | startswith("https://"))' "$config" >/dev/null
jq -e '.schema_version == "coh.query-capability/v1" and .features.read_only and .features.polling and (.features.paging | not) and .query_languages == ["security-onion-oql"]' "$capability" >/dev/null
jq -e '.schema_version == "coh.security-onion-denials/v1" and (.cases | length) >= 12 and (.cases | all(.reason != "" and .covered_by != ""))' "$denials" >/dev/null
jq -e '.credential_exposed == false and .bearer_exposed == false and .native_text_exposed == false and .literal_exposed == false and .result_row_exposed == false and .vendor_body_exposed == false' "$trace" >/dev/null
jq -e '.schema_version == "coh.security-onion-vendor-fixture/v1" and .vendor == "security-onion" and .sensitive_values == "none" and (.records | length) == 5' "$manifest" >/dev/null

go test -count=10 ./internal/connector/securityonion
go test -race ./internal/connector/securityonion
go vet ./internal/connector/securityonion
"${GOBIN}/staticcheck" ./internal/connector/securityonion
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-security-onion: passed"
