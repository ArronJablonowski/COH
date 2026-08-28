#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

contract_root="contracts/splunk-parser/v1"
audit="${contract_root}/fixtures/redacted-audit.json"
registry="${contract_root}/fixtures/command-registry.json"
denials="${contract_root}/fixtures/denial-corpus.json"
revocation="${contract_root}/fixtures/revocation.json"
manifest="internal/connector/splunk/testdata/parser-fixture-manifest.json"
trace="docs/evidence/CYB-99-adversarial-trace.json"

shasum -a 256 -c docs/evidence/CYB-99-artifacts.sha256 >/dev/null
jq -e '.allowed_commands == ["fields","head","search","sort","stats","table"] and (.prohibited_commands | length == 36) and .backticks_allowed == false and .macros_allowed == false and .lookups_allowed == false and .custom_allowed == false' "${registry}" >/dev/null
jq -e '(.cases | length) == 24' "${denials}" >/dev/null
jq -e '.native_text_exposed == false and .literal_exposed == false and .credential_exposed == false and .vendor_body_exposed == false and .sid_exposed == false' "${audit}" >/dev/null
jq -e '.execution_permitted == false and .reason_code == "authorization_revoked"' "${revocation}" >/dev/null
jq -e '.endpoint == "/services/search/v2/parser" and .sensitive_values == "none" and ([.fixtures[].minor] == ["9.4","10.0"])' "${manifest}" >/dev/null
jq -e '.issue == "CYB-99" and .outcome == "passed" and .coverage.allowed_commands == 6 and .coverage.classified_prohibited_commands == 36 and .coverage.denial_corpus_cases == 24 and .native_text_exposed == false and .credential_exposed == false and .vendor_body_exposed == false and .sid_exposed == false' "${trace}" >/dev/null

go test -count=10 ./internal/connector/splunk ./internal/connector/splunkparser
go test -race ./internal/connector/splunk ./internal/connector/splunkparser
go vet ./internal/connector/splunk ./internal/connector/splunkparser
"${GOBIN}/staticcheck" ./internal/connector/splunk ./internal/connector/splunkparser
"${repo_root}/scripts/run_architecture_gate.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-splunk-parser-policy: passed"
