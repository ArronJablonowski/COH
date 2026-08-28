#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

manifest="docs/evidence/CYB-98-helper-manifest.json"
sbom="docs/evidence/CYB-98-helper-sbom.cdx.json"
provenance="docs/evidence/CYB-98-helper-provenance.json"
trace="docs/evidence/CYB-98-adversarial-trace.json"

/usr/bin/shasum -a 256 -c docs/evidence/CYB-98-artifacts.sha256 >/dev/null
/usr/bin/jq -e '.issue == "CYB-98" and .outcome == "passed" and .coverage.accepted_kql_cases == 8 and .coverage.semantic_denial_cases == 20 and .coverage.total_denial_corpus_cases == 38 and .coverage.hostile_metadata_cases == 8 and .coverage.concurrent_validators == 8 and (.blocking_findings | length) == 0 and .credential_exposed == false' "${trace}" >/dev/null
/usr/bin/jq -e '.tool_name == "coh-kusto-validator" and .network_policy == "none" and .credential_classes == ["none"] and (.artifacts | length) == 3 and .qualification.nuget_signatures_verified and .qualification.signed_registry_path_verified and .qualification.reproducible and .qualification.network_denial_verified' "${manifest}" >/dev/null
/usr/bin/jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.6" and ([.components[].name] | contains(["Microsoft.Azure.Kusto.Language","Microsoft.NET.ILLink.Tasks",".NET Runtime"]))' "${sbom}" >/dev/null
/usr/bin/jq -e '.issue == "CYB-98" and .reproducible and .revision_independent_helper_identity and .network_during_helper_execution == "none" and (.subjects | length) == 3' "${provenance}" >/dev/null
/usr/bin/jq -e '.outcome == "accepted" and .query_text_exposed == false and .literal_exposed == false and .schema_name_exposed == false and .workspace_exposed == false and .credential_exposed == false and .executable_path_exposed == false and .stderr_exposed == false' contracts/kusto-validator/v1/fixtures/audit-proof.json >/dev/null
/usr/bin/jq -e '.outcome == "accepted" and .actor_id != "" and .scope_digest != "" and .audit_reservation_digest != ""' contracts/kusto-validator/v1/fixtures/policy-decision.accepted.json >/dev/null
/usr/bin/jq -e '.validation_permitted == false and .execution_permitted == false and .reason_code == "helper_revoked"' contracts/kusto-validator/v1/fixtures/revocation.json >/dev/null
/usr/bin/jq -e '(.cases | length) == 38' contracts/kusto-validator/v1/fixtures/denial-corpus.json >/dev/null

"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/connector/kustovalidator
"${COH_GO_ROOT}/bin/go" test -race ./internal/connector/kustovalidator
"${COH_GO_ROOT}/bin/go" vet ./internal/connector/kustovalidator
"${GOBIN}/staticcheck" ./internal/connector/kustovalidator
"${repo_root}/scripts/check_go_architecture.sh"
"${repo_root}/scripts/check_file_sizes.sh"

echo "verify-kusto-validator-evidence: passed"
