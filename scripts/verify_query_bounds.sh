#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="${root}/contracts/query-bounds/v1"
schema="${contract}/query-bound-decision.schema.json"
fixture="${contract}/fixtures/allowed-decision.canonical.json"
denials="${contract}/fixtures/denial-corpus.json"

for required in "${schema}" "${fixture}" "${denials}" "${contract}/README.md" \
  "${root}/docs/design/mandatory-utc-query-bounds.md"; do
  [[ -s "${required}" ]] || { echo "missing query-bounds artifact: ${required}" >&2; exit 1; }
done

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object" and .additionalProperties == false
  and (.required | length) == 30
  and .properties.schema_version.const == "coh.query-bound-decision/v1"
  and .properties.contract_version.const == "1.0.0"
' "${schema}" >/dev/null

jq -e '
  .schema_version == "coh.query-bound-decision/v1"
  and .contract_version == "1.0.0"
  and .outcome == "allowed"
  and .reason_code == "bounds_satisfied"
  and (.decision_digest | startswith("sha256:"))
  and ((has("native_text") or has("rows") or has("credential") or has("vendor_error")) | not)
' "${fixture}" >/dev/null

jq -e '
  .schema_version == "coh.query-bound-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 24
  and ([.cases[].reason] | unique | length) == 24
  and ([.cases[].class] | index("revoked") != null)
' "${denials}" >/dev/null

go test -count=10 ./internal/domain/querybounds
go test -race ./internal/domain/querybounds
go vet ./internal/domain/querybounds
"${GOBIN}/staticcheck" ./internal/domain/querybounds
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_file_sizes.sh"

echo "verify-query-bounds: passed"
