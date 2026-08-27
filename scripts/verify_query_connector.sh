#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="${root}/contracts/query/v1"
schema="${contract}/query-connector.schema.json"
fixture="${contract}/fixtures/valid/query.canonical.json"
denials="${contract}/fixtures/denial-corpus.json"

for required in "${schema}" "${fixture}" "${denials}" \
  "${contract}/README.md" "${contract}/compatibility-matrix.md"; do
  [[ -s "${required}" ]] || { echo "missing query contract artifact: ${required}" >&2; exit 1; }
done

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 8
  and (["capability","query","validation","execution","schema_page","poll","page","cancellation"]
    | all(. as $name | ($schema["$defs"][$name].type == "object"
      and $schema["$defs"][$name].additionalProperties == false
      and ($schema["$defs"][$name].required | length) > 0)))
' --argjson schema "$(jq -c . "${schema}")" "${schema}" >/dev/null

jq -e '
  .schema_version == "coh.query-connector-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 10
  and ([.cases[].name] | unique | length) == 10
' "${denials}" >/dev/null

jq -e '
  .schema_version == "coh.query-request/v1"
  and .contract_version == "1.0.0"
  and (.scope.resource_ids | length) > 0
  and (.authority.authorization_digest | startswith("sha256:"))
  and (.limits | to_entries | all(.value > 0))
' "${fixture}" >/dev/null

go test -count=10 ./internal/domain/queryconnector
go test -race ./internal/domain/queryconnector
go vet ./internal/domain/queryconnector
"${GOBIN}/staticcheck" ./internal/domain/queryconnector
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_file_sizes.sh"

echo "verify-query-connector: passed"
