#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="${root}/contracts/schema-cache/v1"
schema="${contract}/schema-cache-entry.schema.json"
fixture="${contract}/fixtures/entry-identity.canonical.json"

for required in "${schema}" "${fixture}" "${contract}/README.md" \
  "${root}/docs/design/bounded-schema-cache.md"; do
  [[ -s "${required}" ]] || { echo "missing schema-cache artifact: ${required}" >&2; exit 1; }
done

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object" and .additionalProperties == false
  and (.required | length) == 14
  and .properties.schema_version.const == "coh.schema-cache-entry/v1"
  and .properties.contract_version.const == "1.0.0"
  and .properties.connector_schema_version.const == "coh.query-schema/v1"
' "${schema}" >/dev/null

jq -e '
  .schema_version == "coh.schema-cache-entry/v1"
  and .contract_version == "1.0.0"
  and .connector_schema_version == "coh.query-schema/v1"
  and (.resource_digest | startswith("sha256:"))
  and (.capability_digest | startswith("sha256:"))
  and (.page_digest | startswith("sha256:"))
  and (.provenance_digest | startswith("sha256:"))
  and ((has("case_id") or has("actor_id") or has("query") or has("credential") or has("vendor_error")) | not)
' "${fixture}" >/dev/null

go test -count=10 ./internal/domain/schemacache
go test -race ./internal/domain/schemacache
go vet ./internal/domain/schemacache
"${GOBIN}/staticcheck" ./internal/domain/schemacache
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_file_sizes.sh"

echo "verify-schema-cache: passed"
