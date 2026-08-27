#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="${root}/contracts/query-runtime/v1"
schema="${contract}/query-runtime.schema.json"
fixture="${contract}/fixtures/session.canonical.json"

for required in "${schema}" "${fixture}" "${contract}/README.md" \
  "${root}/docs/design/query-runtime-broker.md"; do
  [[ -s "${required}" ]] || { echo "missing query-runtime artifact: ${required}" >&2; exit 1; }
done

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 3
  and (."$defs".session.additionalProperties == false)
  and (."$defs".slice_plan.additionalProperties == false)
  and (."$defs".rate_reservation.additionalProperties == false)
  and (."$defs".session.properties.schema_version.const == "coh.query-runtime-session/v1")
  and (."$defs".slice_plan.properties.schema_version.const == "coh.query-slice-plan/v1")
  and (."$defs".rate_reservation.properties.schema_version.const == "coh.query-rate-reservation/v1")
' "${schema}" >/dev/null

jq -e '
  .schema_version == "coh.query-runtime-session/v1"
  and .contract_version == "1.0.0"
  and .status == "running" and .mode == "interactive"
  and (.session_digest | startswith("sha256:"))
  and ((has("native_text") or has("rows") or has("credential") or has("url") or has("vendor_error")) | not)
' "${fixture}" >/dev/null

go test -count=10 ./internal/domain/queryruntime
go test -race ./internal/domain/queryruntime
go vet ./internal/domain/queryruntime
"${GOBIN}/staticcheck" ./internal/domain/queryruntime
"${root}/scripts/run_architecture_gate.sh"
"${root}/scripts/check_file_sizes.sh"

echo "verify-query-runtime: passed"
