#!/bin/bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_binary="${COH_GO_BIN:?COH_GO_BIN is required}"
first="$(mktemp -d "${GOTMPDIR}/architecture-catalog-first.XXXXXX")"
second="$(mktemp -d "${GOTMPDIR}/architecture-catalog-second.XXXXXX")"
binary="$(mktemp "${GOTMPDIR}/architecturecatalog.XXXXXX")"
cleanup() { rm -rf "${first}" "${second}"; rm -f "${binary}"; }
trap cleanup EXIT

cd "${root}"
"${go_binary}" build -trimpath -o "${binary}" ./cmd/architecturecatalog
chmod 0500 "${binary}"
"${binary}" -root "${root}" -go "${go_binary}" -output "${first}"
"${binary}" -root "${root}" -go "${go_binary}" -output "${second}"

types=(application_entrypoints capability_graph configuration event_routes model_surface_events module_dependencies)
for type in "${types[@]}"; do
  generated="${first}/${type}.json"
  repeated="${second}/${type}.json"
  checked="${root}/docs/architecture/catalogs/${type}.json"
  cmp -s "${generated}" "${repeated}" || { echo "Architecture catalog is nondeterministic: ${type}" >&2; exit 2; }
  cmp -s "${generated}" "${checked}" || { echo "Architecture catalog is stale: ${type}" >&2; exit 2; }
  bytes="$(wc -c < "${checked}" | tr -d ' ')"
  (( bytes <= 8388608 )) || { echo "Architecture catalog exceeds publication bound: ${type}" >&2; exit 2; }
  jq -e --arg type "${type}" '
    .schema_version == "coh.architecture-catalog/v1" and
    .contract_version == "1.0.0" and .catalog_type == $type and
    .requirements == ["COH-E25-05","EVAL-004","EVAL-029","NFR-019","NFR-026"] and
    (.sources | length > 0) and (.records | length <= 131072) and
    (all(.sources[]; (.path | startswith("/") | not) and (.digest | test("^sha256:[0-9a-f]{64}$")))) and
    (.catalog_digest | test("^sha256:[0-9a-f]{64}$"))
  ' "${checked}" >/dev/null
done

"${go_binary}" test -count=1 ./internal/helper/architecturecatalog \
  -run 'TestCapabilityMutationsDenyOrphansAndCycles|TestModelSurfaceMutationRequiresProjection|TestSourcePolicyDeniesDynamicLoaderAndAlternateLaunch|TestPublicationRedactionRejectsSensitiveAttributes'
"${root}/scripts/check_markdown_links.sh" \
  "${root}/contracts/architecture-catalog/v1/README.md" \
  "${root}/docs/design/generated-architecture-catalogs.md" \
  "${root}/docs/design/deepseek-harness-adoption.md"

echo "architecture-catalog summary: catalogs=6 deterministic=true stale=false schema=closed redacted=true links=valid size_bounded=true mutations=orphan+cycle+alternate-launch+dynamic-loader+model-surface failures=0"
