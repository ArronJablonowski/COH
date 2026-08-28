#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/model-surface/v1"

schemas=(
  "event-vocabulary.schema.json:coh.model-surface-event-vocabulary/v1"
  "model-surface-payload.schema.json:coh.model-surface-payload/v1"
  "model-surface-source.schema.json:coh.model-surface-source/v1"
  "model-surface-projection.schema.json:coh.model-surface-projection/v1"
  "inference-surface-binding.schema.json:coh.inference-surface-binding/v1"
  "model-surface-stream.schema.json:coh.model-surface-stream/v1"
  "compaction-replacement.schema.json:coh.model-surface-compaction-replacement/v1"
  "model-surface-transition.schema.json:coh.model-surface-transition/v1"
)

for entry in "${schemas[@]}"; do
  schema=${entry%%:*}
  version=${entry#*:}
  path="${contract}/${schema}"
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: model-surface schema is missing or linked: ${path}" >&2
    exit 2
  }
  /usr/bin/jq -e --arg version "${version}" '
    .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    and .properties.schema_version.const == $version
    and .properties.contract_version.const == "1.0.0"
    and .additionalProperties == false
    and (.required | index("schema_version") != null)
    and (.required | index("contract_version") != null)
  ' "${path}" >/dev/null
done

for path in "${contract}/README.md" "${contract}/compatibility-matrix.md" \
  "${root}/docs/design/durable-model-surface-provenance.md" \
  "${root}/internal/domain/modelsurface/types.go" \
  "${root}/internal/domain/modelsurface/decode.go" \
  "${root}/internal/domain/modelsurface/canonical.go" \
  "${root}/internal/domain/modelsurface/validate_records.go" \
  "${root}/internal/domain/modelsurface/resolution.go" \
  "${root}/internal/domain/modelsurface/projection.go" \
  "${root}/internal/domain/modelsurface/admission.go" \
  "${root}/internal/domain/modelsurface/stream_runtime.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: required model-surface artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

fixtures=(
  "event-vocabulary.valid.json:coh.model-surface-event-vocabulary/v1"
  "payload.valid.json:coh.model-surface-payload/v1"
  "source.valid.json:coh.model-surface-source/v1"
  "projection.valid.json:coh.model-surface-projection/v1"
  "binding.valid.json:coh.inference-surface-binding/v1"
  "stream.valid.json:coh.model-surface-stream/v1"
  "compaction.valid.json:coh.model-surface-compaction-replacement/v1"
  "transition.valid.json:coh.model-surface-transition/v1"
)
for entry in "${fixtures[@]}"; do
  fixture=${entry%%:*}
  version=${entry#*:}
  /usr/bin/jq -e --arg version "${version}" '
    .schema_version == $version and .contract_version == "1.0.0"
  ' "${contract}/fixtures/${fixture}" >/dev/null
done
/usr/bin/jq -e '
  .schema_version == "coh.model-surface-denial-corpus/v1"
  and .contract_version == "1.0.0"
  and (.cases | length == 13)
  and ([.cases[].name] | unique | length == 13)
' "${contract}/fixtures/denial-corpus.json" >/dev/null

/usr/bin/jq -e '
  (.properties.definitions.items["$ref"] == "#/$defs/event_definition")
  and (.["$defs"].event_definition.properties.event_class.enum == ["live_coordination", "log_only", "model_surface"])
  and (.["$defs"].event_definition.properties.persistence.enum == ["durable", "ephemeral"])
  and (.["$defs"].event_definition.properties.projection_rule.enum | index("none") != null)
' "${contract}/event-vocabulary.schema.json" >/dev/null

/usr/bin/jq -e '
  .properties.event_class.const == "model_surface"
  and .properties.immutable.const == true
  and (.required | index("record_digest") != null)
  and (.required | index("content") != null)
  and (.required | index("instruction_disposition") != null)
  and (.["$defs"].scope.required == ["organization_id", "tenant_id", "case_id", "task_id"])
' "${contract}/model-surface-source.schema.json" >/dev/null

/usr/bin/jq -e '
  .properties.projection_version.const == "1.0.0"
  and (.required | index("ordered_source_record_ids") != null)
  and (.required | index("artifact_digests") != null)
  and (.required | index("composition_digest") != null)
  and (.required | index("surface_digest") != null)
  and (.required | index("projection_digest") != null)
' "${contract}/model-surface-projection.schema.json" >/dev/null

/usr/bin/jq -e '
  .properties.projection_version.const == "1.0.0"
  and (.required | index("request_id") != null)
  and (.required | index("attempt_id") != null)
  and (.required | index("ordered_source_record_ids") != null)
  and (.required | index("artifact_digests") != null)
  and (.required | index("surface_digest") != null)
  and (.required | index("binding_digest") != null)
  and (.required | index("audit_reservation_digest") != null)
' "${contract}/inference-surface-binding.schema.json" >/dev/null

/usr/bin/jq -e '
  (.properties.outcome.enum == ["pending", "succeeded", "empty", "interrupted", "canceled", "timeout", "failed", "uncertain"])
  and (.required | index("source_record_ids") != null)
  and (.required | index("assembled_digest") != null)
  and (.required | index("event_digest") != null)
' "${contract}/model-surface-stream.schema.json" >/dev/null

/usr/bin/jq -e '
  (.["$defs"].covered_source.required | index("evidence_ids") != null)
  and (.["$defs"].covered_source.required | index("normalized_time") != null)
  and (.["$defs"].covered_source.required | index("order_confidence") != null)
  and (.["$defs"].covered_source.required | index("result_state") != null)
  and (.["$defs"].covered_source.required | index("completeness") != null)
  and (.["$defs"].covered_source.required | index("uncertainty") != null)
  and (.required | index("coverage_digest") != null)
' "${contract}/compaction-replacement.schema.json" >/dev/null

/usr/bin/jq -e '
  .properties.phase.enum == ["prepared", "verified", "dispatched", "streaming", "terminal"]
  and (.required | index("provider_attempt") != null)
  and (.required | index("stream_cursor") != null)
  and (.required | index("previous_transition_digest") != null)
  and (.required | index("transition_digest") != null)
' "${contract}/model-surface-transition.schema.json" >/dev/null

for forbidden in credential_value secret_value raw_evidence prompt_content private_path executable_payload callback function_pointer authority_object mutable_url; do
  if /usr/bin/jq -e --arg field "${forbidden}" '
    [paths(objects) as $path | ($path[-1] | tostring | ascii_downcase) | select(contains($field))] | length > 0
  ' "${contract}"/*.schema.json >/dev/null; then
    echo "error: model-surface schema contains forbidden content or authority field: ${forbidden}" >&2
    exit 2
  fi
done

/usr/bin/grep -Fq 'COH-E25-04 / CYB-186' "${contract}/README.md"
for requirement in FR-014 FR-027 FR-038 FR-044 SEC-011 SEC-015 SEC-016 SEC-020; do
  /usr/bin/grep -Fq "${requirement}" "${contract}/README.md"
done
for phrase in 'model_surface' 'log_only' 'live_coordination' 'untrusted_data_only' \
  'Provider fallback' 'Source-covering compaction'; do
  /usr/bin/grep -Fq "${phrase}" "${contract}/README.md"
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"
cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/domain/modelsurface

"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" \
  "${contract}/compatibility-matrix.md" \
  "${root}/docs/design/durable-model-surface-provenance.md"
/usr/bin/git -C "${root}" diff --check

echo "model-surface contract summary: issue=CYB-186 contract=v1 events=model+log+live sources=durable projection=deterministic binding=inference stream=lineage compaction=source-covering recovery=durable failures=0"
