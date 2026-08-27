#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/normalization/v1"
schema="${contract}/normalized-event-envelope.schema.json"
targets="${contract}/compatibility-targets.json"
denials="${contract}/fixtures/denial-corpus.json"

for path in \
  "${contract}/README.md" \
  "${contract}/compatibility-matrix.md" \
  "${schema}" \
  "${targets}" \
  "${denials}" \
  "${contract}/fixtures/valid/event.canonical.json" \
  "${contract}/fixtures/valid/dataset-event.canonical.json" \
  "${root}/docs/design/normalized-event-envelope.md" \
  "${root}/internal/domain/normalizedevent"; do
  [[ -e "${path}" ]] || {
    echo "error: normalized-event input is missing: ${path}" >&2
    exit 2
  }
done

target_digest="sha256:$(/usr/bin/jq -cjS . "${targets}" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
[[ "${target_digest}" == "sha256:82b23c1229c4bb1dbdc047859614d8da924d5bd3e5bdf9efba62b31a397408c1" ]] || {
  echo "error: compatibility target manifest digest changed: ${target_digest}" >&2
  exit 2
}

/usr/bin/jq -e --arg digest "${target_digest}" '
  .schema_version == "coh.normalization-compatibility-targets/v1"
  and .contract_version == "1.0.0"
  and .canonical_encoding == "COH-CJ-1"
  and .status == "design_frozen"
  and .requirements == ["FR-021", "FR-022"]
  and .targets.ocsf.version == "1.9.0"
  and .targets.ocsf.commit == "856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba"
  and .targets.ocsf.source_archive_sha256 == "0ed367ea97dd283d69401099974cec256c862621b6ef53243f76999ace2abfc7"
  and .targets.ecs.version == "9.5.0"
  and .targets.ecs.commit == "401807e0547301525acd28c4fb667203fec66d59"
  and .targets.ecs.source_archive_sha256 == "93a07475f78fc07736128e731cb66d07ce5a1a0a14b72fa9733d6ba5f830df8f"
  and .upgrade_policy.floating_versions_allowed == false
  and .upgrade_policy.development_branches_allowed == false
' "${targets}" >/dev/null

/usr/bin/jq -e --arg digest "${target_digest}" '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and .properties.schema_version.const == "coh.normalized-event-envelope/v1"
  and .properties.contract_version.const == "1.0.0"
  and (.required | contains(["case", "source", "classification", "compatibility", "original", "ocsf", "ecs", "normalization", "lineage", "dataset"]))
  and .["$defs"].compatibility.properties.target_manifest_digest.const == $digest
  and .["$defs"].compatibility.properties.ocsf_version.const == "1.9.0"
  and .["$defs"].compatibility.properties.ecs_version.const == "9.5.0"
  and .["$defs"].original.properties.fields.maxProperties == 1024
  and .["$defs"].ocsf.properties.event.maxProperties == 1024
  and .["$defs"].ecs.properties.fields.maxProperties == 1024
  and (.["$defs"].lineage.required | contains(["raw_artifact", "raw_manifest_digest", "ingest_receipt_digest", "source_provenance_digest", "parent_envelope_digests"]))
  and .["$defs"].dataset.properties.format.const == "parquet"
  and .["$defs"].dataset.properties.access_profile["$ref"] == "#/$defs/access_profile"
' "${schema}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.normalized-event-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 11
  and ([.cases[].name] | unique | length) == 11
  and ([.cases[].name] | contains(["duplicate-key", "unknown-envelope-field", "unsupported-ocsf-target", "missing-raw-manifest", "original-field-mutation", "ocsf-type-mismatch", "classification-downgrade", "changed-transformation", "unsorted-lineage", "direct-dataset-path", "noncanonical-decimal"]))
  and all(.cases[]; (.reason | type) == "string" and (.covered_by | type) == "string")
' "${denials}" >/dev/null

for fixture in "${contract}"/fixtures/valid/*.canonical.json; do
  canonical=$(/usr/bin/jq -cS . "${fixture}")
  fixture_value=$(/bin/cat "${fixture}")
  [[ "${fixture_value}" == "${canonical}" ]] || {
    echo "error: non-canonical fixture: ${fixture}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .original.fields.winlog.event_id == 4624
  and .ocsf.event.class_uid == 3002
  and .ocsf.event.type_uid == 300201
  and .ecs.fields.ecs.version == "9.5.0"
  and .lineage.raw_artifact.classification == "confidential"
  and .dataset == null
' "${contract}/fixtures/valid/event.canonical.json" >/dev/null

/usr/bin/jq -e '
  .dataset.format == "parquet"
  and .dataset.artifact.media_type == "application/vnd.apache.parquet"
  and .dataset.partition_keys == ["date", "tenant"]
  and .dataset.access_profile.max_rows == 10000
  and .dataset.access_profile.max_bytes == 8388608
' "${contract}/fixtures/valid/dataset-event.canonical.json" >/dev/null

if /usr/bin/jq -e '
  [.. | objects | .properties? // {} | keys[]]
  | any(. == "path" or . == "url" or . == "sql" or . == "http" or . == "client" or . == "credential" or . == "secret" or . == "key_reference")
' "${schema}" >/dev/null; then
  echo "error: direct access or secret surface found in envelope schema" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-normalized-event.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/domain/normalizedevent | /usr/bin/tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/domain/normalizedevent | /usr/bin/tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/normalizedevent | /usr/bin/tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/normalizedevent
"${root}/scripts/check_go_architecture.sh" | /usr/bin/tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" \
  "${contract}/README.md" \
  "${contract}/compatibility-matrix.md" \
  "${root}/docs/design/normalized-event-envelope.md"
/usr/bin/git diff --check

echo "normalized-event-envelope summary: contract=1.0.0 ocsf=1.9.0 ecs=9.5.0 original=recoverable raw=COH-E10-bound canonical=COH-NJ-1 fixtures=2 denials=11 dataset=parquet+bounded evidence=resolver-verified failures=0"
