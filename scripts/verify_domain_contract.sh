#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="$root/contracts/domain/v1"
registry="$contract/contract-registry.json"
schema="$contract/common-envelope.schema.json"
workflow_schema="$contract/workflow-payloads.schema.json"
evidence_schema="$contract/evidence-analysis-payloads.schema.json"
authority_schema="$contract/authority-payloads.schema.json"
capability_schema="$contract/capability-risk-payloads.schema.json"
valid="$contract/fixtures/envelope.valid.json"
workflow_valid="$contract/fixtures/workflow-payloads.valid.json"
evidence_valid="$contract/fixtures/evidence-analysis-payloads.valid.json"
authority_valid="$contract/fixtures/authority-payloads.valid.json"
capability_valid="$contract/fixtures/capability-risk-payloads.valid.json"
payload_denials="$contract/fixtures/payload-denials.json"
denied="$contract/fixtures/denied"

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

for command in go jq diff mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done
for path in "$registry" "$schema" "$workflow_schema" "$evidence_schema" "$authority_schema" "$capability_schema" "$valid" "$workflow_valid" "$evidence_valid" "$authority_valid" "$capability_valid" "$payload_denials" "$denied"; do
  [[ -e "$path" ]] || {
    printf 'error: domain contract input is missing: %s\n' "$path" >&2
    exit 2
  }
done
jq -e 'map(.kind) == ["artifact_manifest", "case", "run", "task"] and all(.[]; (.data | type) == "object")' "$workflow_valid" >/dev/null || fail 'workflow positive fixture inventory failed'
jq -e 'map(.kind) == ["claim", "evidence", "finding", "timeline_event"] and all(.[]; (.data | type) == "object")' "$evidence_valid" >/dev/null || fail 'evidence positive fixture inventory failed'
jq -e 'map(.kind) == ["action", "approval", "query", "roe"] and all(.[]; (.data | type) == "object")' "$authority_valid" >/dev/null || fail 'authority positive fixture inventory failed'
jq -e 'map(.kind) == ["model", "risk", "skill", "vulnerability"] and all(.[]; (.data | type) == "object")' "$capability_valid" >/dev/null || fail 'capability positive fixture inventory failed'
jq -e 'length == 16 and (map(.kind) | sort | unique | length) == 16 and all(.[]; (.name | type) == "string" and (.kind | type) == "string" and (.property | type) == "string" and (.operation == "add" or .operation == "remove" or .operation == "replace"))' "$payload_denials" >/dev/null || fail 'payload denial fixture inventory failed'

tmp=$(mktemp -d "${TMPDIR:-/tmp}/coh-domain-contract.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

jq -e '
  .schema == "coh.domain.registry/v1"
  and .contract_schema == "coh.domain/v1"
  and .canonical_encoding == "COH-CJ-1"
  and .common_schema == "common-envelope.schema.json"
  and .status == "draft"
  and .blocked_by == ["COH-E01"]
  and .requirements == ["FR-010", "NFR-021"]
  and (.kinds | length) == 16
  and (.kinds == (.kinds | sort | unique))
  and ((.case_boundaries | keys) == .kinds)
  and (.case_boundaries.case == "self")
  and (.case_boundaries.model == "optional")
  and (.case_boundaries.skill == "optional")
  and ([.case_boundaries[] | select(. == "required")] | length == 13)
' "$registry" >/dev/null || fail 'domain registry invariants failed'

jq -r '.kinds[]' "$registry" > "$tmp/registry-kinds"
jq -r '.properties.kind.enum[]' "$schema" > "$tmp/schema-kinds"
diff -u "$tmp/registry-kinds" "$tmp/schema-kinds" >/dev/null ||
  fail 'registry and common-schema kinds differ'

jq -r '.implemented_kind_schemas | keys[]' "$registry" > "$tmp/implemented-kinds"
printf '%s\n' action approval artifact_manifest case claim evidence finding model query risk roe run skill task timeline_event vulnerability \
  > "$tmp/expected-implemented-kinds"
diff -u "$tmp/expected-implemented-kinds" "$tmp/implemented-kinds" >/dev/null ||
  fail 'implemented per-kind registry entries differ'

for kind in artifact_manifest case run task; do
  jq -e --arg kind "$kind" '
    .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    and (."$defs"[$kind].type == "object")
    and (."$defs"[$kind].additionalProperties == false)
    and (."$defs"[$kind].required | length > 0)
  ' "$workflow_schema" >/dev/null || fail "strict payload schema failed: $kind"
done
for kind in model risk skill vulnerability; do
  jq -e --arg kind "$kind" '.["$schema"] == "https://json-schema.org/draft/2020-12/schema" and (."$defs"[$kind].type == "object") and (."$defs"[$kind].additionalProperties == false) and (."$defs"[$kind].required | length > 0)' "$capability_schema" >/dev/null || fail "strict payload schema failed: $kind"
done
for kind in action approval query roe; do
  jq -e --arg kind "$kind" '.["$schema"] == "https://json-schema.org/draft/2020-12/schema" and (."$defs"[$kind].type == "object") and (."$defs"[$kind].additionalProperties == false) and (."$defs"[$kind].required | length > 0)' "$authority_schema" >/dev/null || fail "strict payload schema failed: $kind"
done
for kind in claim evidence finding timeline_event; do
  jq -e --arg kind "$kind" '
    .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    and (."$defs"[$kind].type == "object")
    and (."$defs"[$kind].additionalProperties == false)
    and (."$defs"[$kind].required | length > 0)
  ' "$evidence_schema" >/dev/null || fail "strict payload schema failed: $kind"
done

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 9
  and ((.required | sort) == (.properties | keys | sort))
  and (.properties.schema.const == "coh.domain/v1")
  and (.properties.revision.minimum == 1)
  and (.properties.data.maxProperties == 128)
' "$schema" >/dev/null || fail 'common-envelope schema shape failed'

envelope_filter='def uuidv7:
    type == "string"
    and test("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
  def timestamp:
    type == "string"
    and test("^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9][.][0-9]{9}Z$");
  (keys | sort) == ["case_id", "created_at", "data", "id", "kind", "organization_id", "revision", "schema", "tenant_id"]
  and .schema == "coh.domain/v1"
  and (.kind as $kind | ($kinds | index($kind)) != null)
  and (.id | uuidv7)
  and (.organization_id | uuidv7)
  and (.tenant_id | uuidv7)
  and ((.case_id == null) or (.case_id | uuidv7))
  and (.revision | type == "number" and floor == . and . >= 1 and . <= 9223372036854775807)
  and (.created_at | timestamp)
  and (.data | type == "object" and length <= 128)'

kinds=$(jq -c '.kinds' "$registry")
jq -e --argjson kinds "$kinds" "$envelope_filter" "$valid" >/dev/null ||
  fail 'positive common-envelope fixture was denied'

denied_count=0
for fixture in "$denied"/*.json; do
  if [[ "$(basename "$fixture")" == "duplicate-key.json" ]]; then
    continue
  fi
  if jq -e --argjson kinds "$kinds" "$envelope_filter" "$fixture" >/dev/null; then
    fail "denial fixture was accepted: ${fixture#$root/}"
  fi
  denied_count=$((denied_count + 1))
done
[[ "$denied_count" == 3 ]] || fail "expected 3 denial fixtures, found $denied_count"

# jq applies last-key-wins semantics, so duplicate-key denial and per-kind
# payload semantics are exercised by the production decoder and validator.
go test ./internal/helper/domaincontract -count=1 >/dev/null ||
  fail 'executable domain contract tests failed'

printf 'domain-contract summary: registry=16 schema-kinds=16 payloads-valid=16 payloads-denied=16 envelope-valid=1 envelopes-denied=4 failures=0\n'
