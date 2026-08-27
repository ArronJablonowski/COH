#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/time/v1"
schema="${contract}/time-normalization.schema.json"
fixtures="${contract}/fixtures/eval-017.json"
design="${root}/docs/design/time-precision-and-uncertainty.md"
package="${root}/internal/domain/temporaltime"

for path in "${contract}/README.md" "${schema}" "${fixtures}" "${design}" "${package}/README.md"; do
  [[ -e "${path}" ]] || {
    echo "error: CYB-82 input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (.oneOf | length) == 4
  and .["$defs"].command.additionalProperties == false
  and .["$defs"].record.additionalProperties == false
  and .["$defs"].comparison.additionalProperties == false
  and .["$defs"].receipt.additionalProperties == false
  and (.["$defs"].command.required | contains(["case", "source_binding", "original_time", "parser", "timezone", "calibration", "evidence_state", "completeness", "idempotency_key", "deadline"]))
  and (.["$defs"].record.required | contains(["command_digest", "normalized_utc", "interval", "timezone_result", "candidate_utc", "outcome", "reason_code"]))
  and (.["$defs"].comparison.properties.outcome.enum | contains(["before", "after", "equal", "overlap", "duplicate", "conflicting", "unknown"]))
  and (.["$defs"].normalization_reason.enum | contains(["dst_gap", "timezone_unresolved", "arithmetic_overflow", "idempotency_conflict", "context_canceled", "context_deadline"]))
' "${schema}" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.eval-017-time-fixtures/v1"
  and .contract_version == "1.0.0"
  and .requirements == ["FR-024", "EVAL-017"]
  and (.cases | length) == 15
  and ([.cases[].name] | unique | length) == 15
  and ([.cases[].name] | contains(["dst-spring-gap", "dst-fall-fold", "missing-timezone", "low-precision-day", "positive-clock-skew", "negative-clock-skew", "duplicate-record", "uncertain-order", "source-conflict", "partial-data", "negative-evidence", "explicit-gap-evidence"]))
' "${fixtures}" >/dev/null

if /usr/bin/jq -e '
  [.. | objects | .properties? // {} | keys[]]
  | any(. == "path" or . == "url" or . == "sql" or . == "http" or . == "client" or . == "connector" or . == "executor" or . == "credential" or . == "secret" or . == "callback" or . == "shell")
' "${schema}" >/dev/null; then
  echo "error: unsafe direct-access surface found in CYB-82 schema" >&2
  exit 2
fi

[[ $(/usr/bin/grep -Fxc './internal/domain/temporaltime FuzzDecodeCommandRoundTrip' "${root}/ci/fuzz-targets.txt") -eq 1 ]] || {
  echo "error: CYB-82 fuzz target is not registered exactly once" >&2
  exit 2
}

for term in FR-024 EVAL-017 COH-E10 CYB-80 DST idempotency rollback privacy; do
  /usr/bin/grep -Fq "${term}" "${design}" || {
    echo "error: CYB-82 design is missing ${term}" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=${COH_FOCUSED_ARTIFACT_DIR:-$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-time-precision.XXXXXX")}
/bin/mkdir -p "${artifact_dir}"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/domain/temporaltime | /usr/bin/tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/domain/temporaltime | /usr/bin/tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/domain/temporaltime | /usr/bin/tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/domain/temporaltime
"${root}/scripts/check_go_architecture.sh" | /usr/bin/tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh" | /usr/bin/tee "${artifact_dir}/file-size.log"
"${root}/scripts/check_markdown_links.sh" "${contract}/README.md" "${design}" "${package}/README.md"
/usr/bin/git diff --check

echo "time-precision summary: contract=1.0.0 requirements=FR-024+EVAL-017 fixtures=15 parsers=pinned+closed tzdata=pinned dst=gap+fold precision=inclusive skew=signed+overflow-safe ordering=conservative replay=durable failures=0 artifacts=${artifact_dir}"
