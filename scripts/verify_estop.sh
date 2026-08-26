#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/estop/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/command.schema.json" \
  "${contract}/state.schema.json" \
  "${contract}/control-ack.schema.json" \
  "${contract}/decision.schema.json" \
  "${root}/internal/domain/estop" \
  "${root}/internal/broker/estop" \
  "${root}/internal/broker/executionstop" \
  "${root}/docs/design/emergency-stop-containment.md"; do
  [[ -e "${path}" ]] || {
    echo "error: E-stop input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .additionalProperties == false
  and .properties.schema_version.const == "coh.estop-command/v1"
  and .["$defs"].scope.properties.kind.enum == ["global", "case"]
  and (.properties | has("authorization_allowed") | not)
  and (.properties | has("policy_allowed") | not)
  and (.properties | has("active") | not)
' "${contract}/command.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.estop-state/v1"
  and .properties.active.const == true
  and .properties.epoch.minimum == 1
' "${contract}/state.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.estop-control-ack/v1"
  and .properties.control_kind.enum == ["credential", "lease", "egress", "remote_job", "workflow", "cooperative"]
  and .properties.outcome.enum == ["applied", "failed", "timeout"]
  and .properties.elapsed_nanos.minimum == 0
  and .properties.objective_nanos.minimum == 1
' "${contract}/control-ack.schema.json" >/dev/null

/usr/bin/jq -e '
  .additionalProperties == false
  and .properties.schema_version.const == "coh.estop-decision/v1"
  and .properties.event.enum == ["activation", "control_ack"]
  and (.properties | has("secret") | not)
  and (.properties | has("credential") | not)
' "${contract}/decision.schema.json" >/dev/null

if /usr/bin/grep -R -E 'json:"(secret|credential|token|private_key)' \
  "${root}/internal/domain/estop" --include='*.go' >/dev/null; then
  echo "error: secret-bearing field found in E-stop domain" >&2
  exit 2
fi

for pattern in \
  'execution \*executionstop.Tracker' \
  'stop +StopGuard' \
  'index +WorkflowIndex' \
  'network +\*ContainmentNetworkBroker'; do
  /usr/bin/grep -R -E "${pattern}" "${root}/internal/broker" "${root}/internal/workflow" --include='*.go' >/dev/null || {
    echo "error: mandatory containment dependency is missing: ${pattern}" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-estop.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

cd "${root}"
packages=(
  ./internal/domain/estop
  ./internal/broker/estop
  ./internal/broker/executionstop
  ./internal/broker/credentiallease
  ./internal/broker/remoteworker
  ./internal/broker/nativeexecutor
  ./internal/broker/ociexecutor
  ./internal/workflow
)
"${COH_GO_ROOT}/bin/go" test -count=1 "${packages[@]}" | tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -count=3 "${packages[@]}" | tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${packages[@]}" | tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -run '^TestTimingConformance' ./internal/broker/estop | tee "${artifact_dir}/timing.log"
"${COH_GO_ROOT}/bin/go" vet "${packages[@]}"

"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
/usr/bin/git diff --check

echo "E-stop summary: activation=atomic+monotonic scope=global+case leases=1s egress=2s jobs+workflows=5s cooperative=10s timing=monotonic audit=durable-outbox replay=idempotent partial=fail-closed failures=0"
