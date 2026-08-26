#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for entry in \
  "CYB-53:CYB-53-signed-tool-registry-report.md" \
  "CYB-54:CYB-54-native-executor-report.md" \
  "CYB-55:CYB-55-oci-executor-report.md" \
  "CYB-58:CYB-58-remote-worker-report.md" \
  "CYB-57:CYB-57-estop-report.md"; do
  issue=${entry%%:*}
  report="${root}/docs/evidence/${entry#*:}"
  manifest="${root}/docs/evidence/${issue}-artifacts.sha256"
  [[ -f "${report}" && -f "${manifest}" ]] || {
    echo "error: E06 leaf evidence is missing for ${issue}" >&2
    exit 2
  }
  /usr/bin/grep -Fq "| Aggregate result | Pass |" "${report}" || {
    echo "error: E06 leaf report does not record Pass: ${report}" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-e06-integration.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

run_leaf() {
  local name=$1
  local summary=$2
  local log="${artifact_dir}/${name}.log"

  "${root}/scripts/verify_${name}.sh" "${root}" | tee "${log}"
  /usr/bin/grep -Fq "${summary}" "${log}" || {
    echo "error: ${name} verifier did not publish its success summary" >&2
    exit 2
  }
}

cd "${root}"
run_leaf tool_registry "tool-registry summary:"
run_leaf native_executor "native-executor summary:"
run_leaf oci_executor "oci-executor summary:"
run_leaf remote_workers "remote-worker summary:"
run_leaf estop "E-stop summary:"

# These focused paths cross the leaf boundaries that make E06 an integrated
# execution boundary: signed registry resolution, isolation enforcement,
# runner-lease dispatch, and containment of every supported execution mode.
"${COH_GO_ROOT}/bin/go" test -count=1 \
  -run 'TestProcessSandboxExecutesWithoutDockerOrAmbientEnvironment|TestEmergencyStopCooperativelyCancelsNativeExecution' \
  ./internal/broker/nativeexecutor | tee "${artifact_dir}/native-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 \
  -run 'TestExecutorUsesActualSignedRegistryAndLivePublisherAuthority|TestExecutorBuildsLeastPrivilegeBoundPlanAndProvenance|TestEmergencyStopCooperativelyCancelsOCIExecution' \
  ./internal/broker/ociexecutor | tee "${artifact_dir}/oci-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 \
  -run 'TestIssueAndDispatchSingleUse|TestPolicyApprovalCancellationAndRedaction|TestEmergencyStopControlRevokesOnlyItsCaseAndIsIdempotent' \
  ./internal/broker/remoteworker | tee "${artifact_dir}/remote-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 \
  -run 'TestGlobalActivationAppliesEveryControlAndGuard|TestTimingConformance' \
  ./internal/broker/estop | tee "${artifact_dir}/containment-integration.log"

"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
/usr/bin/git diff --check

echo "E06 integration summary: registry=signed+typed authorization=fresh zones=native_restricted+oci_sandbox+remote_isolated native=resource+network+filesystem+credential-deny OCI=resource+network+filesystem+credential-deny remote=lease+resource+network+isolation estop=1s+2s+5s+10s evidence=5-leaves failures=0"
