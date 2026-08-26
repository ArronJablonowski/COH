#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

leaves=(
  "CYB-60:CYB-60-agent-loop-report.md:agent_loop:agent-loop summary:"
  "CYB-68:CYB-68-agent-phases-report.md:agent_phases:agent-phase summary:"
  "CYB-69:CYB-69-broker-tool-routing-report.md:broker_tool_routing:broker-route summary:"
  "CYB-65:CYB-65-run-task-budgets-report.md:run_budgets:run-budget summary:"
  "CYB-66:CYB-66-context-compaction-report.md:context_compaction:context-compaction summary:"
  "CYB-67:CYB-67-recovery-control-report.md:recovery_control:recovery-control summary:"
)

for entry in "${leaves[@]}"; do
  IFS=: read -r issue report_name verifier summary <<<"${entry}"
  report="${root}/docs/evidence/${report_name}"
  manifest="${root}/docs/evidence/${issue}-artifacts.sha256"
  script="${root}/scripts/verify_${verifier}.sh"
  for path in "${report}" "${manifest}" "${script}"; do
    [[ -f "${path}" && ! -L "${path}" ]] || {
      echo "error: E08 leaf evidence or verifier is missing or linked: ${path}" >&2
      exit 2
    }
  done
  /usr/bin/grep -Fq '| Aggregate result | Pass |' "${report}" || {
    echo "error: E08 leaf report does not record Pass: ${report}" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-e08-integration.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

for entry in "${leaves[@]}"; do
  IFS=: read -r _ _ verifier summary <<<"${entry}"
  log="${artifact_dir}/${verifier}.log"
  "${root}/scripts/verify_${verifier}.sh" "${root}" | tee "${log}"
  /usr/bin/grep -Fq "${summary}" "${log}" || {
    echo "error: ${verifier} verifier did not publish its success summary" >&2
    exit 2
  }
done

cd "${root}"

# Restart, durable phase sequencing, budget admission/settlement, and the
# broker-only action boundary cross the E08-01 through E08-04 leaves.
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestInjectedCrashesAtEveryDurableBoundaryRecoverSafely|TestAgentLoopChargesBeforeSchedulingAndSettlesBeforeSuccessor|TestBudgetSettlementBindingRecoversWithoutRepeatingActivity|TestInitialBudgetDenialCreatesNoWorkflowState|TestCrashAfterBrokerReceiptNeverReplaysAction|TestInvalidBrokerReceiptFreezesRunAsUncertain' \
  ./internal/workflow/agentloop | tee "${artifact_dir}/durability-budget-broker.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestPlanActObserveReviewCompletesWithTypedBindings|TestActionCrashFreezesUncertainWithoutRedispatch|TestRetryAndReviewCycleExhaustionBecomeDurableFailures' \
  ./internal/workflow/agentphase | tee "${artifact_dir}/phase-integration.log"

# The broker is the sole production connector dispatch route; workflow,
# provider, transport, UI, and command packages must not import around it.
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestToolRouteSuccessBindsPolicyApprovalAuditAndReplaysWithoutDispatch|TestToolRouteDispatchCrashBecomesUncertainAndNeverRedispatches|TestToolRouteCancellationTimeoutAndAuditFailureStayFailClosed' \
  ./internal/broker | tee "${artifact_dir}/broker-boundary.log"

# Compaction retains the full evidence manifest beside its replacement, and
# recovery/cancellation/fallback preserve every explicit terminal condition.
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestCompactPreservesEvidenceSemanticsAndStoresSummaryReferenceSeparately|TestScopeIdentityOrderingAndReplacementTamperAreDenied|TestAmbiguousCommitsRecoverWithoutRepeatingSummaryWrite' \
  ./internal/workflow/contextcompact | tee "${artifact_dir}/compaction-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestRecoveryResumesSafeWorkExactlyAndPreservesTerminalOrUncertainState|TestCancellationIntentIsDurableBeforeOrderedChildAndToolPropagation|TestFallbackUsesOnlyApprovedEquivalentNonBroaderRoute|TestFallbackNeverRunsAfterDenialCancellationTimeoutOrIndeterminateOutcome|TestLostBeginResponseBecomesUncertainAfterDeadlineWithoutProviderRetry' \
  ./internal/workflow/recoverycontrol | tee "${artifact_dir}/recovery-integration.log"

for boundary in workflow provider transport ui command; do
  directory="${root}/internal/${boundary}"
  [[ -d "${directory}" ]] || continue
  if /usr/bin/grep -R -n -E '"github[.]com/ArronJablonowski/COH/internal/(connector|broker/(nativeexecutor|ociexecutor|remoteworker|credentiallease|secretresolver))' \
    "${directory}" --include='*.go' >/dev/null; then
    echo "error: ${boundary} bypasses the broker into a connector, executor, runner, credential, or secret boundary" >&2
    exit 2
  fi
done

"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" \
  "${root}/docs/evidence/CYB-60-agent-loop-report.md" \
  "${root}/docs/evidence/CYB-68-agent-phases-report.md" \
  "${root}/docs/evidence/CYB-69-broker-tool-routing-report.md" \
  "${root}/docs/evidence/CYB-65-run-task-budgets-report.md" \
  "${root}/docs/evidence/CYB-66-context-compaction-report.md" \
  "${root}/docs/evidence/CYB-67-recovery-control-report.md"
/usr/bin/git diff --check

echo "E08 integration summary: children=6 restart=durable phases=plan+act+observe+review broker=bypass-denied budgets=pre-schedule+settled compaction=evidence-manifest-preserved recovery=safe-only cancellation=child+tool+uncertain fallback=approved+equivalent+nonbroader failures=0"
