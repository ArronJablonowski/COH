#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

leaves=(
  "CYB-70|CYB-70-signed-skill-registry-report.md|skill_registry|skill-registry summary:|Result|Pass"
  "CYB-73|CYB-73-progressive-skill-discovery-report.md|skill_discovery|skill-discovery summary:|CI outcome|passed"
  "CYB-72|CYB-72-memory-namespaces-report.md|memory_namespaces|memory-namespace summary:|CI outcome|passed"
  "CYB-75|CYB-75-hostile-content-retrieval-report.md|hostile_content_retrieval|hostile-content summary:|CI outcome|passed"
  "CYB-74|CYB-74-bounded-subagent-dag-report.md|bounded_subagent_dag|bounded-subagent-DAG summary:|CI outcome|passed"
)

for entry in "${leaves[@]}"; do
  IFS='|' read -r issue report_name verifier _ result_label result_value <<<"${entry}"
  report="${root}/docs/evidence/${report_name}"
  manifest="${root}/docs/evidence/${issue}-artifacts.sha256"
  script="${root}/scripts/verify_${verifier}.sh"
  for path in "${report}" "${manifest}" "${script}"; do
    [[ -f "${path}" && ! -L "${path}" ]] || {
      echo "error: E09 leaf evidence or verifier is missing or linked: ${path}" >&2
      exit 2
    }
  done
  if ! /usr/bin/grep -Fq "| ${result_label} | ${result_value} |" "${report}" &&
    ! /usr/bin/grep -Fq "| ${result_label} | \`${result_value}\` |" "${report}"; then
    echo "error: E09 leaf report does not record ${result_value}: ${report}" >&2
    exit 2
  fi
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-e09-integration.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

for entry in "${leaves[@]}"; do
  IFS='|' read -r _ _ verifier summary _ _ <<<"${entry}"
  log="${artifact_dir}/${verifier}.log"
  "${root}/scripts/verify_${verifier}.sh" "${root}" | tee "${log}"
  /usr/bin/grep -Fq "${summary}" "${log}" || {
    echo "error: ${verifier} verifier did not publish its success summary" >&2
    exit 2
  }
done

cd "${root}"

# Promotion, resolution, progressive discovery, and resource release must keep
# signed/reviewed identity, exact immutable bindings, and current revocation.
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestPromotionResolutionRollbackAndRevocation|TestStrictDecodingAndSignatureDenials|TestResolvedSkillSurfaceContainsNoContentOrAuthorityHandle' \
  ./internal/workflow/skillregistry | tee "${artifact_dir}/skill-registry-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestDetailAndResourceRequireExactSignedBindings|TestExactReplayRechecksCurrentRegistryAndCatalog|TestDiscoverySurfaceExposesNoContentOrExecutionCapability' \
  ./internal/workflow/skilldiscovery | tee "${artifact_dir}/skill-discovery-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestSkillResourceIsInspectedBeforeModelFacingRelease|TestE09MemoryNamespaceIsolationPrecedesHostileContentRelease' \
  ./internal/workflow/agentloop | tee "${artifact_dir}/model-release-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestProgressiveDiscoveryRevalidatesSignedRegistryAndRevocation' \
  ./internal/persistence/sqlite | tee "${artifact_dir}/skill-sqlite-integration.log"

# The actual memory and hostile-content controllers are composed above. A
# denied cross-case or cross-tenant lookup never reaches content inspection.
"${COH_GO_ROOT}/bin/go" test -race -count=1 -run \
  'TestE09MemoryNamespaceIsolationPrecedesHostileContentRelease' \
  ./internal/workflow/agentloop | tee "${artifact_dir}/memory-hostile-race.log"

# Delegation bounds, descendant-first cancellation, typed evidence, budget
# settlement, restart recovery, and no-redispatch remain jointly enforced.
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestDepthFanoutConcurrencyAndCycleBoundsFailClosed|TestCancellationPersistsDescendantFirstTargetsAcknowledgmentsAndSettlement|TestExecutePersistsDispatchValidatesStructuredResultAndSettles|TestRecoveryNeverRedispatchesAnIndeterminateChild' \
  ./internal/workflow/subagentdag | tee "${artifact_dir}/subagent-integration.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -run \
  'TestSubagentDAGSurvivesSQLiteRestartWithoutRedispatch' \
  ./internal/persistence/sqlite | tee "${artifact_dir}/subagent-sqlite-integration.log"

"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" \
  "${root}/docs/evidence/CYB-70-signed-skill-registry-report.md" \
  "${root}/docs/evidence/CYB-73-progressive-skill-discovery-report.md" \
  "${root}/docs/evidence/CYB-72-memory-namespaces-report.md" \
  "${root}/docs/evidence/CYB-75-hostile-content-retrieval-report.md" \
  "${root}/docs/evidence/CYB-74-bounded-subagent-dag-report.md"
/usr/bin/git diff --check

echo "E09 integration summary: children=5 skills=signed+reviewed+immutable+revalidated discovery=progressive memory=namespace-isolated hostile-content=sanitized+untrusted subagents=bounded+cancellable+recoverable evidence=durable failures=0"
