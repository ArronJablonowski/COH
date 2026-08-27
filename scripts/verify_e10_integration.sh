#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

leaves=(
  "CYB-76|CYB-76-case-lifecycle-report.md|case_lifecycle|case-lifecycle summary:"
  "CYB-71|CYB-71-immutable-cas-ingestion-report.md|immutable_cas_ingestion|immutable-cas summary:"
  "CYB-79|CYB-79-chain-of-custody-report.md|chain_of_custody|chain-of-custody summary:"
  "CYB-78|CYB-78-governed-redaction-report.md|governed_redaction|governed-redaction summary:"
  "CYB-77|CYB-77-signed-evidence-lifecycle-report.md|signed_evidence_lifecycle|signed-evidence-lifecycle summary:"
)

for entry in "${leaves[@]}"; do
  IFS='|' read -r issue report_name verifier _ <<<"${entry}"
  report="${root}/docs/evidence/${report_name}"
  manifest="${root}/docs/evidence/${issue}-artifacts.sha256"
  script="${root}/scripts/verify_${verifier}.sh"
  for path in "${report}" "${manifest}" "${script}"; do
    [[ -f "${path}" && ! -L "${path}" ]] || {
      echo "error: E10 leaf evidence or verifier is missing or linked: ${path}" >&2
      exit 2
    }
  done
done

for path in \
  "${root}/internal/persistence/sqlite/e10_integration_test.go" \
  "${root}/internal/persistence/sqlite/e10_redaction_integration_test.go" \
  "${root}/internal/persistence/sqlite/e10_delete_integration_test.go" \
  "${root}/internal/workflow/custodycase/adapter.go" \
  "${root}/internal/workflow/evidencesource/adapter.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: E10 parent composition artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-e10-integration.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

for entry in "${leaves[@]}"; do
  IFS='|' read -r _ _ verifier summary <<<"${entry}"
  log="${artifact_dir}/${verifier}.log"
  "${root}/scripts/verify_${verifier}.sh" "${root}" | tee "${log}"
  /usr/bin/grep -Fq "${summary}" "${log}" || {
    echo "error: ${verifier} verifier did not publish its success summary" >&2
    exit 2
  }
done

cd "${root}"

# Real parent compositions prove immutable source and derived bytes through
# signed export, plus governed deletion ordering and restart recovery.
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run \
  'TestCOHE10ComposedExportUsesImmutableEncryptedEvidenceAndDurableStores|TestCOHE10GovernedDeletionOrdersTombstoneDispositionCustodyAndRecovery' \
  ./internal/persistence/sqlite | tee "${artifact_dir}/parent-composition.log"

# Byte/reference mutation and broken lineage are rejected by the real
# ingestion receipt, encrypted manifest, and artifact-set catalog composition.
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run \
  'TestEvidenceReceiptAndEncryptedObjectsSurviveSQLiteRestart' \
  ./internal/persistence/sqlite | tee "${artifact_dir}/mutation-lineage.log"

# Custody insertion, deletion/gap, reorder, mutation, fork, truncation, and
# missing audit coverage fail independent verification from genesis.
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run \
  'TestVerifierRejectsInsertionDeletionReorderMutationForkAndTruncation|TestVerifierRejectsMissingAuditCoverage' \
  ./internal/workflow/custody | tee "${artifact_dir}/custody-gap.log"

# Revoked/changed approval and authority cannot reach redaction transformation;
# ancestry, mapping, custody, and audit substitutions are rejected at export.
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run \
  'TestPreflightRejectsRevokedApprovalAndChangedDecision|TestOrchestratorAuditsRevocationDenialBeforePlaintextOrPublication' \
  ./internal/workflow/redaction | tee "${artifact_dir}/unauthorized-redaction.log"
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run \
  'TestAdapterRejectsBrokenLineageAndMappingSubstitution|TestAdapterRejectsCustodyAndAuditVerificationFailure' \
  ./internal/workflow/lifecycleredaction | tee "${artifact_dir}/redaction-ancestry.log"

# A real two-object interruption leaves one ciphertext removed and one intact;
# exact retry finishes the durable plan. Lost CAS and metadata responses also
# recover without removing manifests, receipts, catalog, or lifecycle history.
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run \
  'TestCOHE10PartialDeletionResumesExactPlanWithoutMetadataLoss|TestLifecycleDispositionRemovesExactBytesAndPreservesMetadataAcrossRestart' \
  ./internal/persistence/sqlite | tee "${artifact_dir}/partial-delete-lost-response.log"

# Consequential lifecycle boundaries remain fail closed under substitutions,
# interruptions, stale state, and exact recovery from every durable phase.
"${COH_GO_ROOT}/bin/go" test -v -count=1 -run \
  'TestExportServiceRejectsSignatureAndPackageSubstitutionBeforeRelease|TestDeleteServiceFailsClosedAtEveryIrreversibleBoundary|TestDeleteServiceResumesEveryDurableProgressPhase|TestDeleteServiceRejectsTamperedDispositionOnReplay' \
  ./internal/workflow/evidencelifecycle | tee "${artifact_dir}/lifecycle-adversarial.log"

"${COH_GO_ROOT}/bin/go" test -count=10 -run 'TestCOHE10' ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" test -count=1 -race -run 'TestCOHE10' ./internal/persistence/sqlite
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/custodycase ./internal/workflow/evidencesource \
  ./internal/workflow/lifecycleredaction ./internal/workflow/lifecycledisposition ./internal/persistence/sqlite
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" \
  "${root}/docs/evidence/CYB-76-case-lifecycle-report.md" \
  "${root}/docs/evidence/CYB-71-immutable-cas-ingestion-report.md" \
  "${root}/docs/evidence/CYB-79-chain-of-custody-report.md" \
  "${root}/docs/evidence/CYB-78-governed-redaction-report.md" \
  "${root}/docs/evidence/CYB-77-signed-evidence-lifecycle-report.md"
/usr/bin/git diff --check

echo "E10 integration summary: children=5 case=scope+retention evidence=immutable+encrypted lineage=verified redaction=authorized+custodied export=signed+independent deletion=tombstone+attested adversarial=mutation+lineage+custody-gap+unauthorized-redaction+partial-delete+lost-response recovery=restart+exact failures=0"
