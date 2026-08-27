package evidencelifecycle

import (
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestCompletedImportProgressBindsIngestionReceipt(t *testing.T) {
	artifact, ingestion := lifecycleDigest("repository-artifact"), lifecycleDigest("repository-ingestion")
	decision, revocation := lifecycleDigest("repository-decision"), lifecycleDigest("repository-revocation")
	packageDigest, manifest := lifecycleDigest("repository-package"), lifecycleDigest("repository-manifest")
	signature, verification := lifecycleDigest("repository-signature"), lifecycleDigest("repository-verification")
	completion := lifecycleDigest("repository-completion")
	progress := Progress{Phase: Completed, OperationID: lifecycleUUID("repository-operation"), Case: lifecycleCase(),
		Operation: Import, CommandDigest: lifecycleDigest("repository-command"), IntentDigest: lifecycleDigest("repository-intent"),
		DecisionDigest: &decision, RevocationDigest: &revocation, PackageDigest: &packageDigest,
		ManifestDigest: &manifest, SignatureDigest: &signature, VerificationReportDigest: &verification,
		CompletionCustodyReceiptDigest: &completion,
		Artifacts:                      []ArtifactProgress{{Ordinal: 1, ArtifactDigest: artifact, IngestionReceiptDigest: &ingestion}}}
	record := Record{OperationID: progress.OperationID, Case: progress.Case, Operation: progress.Operation,
		CommandDigest: progress.CommandDigest, IntentDigest: progress.IntentDigest, DecisionDigest: decision,
		RevocationDigest: revocation, PackageDigest: &packageDigest, ManifestDigest: &manifest,
		SignatureDigest: &signature, VerificationReportDigest: &verification,
		CompletionCustodyReceiptDigest: &completion, Artifacts: []EvidenceReference{{
			Artifact: domain.ArtifactRef{Digest: artifact}, IngestionReceiptDigest: ingestion}}}
	if !progressMatchesLifecycleRecord(progress, record) {
		t.Fatal("matching import progress and record were rejected")
	}
	record.Artifacts[0].IngestionReceiptDigest = lifecycleDigest("repository-substituted-ingestion")
	if progressMatchesLifecycleRecord(progress, record) {
		t.Fatal("substituted ingestion receipt was accepted")
	}
}
