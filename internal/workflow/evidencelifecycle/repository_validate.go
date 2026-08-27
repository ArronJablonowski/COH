package evidencelifecycle

func validStoredProgressTransition(current, next Progress) bool {
	if current.OperationID != next.OperationID || current.Case != next.Case || current.Operation != next.Operation ||
		current.CommandDigest != next.CommandDigest || current.IntentDigest != next.IntentDigest ||
		next.Revision != current.Revision+1 || next.UpdatedAt.Before(current.UpdatedAt) ||
		!validNextPhase(current.Operation, current.Phase, next.Phase) ||
		!preservedDigest(current.DecisionDigest, next.DecisionDigest) ||
		!preservedDigest(current.RevocationDigest, next.RevocationDigest) ||
		!preservedDigest(current.PackageDigest, next.PackageDigest) ||
		!preservedDigest(current.ManifestDigest, next.ManifestDigest) ||
		!preservedDigest(current.SignatureDigest, next.SignatureDigest) ||
		!preservedDigest(current.VerificationReportDigest, next.VerificationReportDigest) ||
		!preservedDigest(current.LifecycleReceiptDigest, next.LifecycleReceiptDigest) ||
		!preservedDigest(current.AuthorizationCustodyReceiptDigest, next.AuthorizationCustodyReceiptDigest) ||
		!preservedDigest(current.CompletionCustodyReceiptDigest, next.CompletionCustodyReceiptDigest) ||
		!preservedDigest(current.DispositionAttestationDigest, next.DispositionAttestationDigest) ||
		len(current.Artifacts) != len(next.Artifacts) {
		return false
	}
	for index, artifact := range current.Artifacts {
		candidate := next.Artifacts[index]
		if artifact.Ordinal != candidate.Ordinal || artifact.ArtifactDigest != candidate.ArtifactDigest ||
			!preservedDigest(artifact.IngestionReceiptDigest, candidate.IngestionReceiptDigest) ||
			!preservedDigest(artifact.CustodyReceiptDigest, candidate.CustodyReceiptDigest) {
			return false
		}
	}
	return true
}

func preservedDigest(current, next *string) bool {
	return current == nil || next != nil && *current == *next
}

func validNextPhase(operation Operation, current, next Phase) bool {
	sequences := map[Operation][]Phase{
		Export:      {Planned, Authorized, Packaged, Custodied, CaseRecorded, Completed},
		Import:      {Quarantined, Verified, Authorized, Published, Custodied, Completed},
		PlaceHold:   {Planned, CaseRecorded, Custodied, Completed},
		ReleaseHold: {Planned, CaseRecorded, Custodied, Completed},
		Delete:      {Planned, Authorized, Tombstoned, Disposed, Custodied, Completed},
	}
	values := sequences[operation]
	for index := 0; index+1 < len(values); index++ {
		if values[index] == current {
			return values[index+1] == next
		}
	}
	return false
}

func validInitialProgress(value Progress) bool {
	return value.Revision == 1 && (value.Operation == Import && value.Phase == Quarantined ||
		value.Operation != Import && value.Phase == Planned)
}

func progressMatchesLifecycleRecord(progress Progress, record Record) bool {
	if progress.Phase != Completed || progress.OperationID != record.OperationID || progress.Case != record.Case ||
		progress.Operation != record.Operation || progress.CommandDigest != record.CommandDigest ||
		progress.IntentDigest != record.IntentDigest || progress.DecisionDigest == nil ||
		progress.RevocationDigest == nil || *progress.DecisionDigest != record.DecisionDigest ||
		*progress.RevocationDigest != record.RevocationDigest ||
		!sameOptionalDigest(progress.PackageDigest, record.PackageDigest) ||
		!sameOptionalDigest(progress.ManifestDigest, record.ManifestDigest) ||
		!sameOptionalDigest(progress.SignatureDigest, record.SignatureDigest) ||
		!sameOptionalDigest(progress.VerificationReportDigest, record.VerificationReportDigest) ||
		!sameOptionalDigest(progress.LifecycleReceiptDigest, record.LifecycleReceiptDigest) ||
		!sameOptionalDigest(progress.AuthorizationCustodyReceiptDigest, record.AuthorizationCustodyReceiptDigest) ||
		!sameOptionalDigest(progress.CompletionCustodyReceiptDigest, record.CompletionCustodyReceiptDigest) ||
		!sameOptionalDigest(progress.DispositionAttestationDigest, record.DispositionAttestationDigest) {
		return false
	}
	if progress.Operation == Import {
		if len(progress.Artifacts) != len(record.Artifacts) {
			return false
		}
		for index, artifact := range progress.Artifacts {
			if artifact.Ordinal != uint16(index+1) || artifact.ArtifactDigest != record.Artifacts[index].Artifact.Digest ||
				artifact.IngestionReceiptDigest == nil ||
				*artifact.IngestionReceiptDigest != record.Artifacts[index].IngestionReceiptDigest {
				return false
			}
		}
	}
	return true
}

func sameOptionalDigest(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func lifecycleReceiptMatchesRecord(receipt Receipt, record Record) bool {
	return receipt.OperationID == record.OperationID && receipt.Case == record.Case &&
		receipt.Operation == record.Operation && receipt.IntentDigest == record.IntentDigest &&
		receipt.DecisionDigest == record.DecisionDigest && receipt.RecordDigest == record.RecordDigest &&
		receipt.AuditEventDigest == record.AuditEventDigest && receipt.ProvenanceDigest == record.ProvenanceDigest &&
		receipt.CreatedAt.Equal(record.CompletedAt) && sameEvidenceReferences(receipt.Artifacts, record.Artifacts) &&
		sameOptionalDigest(receipt.ArtifactSetDigest, record.ArtifactSetDigest) &&
		sameOptionalDigest(receipt.PackageDigest, record.PackageDigest) &&
		sameOptionalDigest(receipt.ManifestDigest, record.ManifestDigest) &&
		sameOptionalDigest(receipt.SignatureDigest, record.SignatureDigest) &&
		sameOptionalDigest(receipt.VerificationReportDigest, record.VerificationReportDigest) &&
		sameOptionalDigest(receipt.LifecycleReceiptDigest, record.LifecycleReceiptDigest) &&
		sameOptionalDigest(receipt.AuthorizationCustodyReceiptDigest, record.AuthorizationCustodyReceiptDigest) &&
		sameOptionalDigest(receipt.CompletionCustodyReceiptDigest, record.CompletionCustodyReceiptDigest) &&
		sameOptionalDigest(receipt.DispositionAttestationDigest, record.DispositionAttestationDigest)
}
