package evidencelifecycle

import "context"

func (service *DeleteService) disposeOrRecoverDelete(ctx context.Context, state deleteState,
	authorization CustodyProofSet, lifecycle LifecycleProof, progress Progress) (
	DispositionAttestation, Progress, error) {
	if progress.Phase == Tombstoned {
		verified, err := service.recheckTombstonedDeletion(ctx, state, lifecycle)
		if err != nil {
			return DispositionAttestation{}, Progress{}, err
		}
		attestation, err := service.disposer.DisposeEvidence(ctx, DispositionRequest{Case: state.Command.Case,
			OperationID: progress.OperationID, ArtifactSetDigest: state.Evidence.ArtifactSetDigest,
			Evidence: verified, AuthorizationCustodyReceiptDigest: authorization.ReceiptSetDigest,
			LifecycleReceiptDigest: lifecycle.ReceiptDigest, Deadline: state.Command.Deadline})
		if err != nil {
			return DispositionAttestation{}, Progress{}, mapExportDependency(ctx, "delete_disposition_unavailable", err)
		}
		if !validDeleteAttestation(attestation, state, authorization, lifecycle, progress.OperationID) {
			return DispositionAttestation{}, Progress{}, newError(Denied, "delete_disposition_invalid", false, nil)
		}
		progress.Phase, progress.DispositionAttestationDigest = Disposed, &attestation.AttestationDigest
		stored, err := service.advanceDelete(ctx, state, progress)
		return attestation, stored, err
	}
	if progress.DispositionAttestationDigest == nil {
		return DispositionAttestation{}, Progress{}, newError(Conflict,
			"delete_disposition_recovery_phase_invalid", false, nil)
	}
	attestation, found, err := service.disposer.RecoverDisposition(ctx, state.Command.Case,
		*progress.DispositionAttestationDigest)
	if err != nil {
		return DispositionAttestation{}, Progress{}, mapExportDependency(ctx,
			"delete_disposition_recovery_unavailable", err)
	}
	if !found || attestation.AttestationDigest != *progress.DispositionAttestationDigest ||
		!validDeleteAttestation(attestation, state, authorization, lifecycle, progress.OperationID) {
		return DispositionAttestation{}, Progress{}, newError(Denied,
			"delete_disposition_recovery_invalid", false, nil)
	}
	return attestation, progress, nil
}

func (service *DeleteService) recheckTombstonedDeletion(ctx context.Context, state deleteState,
	lifecycle LifecycleProof) (VerifiedEvidenceSet, error) {
	current, found, err := service.cases.LoadCase(ctx, state.Command.Case)
	if err != nil {
		return VerifiedEvidenceSet{}, mapExportDependency(ctx, "delete_tombstone_recheck_unavailable", err)
	}
	if !found || !validCaseSnapshot(current) || current.Case != state.Command.Case || current.State != "deleted" ||
		current.Revision != lifecycle.Revision || current.LegalHold || service.clock.Now().Before(current.RetainUntil) ||
		current.ProvenanceDigest != lifecycle.ProvenanceDigest {
		return VerifiedEvidenceSet{}, newError(Denied, "delete_tombstone_recheck_invalid", false, nil)
	}
	pending, err := service.cases.HasIncompleteHoldRelease(ctx, state.Command.Case)
	if err != nil {
		return VerifiedEvidenceSet{}, mapExportDependency(ctx, "delete_hold_recheck_unavailable", err)
	}
	if pending {
		return VerifiedEvidenceSet{}, newError(Denied, string(ReasonHoldReleaseIncomplete), false, nil)
	}
	verified, err := service.evidence.ResolveEvidenceSet(ctx, state.Command.Case, state.Evidence.ArtifactSetDigest)
	if err != nil {
		return VerifiedEvidenceSet{}, mapExportDependency(ctx, "delete_evidence_recheck_unavailable", err)
	}
	if !validVerifiedEvidenceSet(verified, state.Command, current.Classification) ||
		verified.ArtifactSetDigest != state.Evidence.ArtifactSetDigest ||
		verified.LineageDigest != state.Evidence.LineageDigest ||
		verified.ComponentSetDigest != state.Evidence.ComponentSetDigest {
		return VerifiedEvidenceSet{}, newError(Denied, "delete_evidence_recheck_invalid", false, nil)
	}
	return verified, nil
}

func validDeleteAttestation(value DispositionAttestation, state deleteState, authorization CustodyProofSet,
	lifecycle LifecycleProof, operationID string) bool {
	if ValidateDispositionAttestation(value) != nil || value.Case != state.Command.Case ||
		value.OperationID != operationID || value.ArtifactSetDigest != state.Evidence.ArtifactSetDigest ||
		value.AuthorizationCustodyReceiptDigest != authorization.ReceiptSetDigest ||
		value.LifecycleReceiptDigest != lifecycle.ReceiptDigest || len(value.Objects) != len(state.Evidence.Artifacts) {
		return false
	}
	wanted := make(map[string]struct{}, len(state.Evidence.Artifacts))
	for _, artifact := range state.Evidence.Artifacts {
		wanted[artifact.Reference.Artifact.Digest] = struct{}{}
	}
	for _, object := range value.Objects {
		if _, found := wanted[object.ArtifactDigest]; !found {
			return false
		}
		delete(wanted, object.ArtifactDigest)
	}
	return len(wanted) == 0
}
