package evidencelifecycle

import "context"

func (service *DeleteService) completeCustodyOrRecoverDelete(ctx context.Context, state deleteState,
	authorization CustodyProofSet, lifecycle LifecycleProof, attestation DispositionAttestation,
	progress Progress) (CustodyProofSet, Progress, error) {
	if progress.Phase == Disposed {
		request := CustodyRequest{Operation: Delete, Phase: Completed, Case: state.Command.Case,
			ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
			ArtifactSetDigest: state.Evidence.ArtifactSetDigest, Subjects: evidenceReferences(state.Evidence.Artifacts),
			ReasonDigest: state.Command.ReasonDigest, ApprovalDigest: state.Command.ApprovalDigest,
			LifecycleReceiptDigest:       &lifecycle.ReceiptDigest,
			PriorAuthorizationDigest:     &authorization.ReceiptSetDigest,
			DispositionAttestationDigest: &attestation.AttestationDigest,
			PolicyDigest:                 state.Command.PolicyDigest, ExpectedCaseRevision: lifecycle.Revision,
			ExpectedHead: authorization.Head, Deadline: state.Command.Deadline}
		proof, err := service.custody.RecordLifecycle(ctx, request)
		if err != nil {
			return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
				"delete_completion_custody_unavailable", err)
		}
		if !validCustodyProofSet(proof, state.Command.Case, authorization.Head, len(state.Evidence.Artifacts)) {
			return CustodyProofSet{}, Progress{}, newError(Denied,
				"delete_completion_custody_invalid", false, nil)
		}
		verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
		if err != nil {
			return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
				"delete_completion_custody_verification_unavailable", err)
		}
		if !validCustodyVerification(verified, proof.Head) {
			return CustodyProofSet{}, Progress{}, newError(Denied,
				"delete_completion_custody_verification_invalid", false, nil)
		}
		progress.Phase, progress.CompletionCustodyReceiptDigest = Custodied, &proof.ReceiptSetDigest
		stored, err := service.advanceDelete(ctx, state, progress)
		return proof, stored, err
	}
	if progress.Phase != Custodied || progress.CompletionCustodyReceiptDigest == nil {
		return CustodyProofSet{}, Progress{}, newError(Conflict,
			"delete_completion_custody_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.custody.RecoverLifecycle(ctx, state.Command.Case,
		*progress.CompletionCustodyReceiptDigest)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
			"delete_completion_custody_recovery_unavailable", err)
	}
	if !found || proof.ReceiptSetDigest != *progress.CompletionCustodyReceiptDigest ||
		!validCustodyProofSet(proof, state.Command.Case, authorization.Head, len(state.Evidence.Artifacts)) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"delete_completion_custody_recovery_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
			"delete_completion_custody_recovery_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, proof.Head) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"delete_completion_custody_recovery_verification_invalid", false, nil)
	}
	return proof, progress, nil
}
