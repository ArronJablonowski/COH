package evidencelifecycle

import "context"

func (service *ExportService) completeCustodyOrRecoverExport(ctx context.Context, state exportState,
	authorization CustodyProofSet, manifest ExportManifest, signature DetachedSignature,
	packaged QuarantinedPackage, progress Progress) (CustodyProofSet, Progress, error) {
	if progress.Phase == Packaged {
		return service.completeCustody(ctx, state, authorization, manifest, signature, packaged, progress)
	}
	if (progress.Phase != Custodied && progress.Phase != CaseRecorded) ||
		progress.CompletionCustodyReceiptDigest == nil {
		return CustodyProofSet{}, Progress{}, newError(Conflict,
			"export_completion_custody_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.custody.RecoverLifecycle(ctx, state.Command.Case,
		*progress.CompletionCustodyReceiptDigest)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
			"export_completion_custody_recovery_unavailable", err)
	}
	if !found || proof.ReceiptSetDigest != *progress.CompletionCustodyReceiptDigest ||
		!validCustodyProofSet(proof, state.Command.Case, authorization.Head, len(state.Evidence.Artifacts)) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"export_completion_custody_recovery_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
			"export_completion_custody_recovery_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, proof.Head) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"export_completion_custody_recovery_verification_invalid", false, nil)
	}
	if !sameHead(state.Decision.ExpectedCustodyHead, proof.Head) {
		return CustodyProofSet{}, Progress{}, newError(Conflict, string(ReasonStaleCustody), false, nil)
	}
	return proof, progress, nil
}

func (service *ExportService) recordOrRecoverCaseExport(ctx context.Context, state exportState,
	manifest ExportManifest, progress Progress) (LifecycleProof, Progress, error) {
	if progress.Phase == Custodied {
		return service.recordCaseExport(ctx, state, manifest, progress)
	}
	if progress.Phase != CaseRecorded || progress.LifecycleReceiptDigest == nil {
		return LifecycleProof{}, Progress{}, newError(Conflict,
			"export_case_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.cases.ResolveLifecycleReceipt(ctx, state.Command.Case,
		*progress.LifecycleReceiptDigest)
	if err != nil {
		return LifecycleProof{}, Progress{}, mapExportDependency(ctx, "export_case_recovery_unavailable", err)
	}
	if !found || proof.ReceiptDigest != *progress.LifecycleReceiptDigest ||
		!validLifecycleProof(proof, state.Command.Case, Export) || proof.Revision != manifest.CaseRevision+1 ||
		proof.Revision != state.CurrentCaseRevision {
		return LifecycleProof{}, Progress{}, newError(Denied, "export_case_recovery_invalid", false, nil)
	}
	return proof, progress, nil
}
