package evidencelifecycle

import "context"

func (service *ExportService) recoverCompleted(ctx context.Context, command Command, intent, idempotency string,
	receipt Receipt) (Result, error) {
	if ValidateReceipt(receipt) != nil || receipt.Operation != Export || receipt.Case != command.Case ||
		receipt.RequestID != command.RequestID || receipt.IntentDigest != intent ||
		receipt.IdempotencyDigest != idempotency || receipt.PackageDigest == nil {
		return Result{}, newError(Denied, string(ReasonChangedReplay), false, nil)
	}
	current, found, err := service.cases.LoadCase(ctx, command.Case)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_case_unavailable", err)
	}
	if !found || !validCaseSnapshot(current) || current.State == "deleted" {
		return Result{}, newError(Denied, "export_replay_case_invalid", false, nil)
	}
	pending, err := service.cases.HasIncompleteHoldRelease(ctx, command.Case)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_hold_unavailable", err)
	}
	if pending {
		return Result{}, newError(Denied, string(ReasonHoldReleaseIncomplete), false, nil)
	}
	head, err := service.custody.LoadCustodyHead(ctx, command.Case)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_custody_unavailable", err)
	}
	replayCommand := command
	replayCommand.ExpectedCaseRevision, replayCommand.ExpectedCustodyHead = current.Revision, head
	replayIntent, err := IntentBindingDigest(replayCommand)
	if err != nil {
		return Result{}, err
	}
	state, err := service.preflight(ctx, replayCommand, replayIntent)
	if err != nil {
		return Result{}, err
	}
	packaged, found, err := service.packages.RecoverPackage(ctx, command.Case, *receipt.PackageDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_package_unavailable", err)
	}
	if !found || packaged.PackageDigest != *receipt.PackageDigest || receipt.ManifestDigest == nil ||
		packaged.ManifestDigest != *receipt.ManifestDigest || receipt.SignatureDigest == nil ||
		packaged.SignatureDigest != *receipt.SignatureDigest {
		return Result{}, newError(Denied, "export_replay_package_invalid", false, nil)
	}
	if err = service.packages.VerifyPackage(ctx, packaged, command.Limits); err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_package_verification_unavailable", err)
	}
	manifest, signature, err := service.packages.RecoverPackageProof(ctx, packaged, command.Limits)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_package_proof_unavailable", err)
	}
	if !validCompletedExportPackage(manifest, signature, packaged, receipt, command, state.Evidence,
		service.signing, service.clock.Now()) {
		return Result{}, newError(Denied, "export_replay_package_proof_invalid", false, nil)
	}
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		return Result{}, err
	}
	if err = service.verifier.VerifyDetachedSignature(ctx, VerifySignatureRequest{ManifestDigest: manifest.ManifestDigest,
		CanonicalBytes: canonical, Signature: signature, TrustSnapshotDigest: service.signing.TrustSnapshotDigest,
		RevocationDigest: service.signing.KeyRevocationDigest, At: service.clock.Now()}); err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_signature_verification_unavailable", err)
	}
	originalCustody, err := service.custody.VerifyLifecycle(ctx, command.Case, 1,
		command.ExpectedCustodyHead.Sequence)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_original_custody_unavailable", err)
	}
	if !validCustodyVerification(originalCustody, command.ExpectedCustodyHead) {
		return Result{}, newError(Denied, "export_replay_original_custody_invalid", false, nil)
	}
	authorization, found, err := service.custody.RecoverLifecycle(ctx, command.Case,
		*receipt.AuthorizationCustodyReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_authorization_custody_unavailable", err)
	}
	if !found || authorization.ReceiptSetDigest != *receipt.AuthorizationCustodyReceiptDigest ||
		!validCustodyProofSet(authorization, command.Case, command.ExpectedCustodyHead, len(state.Evidence.Artifacts)) {
		return Result{}, newError(Denied, "export_replay_authorization_custody_invalid", false, nil)
	}
	completion, found, err := service.custody.RecoverLifecycle(ctx, command.Case,
		*receipt.CompletionCustodyReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_completion_custody_unavailable", err)
	}
	if !found || completion.ReceiptSetDigest != *receipt.CompletionCustodyReceiptDigest ||
		!validCustodyProofSet(completion, command.Case, authorization.Head, len(state.Evidence.Artifacts)) {
		return Result{}, newError(Denied, "export_replay_completion_custody_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, command.Case, 1, completion.Head.Sequence)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_custody_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, completion.Head) {
		return Result{}, newError(Denied, "export_replay_custody_verification_invalid", false, nil)
	}
	lifecycle, found, err := service.cases.ResolveLifecycleReceipt(ctx, command.Case,
		*receipt.LifecycleReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_lifecycle_unavailable", err)
	}
	if !found || lifecycle.ReceiptDigest != *receipt.LifecycleReceiptDigest ||
		!validLifecycleProof(lifecycle, command.Case, Export) || lifecycle.Revision != manifest.CaseRevision+1 {
		return Result{}, newError(Denied, "export_replay_lifecycle_invalid", false, nil)
	}
	eventID := deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", receipt.OperationID+"\x00completed")
	if err = service.auditor.VerifyLifecycleEvent(ctx, command.Case, eventID, receipt.AuditEventDigest); err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_audit_unavailable", err)
	}
	reference := packaged.Reference
	return Result{Receipt: receipt, ReleaseReference: &reference, Replayed: true}, nil
}
