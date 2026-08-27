package evidencelifecycle

import "context"

func (service *DeleteService) recoverCompletedDelete(ctx context.Context, command Command, intent,
	idempotency string, receipt Receipt) (Result, error) {
	if ValidateReceipt(receipt) != nil || receipt.Operation != Delete || receipt.Case != command.Case ||
		receipt.RequestID != command.RequestID || receipt.IntentDigest != intent ||
		receipt.IdempotencyDigest != idempotency || receipt.ArtifactSetDigest == nil ||
		receipt.AuthorizationCustodyReceiptDigest == nil || receipt.LifecycleReceiptDigest == nil ||
		receipt.DispositionAttestationDigest == nil || receipt.CompletionCustodyReceiptDigest == nil {
		return Result{}, newError(Denied, string(ReasonChangedReplay), false, nil)
	}
	progress := Progress{ProgressDigest: receipt.ReceiptDigest}
	state, err := service.authorizeDelete(ctx, command, intent, progress, true)
	if err != nil {
		return Result{}, err
	}
	authorization, found, err := service.custody.RecoverLifecycle(ctx, command.Case,
		*receipt.AuthorizationCustodyReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "delete_replay_authorization_unavailable", err)
	}
	if !found || authorization.ReceiptSetDigest != *receipt.AuthorizationCustodyReceiptDigest ||
		!validCustodyProofSet(authorization, command.Case, command.ExpectedCustodyHead, len(state.Evidence.Artifacts)) {
		return Result{}, newError(Denied, "delete_replay_authorization_invalid", false, nil)
	}
	lifecycle, found, err := service.cases.ResolveLifecycleReceipt(ctx, command.Case,
		*receipt.LifecycleReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "delete_replay_lifecycle_unavailable", err)
	}
	if !found || !validLifecycleProof(lifecycle, command.Case, Delete) || lifecycle.LegalHold ||
		lifecycle.ReceiptDigest != *receipt.LifecycleReceiptDigest || lifecycle.Revision != state.Case.Revision {
		return Result{}, newError(Denied, "delete_replay_lifecycle_invalid", false, nil)
	}
	attestation, found, err := service.disposer.RecoverDisposition(ctx, command.Case,
		*receipt.DispositionAttestationDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "delete_replay_disposition_unavailable", err)
	}
	if !found || attestation.AttestationDigest != *receipt.DispositionAttestationDigest ||
		!validDeleteAttestation(attestation, state, authorization, lifecycle, receipt.OperationID) {
		return Result{}, newError(Denied, "delete_replay_disposition_invalid", false, nil)
	}
	completion, found, err := service.custody.RecoverLifecycle(ctx, command.Case,
		*receipt.CompletionCustodyReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "delete_replay_completion_unavailable", err)
	}
	if !found || completion.ReceiptSetDigest != *receipt.CompletionCustodyReceiptDigest ||
		!validCustodyProofSet(completion, command.Case, authorization.Head, len(state.Evidence.Artifacts)) {
		return Result{}, newError(Denied, "delete_replay_completion_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, command.Case, 1, completion.Head.Sequence)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "delete_replay_custody_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, completion.Head) {
		return Result{}, newError(Denied, "delete_replay_custody_verification_invalid", false, nil)
	}
	eventID := deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", receipt.OperationID+"\x00completed")
	if err = service.auditor.VerifyLifecycleEvent(ctx, command.Case, eventID, receipt.AuditEventDigest); err != nil {
		return Result{}, mapExportDependency(ctx, "delete_replay_audit_unavailable", err)
	}
	return Result{Receipt: receipt, Replayed: true}, nil
}
