package evidencelifecycle

import "context"

func (service *HoldService) recoverCompletedHold(ctx context.Context, command Command, intent,
	idempotency string, receipt Receipt) (Result, error) {
	if ValidateReceipt(receipt) != nil || receipt.Operation != command.Operation || receipt.Case != command.Case ||
		receipt.RequestID != command.RequestID || receipt.IntentDigest != intent ||
		receipt.IdempotencyDigest != idempotency || receipt.ArtifactSetDigest == nil ||
		receipt.LifecycleReceiptDigest == nil || receipt.CompletionCustodyReceiptDigest == nil {
		return Result{}, newError(Denied, string(ReasonChangedReplay), false, nil)
	}
	progress := Progress{ProgressDigest: receipt.ReceiptDigest}
	state, err := service.authorizeHold(ctx, command, intent, progress, true)
	if err != nil {
		return Result{}, err
	}
	lifecycle, found, err := service.cases.ResolveLifecycleReceipt(ctx, command.Case,
		*receipt.LifecycleReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "hold_replay_lifecycle_unavailable", err)
	}
	if !found || !validLifecycleProof(lifecycle, command.Case, command.Operation) ||
		lifecycle.ReceiptDigest != *receipt.LifecycleReceiptDigest || lifecycle.Revision != state.Case.Revision ||
		command.Operation == PlaceHold && !lifecycle.LegalHold ||
		command.Operation == ReleaseHold && lifecycle.LegalHold {
		return Result{}, newError(Denied, "hold_replay_lifecycle_invalid", false, nil)
	}
	custody, found, err := service.custody.RecoverLifecycle(ctx, command.Case,
		*receipt.CompletionCustodyReceiptDigest)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "hold_replay_custody_unavailable", err)
	}
	if !found || custody.ReceiptSetDigest != *receipt.CompletionCustodyReceiptDigest ||
		!validCustodyProofSet(custody, command.Case, command.ExpectedCustodyHead, len(state.Evidence.Artifacts)) {
		return Result{}, newError(Denied, "hold_replay_custody_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, command.Case, 1, custody.Head.Sequence)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "hold_replay_custody_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, custody.Head) {
		return Result{}, newError(Denied, "hold_replay_custody_verification_invalid", false, nil)
	}
	eventID := deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", receipt.OperationID+"\x00completed")
	if err = service.auditor.VerifyLifecycleEvent(ctx, command.Case, eventID, receipt.AuditEventDigest); err != nil {
		return Result{}, mapExportDependency(ctx, "hold_replay_audit_unavailable", err)
	}
	return Result{Receipt: receipt, Replayed: true}, nil
}
