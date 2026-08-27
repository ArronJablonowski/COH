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
	if _, err = service.preflight(ctx, replayCommand, replayIntent); err != nil {
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
	eventID := deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", receipt.OperationID+"\x00completed")
	if err = service.auditor.VerifyLifecycleEvent(ctx, command.Case, eventID, receipt.AuditEventDigest); err != nil {
		return Result{}, mapExportDependency(ctx, "export_replay_audit_unavailable", err)
	}
	reference := packaged.Reference
	return Result{Receipt: receipt, ReleaseReference: &reference, Replayed: true}, nil
}
