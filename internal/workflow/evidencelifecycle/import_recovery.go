package evidencelifecycle

import "context"

func (service *ImportService) recoverCompletedImport(ctx context.Context, command Command, inputReference,
	intent, idempotency string, receipt Receipt) (Result, error) {
	if !validOpaque(inputReference, 1, 256) || ValidateReceipt(receipt) != nil || receipt.Operation != Import ||
		receipt.Case != command.Case || receipt.RequestID != command.RequestID || receipt.IntentDigest != intent ||
		receipt.IdempotencyDigest != idempotency || receipt.PackageDigest == nil || command.PackageDigest == nil ||
		*receipt.PackageDigest != *command.PackageDigest || receipt.ArtifactSetDigest == nil ||
		receipt.VerificationReportDigest == nil {
		return Result{}, newError(Denied, string(ReasonChangedReplay), false, nil)
	}
	current, found, err := service.cases.LoadCase(ctx, command.Case)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "import_replay_case_unavailable", err)
	}
	if !found || !validCaseSnapshot(current) || current.Case != command.Case || current.State == "deleted" {
		return Result{}, newError(Denied, "import_replay_case_invalid", false, nil)
	}
	pending, err := service.cases.HasIncompleteHoldRelease(ctx, command.Case)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "import_replay_hold_unavailable", err)
	}
	if pending {
		return Result{}, newError(Denied, string(ReasonHoldReleaseIncomplete), false, nil)
	}
	head, err := service.custody.LoadCustodyHead(ctx, command.Case)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "import_replay_custody_unavailable", err)
	}
	replayCommand := command
	replayCommand.ExpectedCaseRevision, replayCommand.ExpectedCustodyHead = current.Revision, head
	replayIntent, err := IntentBindingDigest(replayCommand)
	if err != nil {
		return Result{}, err
	}
	authorization := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: replayIntent, Command: replayCommand, CaseState: current.State,
		CaseClassification: current.Classification, CaseRevision: current.Revision, RetainUntil: current.RetainUntil,
		LegalHold: current.LegalHold, HoldReleasePending: pending, CaseProvenanceDigest: current.ProvenanceDigest,
		ArtifactSetDigest: receipt.ArtifactSetDigest, VerificationReportDigest: receipt.VerificationReportDigest,
		CurrentCustodyHead: head}
	authorization.AuthorizationDigest, err = AuthorizationBindingDigest(authorization)
	if err != nil || ValidateAuthorization(authorization) != nil {
		return Result{}, newError(Denied, "import_replay_authorization_invalid", false, err)
	}
	decision, err := service.authority.AuthorizeEvidenceLifecycle(ctx, authorization)
	if err != nil {
		return Result{}, mapExportDependency(ctx, "import_replay_authority_unavailable", err)
	}
	if !validImportDecision(decision, authorization, service.clock.Now()) {
		return Result{}, newError(Denied, "import_replay_decision_invalid", false, nil)
	}
	eventID := deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", receipt.OperationID+"\x00completed")
	if err = service.auditor.VerifyLifecycleEvent(ctx, command.Case, eventID, receipt.AuditEventDigest); err != nil {
		return Result{}, mapExportDependency(ctx, "import_replay_audit_unavailable", err)
	}
	return Result{Receipt: receipt, Imported: append([]EvidenceReference(nil), receipt.Artifacts...), Replayed: true}, nil
}
