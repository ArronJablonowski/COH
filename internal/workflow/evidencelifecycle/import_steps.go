package evidencelifecycle

import "context"

func (service *ImportService) authorizeImport(ctx context.Context, command Command, intent string,
	verified VerifiedImport, recovery bool) (importState, error) {
	current, found, err := service.cases.LoadCase(ctx, command.Case)
	if err != nil {
		return importState{}, mapExportDependency(ctx, "import_case_unavailable", err)
	}
	if !found || !validCaseSnapshot(current) || current.Case != command.Case || current.State == "deleted" ||
		current.Revision != command.ExpectedCaseRevision {
		return importState{}, newError(Denied, "import_case_invalid", false, nil)
	}
	pending, err := service.cases.HasIncompleteHoldRelease(ctx, command.Case)
	if err != nil {
		return importState{}, mapExportDependency(ctx, "import_hold_unavailable", err)
	}
	if pending {
		return importState{}, newError(Denied, string(ReasonHoldReleaseIncomplete), false, nil)
	}
	if classificationRank(verified.Manifest.Classification) > classificationRank(current.Classification) {
		return importState{}, newError(Denied, "import_classification_invalid", false, nil)
	}
	head, err := service.custody.LoadCustodyHead(ctx, command.Case)
	if err != nil {
		return importState{}, mapExportDependency(ctx, "import_custody_head_unavailable", err)
	}
	if !recovery && !sameHead(head, command.ExpectedCustodyHead) {
		return importState{}, newError(Conflict, string(ReasonStaleCustody), true, nil)
	}
	authorizationCommand, authorizationIntent := command, intent
	if recovery {
		authorizationCommand.ExpectedCaseRevision, authorizationCommand.ExpectedCustodyHead = current.Revision, head
		authorizationIntent, err = IntentBindingDigest(authorizationCommand)
		if err != nil {
			return importState{}, err
		}
	}
	reportDigest := verified.Verification.ReportDigest
	artifactSet := verified.Verification.ArtifactSetDigest
	authorization := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: authorizationIntent, Command: authorizationCommand, CaseState: current.State,
		CaseClassification: current.Classification,
		CaseRevision:       current.Revision, RetainUntil: current.RetainUntil, LegalHold: current.LegalHold,
		HoldReleasePending: pending, CaseProvenanceDigest: current.ProvenanceDigest,
		ArtifactSetDigest: &artifactSet, VerificationReportDigest: &reportDigest, CurrentCustodyHead: head}
	authorization.AuthorizationDigest, err = AuthorizationBindingDigest(authorization)
	if err != nil || ValidateAuthorization(authorization) != nil {
		return importState{}, newError(Denied, "import_authorization_invalid", false, err)
	}
	decision, err := service.authority.AuthorizeEvidenceLifecycle(ctx, authorization)
	if err != nil {
		return importState{}, mapExportDependency(ctx, "import_authority_unavailable", err)
	}
	now := service.clock.Now()
	if !validImportDecision(decision, authorization, now) {
		return importState{}, newError(Denied, "import_decision_invalid", false, nil)
	}
	return importState{Command: command, IntentDigest: intent, Case: current, Verified: verified,
		Decision: decision, FinalDecisionDigest: decision.DecisionDigest,
		FinalRevocationDigest: decision.RevocationDigest, AuthorizedAt: now}, nil
}

func (service *ImportService) restoreOrPlanImport(ctx context.Context, command Command, intent,
	idempotency string, verified VerifiedImport) (Progress, error) {
	stored, found, err := service.store.LoadProgress(ctx, command.Case, idempotency)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "import_progress_recovery_unavailable", err)
	}
	if !found {
		return service.planImport(ctx, command, intent, verified)
	}
	if !validRecoveredImportProgress(stored, command, intent, verified) {
		return Progress{}, newError(Conflict, string(ReasonChangedReplay), false, nil)
	}
	if stored.Phase != Quarantined {
		return stored, nil
	}
	manifestDigest, signatureDigest, reportDigest := verified.Manifest.ManifestDigest,
		verified.Package.SignatureDigest, verified.Verification.ReportDigest
	stored.Phase, stored.ManifestDigest, stored.SignatureDigest, stored.VerificationReportDigest =
		Verified, &manifestDigest, &signatureDigest, &reportDigest
	return service.advanceImportValues(ctx, command, intent, stored)
}

func validRecoveredImportProgress(value Progress, command Command, intent string, verified VerifiedImport) bool {
	commandDigest, err := CommandBindingDigest(command)
	if err != nil || ValidateProgress(value) != nil || value.Operation != Import || value.Case != command.Case ||
		value.CommandDigest != commandDigest || value.IntentDigest != intent || value.PackageDigest == nil ||
		*value.PackageDigest != verified.Package.PackageDigest || value.OperationID !=
		deterministicUUID("COH-EVIDENCE-IMPORT-OPERATION-ID-V1\x00", command.RequestID+"\x00"+intent) ||
		value.Phase == Completed || len(value.Artifacts) != len(verified.Staged) {
		return false
	}
	for index, artifact := range value.Artifacts {
		if artifact.Ordinal != verified.Staged[index].Ordinal ||
			artifact.ArtifactDigest != verified.Staged[index].ArtifactDigest {
			return false
		}
	}
	return true
}

func (service *ImportService) planImport(ctx context.Context, command Command, intent string,
	verified VerifiedImport) (Progress, error) {
	commandDigest, _ := CommandBindingDigest(command)
	artifacts := make([]ArtifactProgress, len(verified.Staged))
	for index, value := range verified.Staged {
		artifacts[index] = ArtifactProgress{Ordinal: value.Ordinal, ArtifactDigest: value.ArtifactDigest}
	}
	packageDigest := verified.Package.PackageDigest
	progress := Progress{SchemaVersion: ProgressSchemaVersion, ContractVersion: ContractVersion,
		OperationID: deterministicUUID("COH-EVIDENCE-IMPORT-OPERATION-ID-V1\x00", command.RequestID+"\x00"+intent),
		Case:        command.Case, Operation: Import, Phase: Quarantined, CommandDigest: commandDigest,
		IntentDigest: intent, PackageDigest: &packageDigest, Artifacts: artifacts,
		UpdatedAt: service.clock.Now(), Revision: 1}
	progress.ProgressDigest, _ = ProgressBindingDigest(progress)
	stored, _, err := service.store.Advance(ctx, command.IdempotencyKey, intent, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "import_plan_unavailable", err)
	}
	if ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "import_progress_conflict", true, nil)
	}
	manifestDigest, signatureDigest, reportDigest := verified.Manifest.ManifestDigest,
		verified.Package.SignatureDigest, verified.Verification.ReportDigest
	stored.Phase, stored.ManifestDigest, stored.SignatureDigest, stored.VerificationReportDigest =
		Verified, &manifestDigest, &signatureDigest, &reportDigest
	stored, err = service.advanceImportValues(ctx, command, intent, stored)
	if err != nil {
		return Progress{}, err
	}
	return stored, nil
}

func (service *ImportService) authorizeImportProgress(ctx context.Context, state importState,
	stored Progress) (Progress, error) {
	stored.Phase, stored.DecisionDigest, stored.RevocationDigest = Authorized,
		&state.Decision.DecisionDigest, &state.Decision.RevocationDigest
	return service.advanceImport(ctx, state, stored)
}

func (service *ImportService) authorizeOrResumeImport(ctx context.Context, state importState,
	progress Progress) (Progress, importState, error) {
	switch progress.Phase {
	case Verified:
		stored, err := service.authorizeImportProgress(ctx, state, progress)
		return stored, state, err
	case Authorized, Published, Custodied:
		if progress.DecisionDigest == nil || progress.RevocationDigest == nil {
			return Progress{}, importState{}, newError(Denied, "import_recovered_authority_invalid", false, nil)
		}
		state.FinalDecisionDigest, state.FinalRevocationDigest =
			*progress.DecisionDigest, *progress.RevocationDigest
		return progress, state, nil
	default:
		return Progress{}, importState{}, newError(Conflict, "import_progress_phase_invalid", false, nil)
	}
}

func (service *ImportService) publishOrRecoverImport(ctx context.Context, state importState,
	progress Progress) (PublishedImport, Progress, error) {
	published, err := service.publishImportValue(ctx, state)
	if err != nil {
		return PublishedImport{}, Progress{}, err
	}
	if progress.Phase == Authorized {
		progress.Phase, progress.Artifacts = Published, cloneArtifactProgress(published.Progress)
		stored, err := service.advanceImport(ctx, state, progress)
		return published, stored, err
	}
	if (progress.Phase != Published && progress.Phase != Custodied) ||
		!publicationMatchesProgress(published, progress) {
		return PublishedImport{}, Progress{}, newError(Conflict, "import_publication_recovery_invalid", false, nil)
	}
	return published, progress, nil
}

func cloneArtifactProgress(values []ArtifactProgress) []ArtifactProgress {
	result := make([]ArtifactProgress, len(values))
	for index, value := range values {
		result[index] = value
		if value.IngestionReceiptDigest != nil {
			copyValue := *value.IngestionReceiptDigest
			result[index].IngestionReceiptDigest = &copyValue
		}
		if value.CustodyReceiptDigest != nil {
			copyValue := *value.CustodyReceiptDigest
			result[index].CustodyReceiptDigest = &copyValue
		}
	}
	return result
}

func (service *ImportService) publishImportValue(ctx context.Context,
	state importState) (PublishedImport, error) {
	now := service.clock.Now()
	if !validTime(now) || !now.Before(state.Command.Deadline) || !now.Before(state.Decision.ExpiresAt) {
		return PublishedImport{}, newError(Timeout, "import_authorization_expired", false, nil)
	}
	published, err := service.publisher.PublishImport(ctx, ImportPublicationRequest{
		RequestID: state.Command.RequestID, IdempotencyKey: state.Command.IdempotencyKey, Case: state.Command.Case,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision, Verified: state.Verified,
		PolicyDigest: state.Command.PolicyDigest, Deadline: state.Command.Deadline})
	if err != nil {
		return PublishedImport{}, mapExportDependency(ctx, "import_publication_unavailable", err)
	}
	if !validPublishedImport(published, state.Verified) {
		return PublishedImport{}, newError(Denied, "import_publication_invalid", false, nil)
	}
	return published, nil
}

func publicationMatchesProgress(published PublishedImport, progress Progress) bool {
	if len(published.Progress) != len(progress.Artifacts) {
		return false
	}
	for index, artifact := range progress.Artifacts {
		candidate := published.Progress[index]
		if artifact.Ordinal != candidate.Ordinal || artifact.ArtifactDigest != candidate.ArtifactDigest ||
			artifact.IngestionReceiptDigest == nil || candidate.IngestionReceiptDigest == nil ||
			*artifact.IngestionReceiptDigest != *candidate.IngestionReceiptDigest ||
			progress.Phase == Published && artifact.CustodyReceiptDigest != nil ||
			progress.Phase == Custodied && artifact.CustodyReceiptDigest == nil {
			return false
		}
	}
	return true
}

func (service *ImportService) custodyImport(ctx context.Context, state importState, published PublishedImport,
	progress Progress) (CustodyProofSet, Progress, error) {
	manifestDigest, signatureDigest := state.Verified.Manifest.ManifestDigest, state.Verified.Package.SignatureDigest
	request := CustodyRequest{Operation: Import, Phase: Completed, Case: state.Command.Case,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
		ArtifactSetDigest: state.Verified.Verification.ArtifactSetDigest, Subjects: published.Artifacts,
		ManifestDigest: &manifestDigest, PackageDigest: state.Command.PackageDigest, SourceDigest: state.Command.SourceDigest,
		SignatureDigest: &signatureDigest, PolicyDigest: state.Command.PolicyDigest,
		ExpectedCaseRevision: state.Case.Revision, ExpectedHead: state.Command.ExpectedCustodyHead,
		Deadline: state.Command.Deadline}
	proof, err := service.custody.RecordLifecycle(ctx, request)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "import_custody_unavailable", err)
	}
	if !validCustodyProofSet(proof, state.Command.Case, state.Command.ExpectedCustodyHead, len(published.Artifacts)) {
		return CustodyProofSet{}, Progress{}, newError(Denied, "import_custody_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil || !validCustodyVerification(verified, proof.Head) {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "import_custody_verification_unavailable", err)
	}
	for index := range progress.Artifacts {
		digest := proof.Proofs[index].ReceiptDigest
		progress.Artifacts[index].CustodyReceiptDigest = &digest
	}
	progress.Phase, progress.CompletionCustodyReceiptDigest = Custodied, &proof.ReceiptSetDigest
	stored, err := service.advanceImport(ctx, state, progress)
	return proof, stored, err
}

func (service *ImportService) custodyOrRecoverImport(ctx context.Context, state importState,
	published PublishedImport, progress Progress) (CustodyProofSet, Progress, error) {
	if progress.Phase == Published {
		return service.custodyImport(ctx, state, published, progress)
	}
	if progress.Phase != Custodied || progress.CompletionCustodyReceiptDigest == nil {
		return CustodyProofSet{}, Progress{}, newError(Conflict, "import_custody_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.custody.RecoverLifecycle(ctx, state.Command.Case,
		*progress.CompletionCustodyReceiptDigest)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "import_custody_recovery_unavailable", err)
	}
	if !found || !validCustodyProofSet(proof, state.Command.Case, state.Command.ExpectedCustodyHead,
		len(published.Artifacts)) || proof.ReceiptSetDigest != *progress.CompletionCustodyReceiptDigest ||
		!custodyMatchesProgress(proof, progress) {
		return CustodyProofSet{}, Progress{}, newError(Denied, "import_custody_recovery_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "import_custody_recovery_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, proof.Head) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"import_custody_recovery_verification_invalid", false, nil)
	}
	return proof, progress, nil
}

func custodyMatchesProgress(proof CustodyProofSet, progress Progress) bool {
	if len(proof.Proofs) != len(progress.Artifacts) {
		return false
	}
	for index, artifact := range progress.Artifacts {
		if artifact.CustodyReceiptDigest == nil || *artifact.CustodyReceiptDigest != proof.Proofs[index].ReceiptDigest {
			return false
		}
	}
	return true
}

func (service *ImportService) advanceImport(ctx context.Context, state importState,
	progress Progress) (Progress, error) {
	return service.advanceImportValues(ctx, state.Command, state.IntentDigest, progress)
}

func (service *ImportService) advanceImportValues(ctx context.Context, command Command, intent string,
	progress Progress) (Progress, error) {
	progress.Revision++
	progress.UpdatedAt, progress.ProgressDigest = service.clock.Now(), ""
	progress.ProgressDigest, _ = ProgressBindingDigest(progress)
	if ValidateProgress(progress) != nil {
		return Progress{}, newError(Unavailable, "import_progress_build_invalid", false, nil)
	}
	stored, _, err := service.store.Advance(ctx, command.IdempotencyKey, intent, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "import_progress_unavailable", err)
	}
	if ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "import_progress_conflict", true, nil)
	}
	return stored, nil
}
