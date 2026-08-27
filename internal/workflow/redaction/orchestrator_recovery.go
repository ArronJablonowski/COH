package redaction

import "context"

func (service *orchestrator) recoverOrPlan(ctx context.Context,
	state authorizedState) (Progress, *Receipt, error) {
	idempotency, err := IdempotencyBindingDigest(state.Command.IdempotencyKey)
	if err != nil {
		return Progress{}, nil, err
	}
	receipt, found, err := service.store.Recover(ctx, state.Command.Case, idempotency)
	if err != nil {
		return Progress{}, nil, mapDependency(ctx, "receipt_recovery_unavailable", err)
	}
	if found {
		if ValidateReceipt(receipt) != nil || receipt.Case != state.Command.Case ||
			receipt.IdempotencyDigest != idempotency || receipt.IntentDigest != state.IntentDigest {
			return Progress{}, nil, newError(Denied, "changed_replay", false, nil)
		}
		if err = service.verifyRecoveredAudit(ctx, receipt); err != nil {
			return Progress{}, nil, err
		}
		copyValue := cloneReceipt(receipt)
		return Progress{}, &copyValue, nil
	}
	planned := Progress{Case: state.Command.Case, IdempotencyDigest: idempotency, IntentDigest: state.IntentDigest,
		Phase: PhasePlanned, Revision: 1, PlanDigest: state.Plan.PlanDigest,
		DecisionDigest: state.Decision.DecisionDigest, ApprovalUseDigest: state.Approval.UseDigest,
		UpdatedAt: state.AuthorizedAt}
	progress, _, err := service.store.Advance(ctx, state.Command.IdempotencyKey, 0, planned)
	if err != nil {
		return Progress{}, nil, mapDependency(ctx, "progress_plan_unavailable", err)
	}
	if err = validateProgressForState(progress, state, idempotency); err != nil {
		return Progress{}, nil, err
	}
	return progress, nil, nil
}

func (service *orchestrator) publishOrResume(ctx context.Context, state authorizedState,
	progress Progress) (publicationResult, Progress, error) {
	if progress.Phase != PhasePlanned {
		published, err := publicationFromProgress(progress)
		return published, progress, err
	}
	published, err := service.derivation.deriveAndPublish(ctx, state)
	if err != nil {
		return publicationResult{}, Progress{}, err
	}
	now, err := service.nowBeforeRelease(state)
	if err != nil {
		return publicationResult{}, Progress{}, err
	}
	mappingDigest := published.Derivation.Mapping.MappingDigest
	next := cloneProgress(progress)
	next.Phase, next.Revision, next.DecisionDigest, next.UpdatedAt = PhasePublished, 2, state.Decision.DecisionDigest, now
	next.Derived, next.Mapping = clonePublished(&published.Derived), clonePublished(&published.Mapping)
	next.MappingDigest = &mappingDigest
	advanced, _, err := service.store.Advance(ctx, state.Command.IdempotencyKey, progress.Revision, next)
	if err != nil {
		return publicationResult{}, Progress{}, mapDependency(ctx, "progress_publish_unavailable", err)
	}
	if err = validateProgressForState(advanced, state, progress.IdempotencyDigest); err != nil {
		return publicationResult{}, Progress{}, err
	}
	storedPublication, err := publicationFromProgress(advanced)
	return storedPublication, advanced, err
}

func (service *orchestrator) custodyOrResume(ctx context.Context, state authorizedState,
	published publicationResult, progress Progress) (CustodyProof, Progress, error) {
	request := custodyRequestFor(state, published)
	if progress.Phase == PhaseCustodied {
		proof := *progress.Custody
		if err := service.custody.VerifyRedaction(ctx, request, proof); err != nil {
			return CustodyProof{}, Progress{}, mapDependency(ctx, "custody_verification_unavailable", err)
		}
		return proof, progress, nil
	}
	proof, err := service.recordCustody(ctx, state, published)
	if err != nil {
		return CustodyProof{}, Progress{}, err
	}
	now, err := service.nowBeforeRelease(state)
	if err != nil {
		return CustodyProof{}, Progress{}, err
	}
	next := cloneProgress(progress)
	next.Phase, next.Revision, next.DecisionDigest, next.UpdatedAt = PhaseCustodied, 3, state.Decision.DecisionDigest, now
	next.Custody = clonePointer(&proof)
	advanced, _, err := service.store.Advance(ctx, state.Command.IdempotencyKey, progress.Revision, next)
	if err != nil {
		return CustodyProof{}, Progress{}, mapDependency(ctx, "progress_custody_unavailable", err)
	}
	if err = validateProgressForState(advanced, state, progress.IdempotencyDigest); err != nil {
		return CustodyProof{}, Progress{}, err
	}
	return *advanced.Custody, advanced, nil
}

func publicationFromProgress(progress Progress) (publicationResult, error) {
	if validateProgress(progress) != nil || progress.Phase == PhasePlanned || progress.Derived == nil ||
		progress.Mapping == nil || progress.MappingDigest == nil {
		return publicationResult{}, newError(Denied, "published_progress_invalid", false, nil)
	}
	return publicationResult{Derivation: Derivation{DerivedArtifact: progress.Derived.Reference.Artifact,
		Mapping: Mapping{MappingDigest: *progress.MappingDigest}}, Derived: *clonePublished(progress.Derived),
		Mapping: *clonePublished(progress.Mapping)}, nil
}

func validateProgressForState(progress Progress, state authorizedState, idempotency string) error {
	if validateProgress(progress) != nil || progress.Case != state.Command.Case ||
		progress.IdempotencyDigest != idempotency || progress.IntentDigest != state.IntentDigest ||
		progress.PlanDigest != state.Plan.PlanDigest || progress.ApprovalUseDigest != state.Approval.UseDigest ||
		progress.Phase == PhaseCustodied && progress.DecisionDigest != state.Decision.DecisionDigest {
		return newError(Denied, "recovered_progress_invalid", false, nil)
	}
	return nil
}

func (service *orchestrator) verifyRecoveredAudit(ctx context.Context, receipt Receipt) error {
	eventID := deterministicUUID("COH-REDACTION-AUDIT-ID-V1\x00", receipt.RedactionID+"\x00completed")
	proof, err := service.auditor.VerifyRedactionEvent(ctx, receipt.Case, eventID, receipt.AuditEventDigest)
	if err != nil {
		return mapDependency(ctx, "audit_verification_unavailable", err)
	}
	if !validAuditProof(proof) || proof.EventDigest != receipt.AuditEventDigest {
		return newError(Denied, "audit_verification_invalid", false, nil)
	}
	return nil
}
