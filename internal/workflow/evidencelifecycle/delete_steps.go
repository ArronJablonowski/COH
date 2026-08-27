package evidencelifecycle

import "context"

func (service *DeleteService) planDelete(ctx context.Context, state deleteState) (Progress, error) {
	commandDigest, _ := CommandBindingDigest(state.Command)
	progress := Progress{SchemaVersion: ProgressSchemaVersion, ContractVersion: ContractVersion,
		OperationID: deterministicUUID("COH-EVIDENCE-DELETE-OPERATION-ID-V1\x00",
			state.Command.RequestID+"\x00"+state.IntentDigest), Case: state.Command.Case, Operation: Delete,
		Phase: Planned, CommandDigest: commandDigest, IntentDigest: state.IntentDigest,
		UpdatedAt: state.AuthorizedAt, Revision: 1}
	progress.ProgressDigest, _ = ProgressBindingDigest(progress)
	stored, _, err := service.store.Advance(ctx, state.Command.IdempotencyKey, state.IntentDigest, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "delete_plan_unavailable", err)
	}
	if ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "delete_progress_conflict", true, nil)
	}
	return stored, nil
}

func (service *DeleteService) authorizeCustodyOrRecoverDelete(ctx context.Context, state deleteState,
	progress Progress) (CustodyProofSet, Progress, deleteState, error) {
	if progress.Phase == Planned {
		now := service.clock.Now()
		if !validTime(now) || !now.Before(state.Command.Deadline) || !now.Before(state.Decision.ExpiresAt) {
			return CustodyProofSet{}, Progress{}, deleteState{}, newError(Timeout,
				"delete_authorization_expired", false, nil)
		}
		request := CustodyRequest{Operation: Delete, Phase: Authorized, Case: state.Command.Case,
			ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
			ArtifactSetDigest: state.Evidence.ArtifactSetDigest, Subjects: evidenceReferences(state.Evidence.Artifacts),
			ReasonDigest: state.Command.ReasonDigest, ApprovalDigest: state.Command.ApprovalDigest,
			PolicyDigest: state.Command.PolicyDigest, ExpectedCaseRevision: state.Command.ExpectedCaseRevision,
			ExpectedHead: state.InitialHead, Deadline: state.Command.Deadline}
		proof, err := service.custody.RecordLifecycle(ctx, request)
		if err != nil {
			return CustodyProofSet{}, Progress{}, deleteState{}, mapExportDependency(ctx,
				"delete_authorization_custody_unavailable", err)
		}
		if !validCustodyProofSet(proof, state.Command.Case, state.InitialHead, len(state.Evidence.Artifacts)) {
			return CustodyProofSet{}, Progress{}, deleteState{}, newError(Denied,
				"delete_authorization_custody_invalid", false, nil)
		}
		verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
		if err != nil {
			return CustodyProofSet{}, Progress{}, deleteState{}, mapExportDependency(ctx,
				"delete_authorization_custody_verification_unavailable", err)
		}
		if !validCustodyVerification(verified, proof.Head) {
			return CustodyProofSet{}, Progress{}, deleteState{}, newError(Denied,
				"delete_authorization_custody_verification_invalid", false, nil)
		}
		progress.Phase, progress.DecisionDigest, progress.RevocationDigest = Authorized,
			&state.Decision.DecisionDigest, &state.Decision.RevocationDigest
		progress.AuthorizationCustodyReceiptDigest = &proof.ReceiptSetDigest
		stored, err := service.advanceDelete(ctx, state, progress)
		return proof, stored, state, err
	}
	if progress.AuthorizationCustodyReceiptDigest == nil || progress.DecisionDigest == nil ||
		progress.RevocationDigest == nil {
		return CustodyProofSet{}, Progress{}, deleteState{}, newError(Conflict,
			"delete_authorization_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.custody.RecoverLifecycle(ctx, state.Command.Case,
		*progress.AuthorizationCustodyReceiptDigest)
	if err != nil {
		return CustodyProofSet{}, Progress{}, deleteState{}, mapExportDependency(ctx,
			"delete_authorization_custody_recovery_unavailable", err)
	}
	if !found || proof.ReceiptSetDigest != *progress.AuthorizationCustodyReceiptDigest ||
		!validCustodyProofSet(proof, state.Command.Case, state.InitialHead, len(state.Evidence.Artifacts)) {
		return CustodyProofSet{}, Progress{}, deleteState{}, newError(Denied,
			"delete_authorization_custody_recovery_invalid", false, nil)
	}
	state.FinalDecisionDigest, state.FinalRevocationDigest = *progress.DecisionDigest, *progress.RevocationDigest
	return proof, progress, state, nil
}

func (service *DeleteService) tombstoneOrRecoverDelete(ctx context.Context, state deleteState,
	authorization CustodyProofSet, progress Progress) (LifecycleProof, Progress, error) {
	if progress.Phase == Authorized {
		idempotency, _ := IdempotencyBindingDigest(state.Command.IdempotencyKey)
		proof, err := service.lifecycle.ApplyCaseOperation(ctx, LifecycleRequest{Operation: Delete,
			Case: state.Command.Case, ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
			ExpectedCaseRevision: state.Command.ExpectedCaseRevision, ReasonDigest: state.Command.ReasonDigest,
			PolicyDigest: state.Command.PolicyDigest, IdempotencyDigest: idempotency,
			Deadline: state.Command.Deadline})
		if err != nil {
			return LifecycleProof{}, Progress{}, mapExportDependency(ctx, "delete_tombstone_unavailable", err)
		}
		if !validLifecycleProof(proof, state.Command.Case, Delete) || proof.LegalHold ||
			proof.Revision != state.Command.ExpectedCaseRevision+1 {
			return LifecycleProof{}, Progress{}, newError(Denied, "delete_tombstone_invalid", false, nil)
		}
		resolved, found, err := service.cases.ResolveLifecycleReceipt(ctx, state.Command.Case, proof.ReceiptDigest)
		if err != nil {
			return LifecycleProof{}, Progress{}, mapExportDependency(ctx, "delete_tombstone_receipt_unavailable", err)
		}
		if !found || resolved != proof {
			return LifecycleProof{}, Progress{}, newError(Denied, "delete_tombstone_receipt_invalid", false, nil)
		}
		progress.Phase, progress.LifecycleReceiptDigest = Tombstoned, &proof.ReceiptDigest
		stored, err := service.advanceDelete(ctx, state, progress)
		return proof, stored, err
	}
	if progress.LifecycleReceiptDigest == nil {
		return LifecycleProof{}, Progress{}, newError(Conflict, "delete_tombstone_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.cases.ResolveLifecycleReceipt(ctx, state.Command.Case,
		*progress.LifecycleReceiptDigest)
	if err != nil {
		return LifecycleProof{}, Progress{}, mapExportDependency(ctx, "delete_tombstone_recovery_unavailable", err)
	}
	if !found || !validLifecycleProof(proof, state.Command.Case, Delete) || proof.LegalHold ||
		proof.ReceiptDigest != *progress.LifecycleReceiptDigest || proof.Revision != state.Command.ExpectedCaseRevision+1 {
		return LifecycleProof{}, Progress{}, newError(Denied, "delete_tombstone_recovery_invalid", false, nil)
	}
	_ = authorization
	return proof, progress, nil
}

func (service *DeleteService) advanceDelete(ctx context.Context, state deleteState,
	progress Progress) (Progress, error) {
	progress.Revision++
	progress.UpdatedAt, progress.ProgressDigest = service.clock.Now(), ""
	progress.ProgressDigest, _ = ProgressBindingDigest(progress)
	if ValidateProgress(progress) != nil {
		return Progress{}, newError(Unavailable, "delete_progress_build_invalid", false, nil)
	}
	stored, _, err := service.store.Advance(ctx, state.Command.IdempotencyKey, state.IntentDigest, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "delete_progress_unavailable", err)
	}
	if ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "delete_progress_conflict", true, nil)
	}
	return stored, nil
}
