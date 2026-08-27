package evidencelifecycle

import (
	"context"
	"time"
)

func (service *HoldService) applyOrRecoverHold(ctx context.Context, state holdState,
	progress Progress) (LifecycleProof, Progress, holdState, error) {
	if progress.Phase == Planned {
		now := service.clock.Now()
		if !validTime(now) || !now.Before(state.Command.Deadline) || !now.Before(state.Decision.ExpiresAt) {
			return LifecycleProof{}, Progress{}, holdState{}, newError(Timeout, "hold_authorization_expired", false, nil)
		}
		idempotency, _ := IdempotencyBindingDigest(state.Command.IdempotencyKey)
		proof, err := service.lifecycle.ApplyCaseOperation(ctx, LifecycleRequest{Operation: state.Command.Operation,
			Case: state.Command.Case, ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
			ExpectedCaseRevision: state.Command.ExpectedCaseRevision, ReasonDigest: state.Command.ReasonDigest,
			PolicyDigest: state.Command.PolicyDigest, IdempotencyDigest: idempotency,
			Deadline: state.Command.Deadline})
		if err != nil {
			return LifecycleProof{}, Progress{}, holdState{}, mapExportDependency(ctx, "hold_case_transition_unavailable", err)
		}
		if !validLifecycleProof(proof, state.Command.Case, state.Command.Operation) ||
			proof.Revision != state.Command.ExpectedCaseRevision+1 ||
			state.Command.Operation == PlaceHold && !proof.LegalHold ||
			state.Command.Operation == ReleaseHold && proof.LegalHold {
			return LifecycleProof{}, Progress{}, holdState{}, newError(Denied, "hold_case_transition_invalid", false, nil)
		}
		resolved, found, err := service.cases.ResolveLifecycleReceipt(ctx, state.Command.Case, proof.ReceiptDigest)
		if err != nil {
			return LifecycleProof{}, Progress{}, holdState{}, mapExportDependency(ctx, "hold_case_receipt_unavailable", err)
		}
		if !found || resolved != proof {
			return LifecycleProof{}, Progress{}, holdState{}, newError(Denied, "hold_case_receipt_invalid", false, nil)
		}
		progress.Phase, progress.DecisionDigest, progress.RevocationDigest = CaseRecorded,
			&state.Decision.DecisionDigest, &state.Decision.RevocationDigest
		progress.LifecycleReceiptDigest = &proof.ReceiptDigest
		stored, err := service.advanceHold(ctx, state, progress)
		return proof, stored, state, err
	}
	if (progress.Phase != CaseRecorded && progress.Phase != Custodied) || progress.LifecycleReceiptDigest == nil ||
		progress.DecisionDigest == nil || progress.RevocationDigest == nil {
		return LifecycleProof{}, Progress{}, holdState{}, newError(Conflict, "hold_progress_phase_invalid", false, nil)
	}
	proof, found, err := service.cases.ResolveLifecycleReceipt(ctx, state.Command.Case,
		*progress.LifecycleReceiptDigest)
	if err != nil {
		return LifecycleProof{}, Progress{}, holdState{}, mapExportDependency(ctx, "hold_case_recovery_unavailable", err)
	}
	if !found || !validLifecycleProof(proof, state.Command.Case, state.Command.Operation) ||
		proof.ReceiptDigest != *progress.LifecycleReceiptDigest || proof.Revision != state.Case.Revision ||
		state.Command.Operation == PlaceHold && !proof.LegalHold ||
		state.Command.Operation == ReleaseHold && proof.LegalHold {
		return LifecycleProof{}, Progress{}, holdState{}, newError(Denied, "hold_case_recovery_invalid", false, nil)
	}
	state.FinalDecisionDigest, state.FinalRevocationDigest = *progress.DecisionDigest, *progress.RevocationDigest
	return proof, progress, state, nil
}

func (service *HoldService) custodyOrRecoverHold(ctx context.Context, state holdState, lifecycle LifecycleProof,
	progress Progress) (CustodyProofSet, Progress, error) {
	if progress.Phase == CaseRecorded {
		request := CustodyRequest{Operation: state.Command.Operation, Phase: Completed, Case: state.Command.Case,
			ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
			ArtifactSetDigest: state.Evidence.ArtifactSetDigest, Subjects: evidenceReferences(state.Evidence.Artifacts),
			ReasonDigest: state.Command.ReasonDigest, LifecycleReceiptDigest: &lifecycle.ReceiptDigest,
			PolicyDigest: state.Command.PolicyDigest, ExpectedCaseRevision: lifecycle.Revision,
			ExpectedHead: state.InitialHead, Deadline: state.Command.Deadline}
		proof, err := service.custody.RecordLifecycle(ctx, request)
		if err != nil {
			return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "hold_custody_unavailable", err)
		}
		if !validCustodyProofSet(proof, state.Command.Case, state.InitialHead, len(state.Evidence.Artifacts)) {
			return CustodyProofSet{}, Progress{}, newError(Denied, "hold_custody_invalid", false, nil)
		}
		verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
		if err != nil {
			return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "hold_custody_verification_unavailable", err)
		}
		if !validCustodyVerification(verified, proof.Head) {
			return CustodyProofSet{}, Progress{}, newError(Denied, "hold_custody_verification_invalid", false, nil)
		}
		progress.Phase, progress.CompletionCustodyReceiptDigest = Custodied, &proof.ReceiptSetDigest
		stored, err := service.advanceHold(ctx, state, progress)
		return proof, stored, err
	}
	if progress.Phase != Custodied || progress.CompletionCustodyReceiptDigest == nil {
		return CustodyProofSet{}, Progress{}, newError(Conflict, "hold_custody_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.custody.RecoverLifecycle(ctx, state.Command.Case,
		*progress.CompletionCustodyReceiptDigest)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "hold_custody_recovery_unavailable", err)
	}
	if !found || proof.ReceiptSetDigest != *progress.CompletionCustodyReceiptDigest ||
		!validCustodyProofSet(proof, state.Command.Case, state.InitialHead, len(state.Evidence.Artifacts)) {
		return CustodyProofSet{}, Progress{}, newError(Denied, "hold_custody_recovery_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx, "hold_custody_recovery_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, proof.Head) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"hold_custody_recovery_verification_invalid", false, nil)
	}
	return proof, progress, nil
}

func (service *HoldService) advanceHold(ctx context.Context, state holdState,
	progress Progress) (Progress, error) {
	progress.Revision++
	progress.UpdatedAt, progress.ProgressDigest = service.clock.Now(), ""
	progress.ProgressDigest, _ = ProgressBindingDigest(progress)
	if ValidateProgress(progress) != nil {
		return Progress{}, newError(Unavailable, "hold_progress_build_invalid", false, nil)
	}
	stored, _, err := service.store.Advance(ctx, state.Command.IdempotencyKey, state.IntentDigest, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "hold_progress_unavailable", err)
	}
	if ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "hold_progress_conflict", true, nil)
	}
	return stored, nil
}

func (service *HoldService) loadHoldProgress(ctx context.Context, command Command, intent,
	idempotency string) (Progress, bool, error) {
	progress, found, err := service.store.LoadProgress(ctx, command.Case, idempotency)
	if err != nil {
		return Progress{}, false, mapExportDependency(ctx, "hold_progress_recovery_unavailable", err)
	}
	if found && !validRecoveredHoldProgress(progress, command, intent) {
		return Progress{}, false, newError(Conflict, string(ReasonChangedReplay), false, nil)
	}
	return progress, found, nil
}

func validRecoveredHoldProgress(value Progress, command Command, intent string) bool {
	commandDigest, err := CommandBindingDigest(command)
	return err == nil && ValidateProgress(value) == nil && value.Operation == command.Operation &&
		value.Case == command.Case && value.CommandDigest == commandDigest && value.IntentDigest == intent &&
		value.OperationID == deterministicUUID("COH-EVIDENCE-HOLD-OPERATION-ID-V1\x00",
			command.RequestID+"\x00"+intent) &&
		(value.Phase == Planned || value.Phase == CaseRecorded || value.Phase == Custodied) &&
		len(value.Artifacts) == 0
}

func (service *HoldService) authorizeHold(ctx context.Context, command Command, intent string,
	progress Progress, recovery bool) (holdState, error) {
	current, found, err := service.cases.LoadCase(ctx, command.Case)
	if err != nil {
		return holdState{}, mapExportDependency(ctx, "hold_case_unavailable", err)
	}
	if !found || !validCaseSnapshot(current) || current.Case != command.Case || current.State == "deleted" {
		return holdState{}, newError(Denied, "hold_case_invalid", false, nil)
	}
	pending, err := service.cases.HasIncompleteHoldRelease(ctx, command.Case)
	if err != nil {
		return holdState{}, mapExportDependency(ctx, "hold_pending_state_unavailable", err)
	}
	if pending && !(recovery && command.Operation == ReleaseHold) {
		return holdState{}, newError(Denied, string(ReasonHoldReleaseIncomplete), false, nil)
	}
	evidence, err := service.evidence.ResolveEvidenceSet(ctx, command.Case, *command.ArtifactSetDigest)
	if err != nil {
		return holdState{}, mapExportDependency(ctx, "hold_evidence_unavailable", err)
	}
	if !validVerifiedEvidenceSet(evidence, command, current.Classification) {
		return holdState{}, newError(Denied, "hold_evidence_invalid", false, nil)
	}
	head, err := service.custody.LoadCustodyHead(ctx, command.Case)
	if err != nil {
		return holdState{}, mapExportDependency(ctx, "hold_custody_head_unavailable", err)
	}
	if !recovery && (!sameHead(head, command.ExpectedCustodyHead) || current.Revision != command.ExpectedCaseRevision ||
		command.Operation == PlaceHold && current.LegalHold || command.Operation == ReleaseHold && !current.LegalHold) {
		return holdState{}, newError(Conflict, "hold_state_conflict", true, nil)
	}
	authorizationCommand, authorizationIntent := command, intent
	if recovery {
		authorizationCommand.ExpectedCaseRevision, authorizationCommand.ExpectedCustodyHead = current.Revision, head
		authorizationIntent, err = IntentBindingDigest(authorizationCommand)
		if err != nil {
			return holdState{}, err
		}
	}
	authorization := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: authorizationIntent, Command: authorizationCommand, CaseState: current.State,
		CaseClassification: current.Classification, CaseRevision: current.Revision, RetainUntil: current.RetainUntil,
		LegalHold: current.LegalHold, HoldReleasePending: pending, CaseProvenanceDigest: current.ProvenanceDigest,
		ArtifactSetDigest: authorizationCommand.ArtifactSetDigest, CurrentCustodyHead: head}
	if recovery {
		authorization.ProgressDigest = &progress.ProgressDigest
	}
	authorization.AuthorizationDigest, err = AuthorizationBindingDigest(authorization)
	if err != nil || ValidateAuthorization(authorization) != nil {
		return holdState{}, newError(Denied, "hold_authorization_invalid", false, err)
	}
	decision, err := service.authority.AuthorizeEvidenceLifecycle(ctx, authorization)
	if err != nil {
		return holdState{}, mapExportDependency(ctx, "hold_authority_unavailable", err)
	}
	now := service.clock.Now()
	if !validHoldDecision(decision, authorization, now) {
		return holdState{}, newError(Denied, "hold_decision_invalid", false, nil)
	}
	state := holdState{Command: command, IntentDigest: intent, Case: current, Evidence: evidence,
		Decision: decision, FinalDecisionDigest: decision.DecisionDigest,
		FinalRevocationDigest: decision.RevocationDigest, InitialHead: command.ExpectedCustodyHead, AuthorizedAt: now}
	if recovery && progress.DecisionDigest != nil && progress.RevocationDigest != nil {
		state.FinalDecisionDigest, state.FinalRevocationDigest = *progress.DecisionDigest, *progress.RevocationDigest
	}
	return state, nil
}

func (service *HoldService) planHold(ctx context.Context, state holdState) (Progress, error) {
	commandDigest, _ := CommandBindingDigest(state.Command)
	progress := Progress{SchemaVersion: ProgressSchemaVersion, ContractVersion: ContractVersion,
		OperationID: deterministicUUID("COH-EVIDENCE-HOLD-OPERATION-ID-V1\x00",
			state.Command.RequestID+"\x00"+state.IntentDigest), Case: state.Command.Case,
		Operation: state.Command.Operation, Phase: Planned, CommandDigest: commandDigest,
		IntentDigest: state.IntentDigest, UpdatedAt: state.AuthorizedAt, Revision: 1}
	progress.ProgressDigest, _ = ProgressBindingDigest(progress)
	stored, _, err := service.store.Advance(ctx, state.Command.IdempotencyKey, state.IntentDigest, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "hold_plan_unavailable", err)
	}
	if ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "hold_progress_conflict", true, nil)
	}
	return stored, nil
}

func validHoldDecision(value Decision, authorization AuthorizationRequest, now time.Time) bool {
	command := authorization.Command
	return ValidateDecision(value) == nil && value.Outcome == Allow && value.ReasonCode == ReasonAuthorized &&
		value.AuthorizationDigest == authorization.AuthorizationDigest && value.IntentDigest == authorization.IntentDigest &&
		value.Operation == command.Operation && value.Case == command.Case && value.ActorID == command.ActorID &&
		value.ActorRevision == command.ActorRevision && value.ArtifactSetDigest != nil &&
		authorization.ArtifactSetDigest != nil && *value.ArtifactSetDigest == *authorization.ArtifactSetDigest &&
		value.PackageDigest == nil && value.ApprovalDigest == nil && value.PolicyDigest == command.PolicyDigest &&
		value.ExpectedCaseRevision == authorization.CaseRevision &&
		sameHead(value.ExpectedCustodyHead, authorization.CurrentCustodyHead) && validTime(now) &&
		!now.Before(value.IssuedAt) && now.Before(value.ExpiresAt) && !value.ExpiresAt.After(command.Deadline)
}
