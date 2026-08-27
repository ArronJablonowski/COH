package evidencelifecycle

import (
	"context"
	"time"
)

func (service *DeleteService) loadDeleteProgress(ctx context.Context, command Command, intent,
	idempotency string) (Progress, bool, error) {
	progress, found, err := service.store.LoadProgress(ctx, command.Case, idempotency)
	if err != nil {
		return Progress{}, false, mapExportDependency(ctx, "delete_progress_recovery_unavailable", err)
	}
	if found && !validRecoveredDeleteProgress(progress, command, intent) {
		return Progress{}, false, newError(Conflict, string(ReasonChangedReplay), false, nil)
	}
	return progress, found, nil
}

func validRecoveredDeleteProgress(value Progress, command Command, intent string) bool {
	commandDigest, err := CommandBindingDigest(command)
	if err != nil || ValidateProgress(value) != nil || value.Operation != Delete || value.Case != command.Case ||
		value.CommandDigest != commandDigest || value.IntentDigest != intent || value.OperationID !=
		deterministicUUID("COH-EVIDENCE-DELETE-OPERATION-ID-V1\x00", command.RequestID+"\x00"+intent) ||
		len(value.Artifacts) != 0 {
		return false
	}
	return value.Phase == Planned || value.Phase == Authorized || value.Phase == Tombstoned ||
		value.Phase == Disposed || value.Phase == Custodied
}

func (service *DeleteService) authorizeDelete(ctx context.Context, command Command, intent string,
	progress Progress, recovery bool) (deleteState, error) {
	current, found, err := service.cases.LoadCase(ctx, command.Case)
	if err != nil {
		return deleteState{}, mapExportDependency(ctx, "delete_case_unavailable", err)
	}
	if !found || !validCaseSnapshot(current) || current.Case != command.Case {
		return deleteState{}, newError(Denied, "delete_case_invalid", false, nil)
	}
	pending, err := service.cases.HasIncompleteHoldRelease(ctx, command.Case)
	if err != nil {
		return deleteState{}, mapExportDependency(ctx, "delete_hold_state_unavailable", err)
	}
	now := service.clock.Now()
	if current.LegalHold || pending {
		return deleteState{}, newError(Denied, string(ReasonLegalHoldActive), false, nil)
	}
	if now.Before(current.RetainUntil) {
		return deleteState{}, newError(Denied, string(ReasonRetentionActive), false, nil)
	}
	evidence, err := service.evidence.ResolveEvidenceSet(ctx, command.Case, *command.ArtifactSetDigest)
	if err != nil {
		return deleteState{}, mapExportDependency(ctx, "delete_evidence_unavailable", err)
	}
	if !validVerifiedEvidenceSet(evidence, command, current.Classification) {
		return deleteState{}, newError(Denied, "delete_evidence_invalid", false, nil)
	}
	head, err := service.custody.LoadCustodyHead(ctx, command.Case)
	if err != nil {
		return deleteState{}, mapExportDependency(ctx, "delete_custody_head_unavailable", err)
	}
	if !recovery && (current.State == "deleted" || current.Revision != command.ExpectedCaseRevision ||
		!sameHead(head, command.ExpectedCustodyHead) || head.Sequence == 0) {
		return deleteState{}, newError(Conflict, "delete_state_conflict", true, nil)
	}
	if recovery && progress.Phase == Planned && current.State == "deleted" {
		return deleteState{}, newError(Conflict, "delete_untracked_tombstone", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, command.Case, 1, head.Sequence)
	if err != nil {
		return deleteState{}, mapExportDependency(ctx, "delete_custody_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, head) {
		return deleteState{}, newError(Denied, "delete_custody_verification_invalid", false, nil)
	}
	authorizationCommand, authorizationIntent := command, intent
	if recovery {
		authorizationCommand.ExpectedCaseRevision, authorizationCommand.ExpectedCustodyHead = current.Revision, head
		authorizationIntent, err = IntentBindingDigest(authorizationCommand)
		if err != nil {
			return deleteState{}, err
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
		return deleteState{}, newError(Denied, "delete_authorization_invalid", false, err)
	}
	decision, err := service.authority.AuthorizeEvidenceLifecycle(ctx, authorization)
	if err != nil {
		return deleteState{}, mapExportDependency(ctx, "delete_authority_unavailable", err)
	}
	if !validDeleteDecision(decision, authorization, now) {
		return deleteState{}, newError(Denied, "delete_decision_invalid", false, nil)
	}
	state := deleteState{Command: command, IntentDigest: intent, Case: current, Evidence: evidence,
		Decision: decision, FinalDecisionDigest: decision.DecisionDigest,
		FinalRevocationDigest: decision.RevocationDigest, InitialHead: command.ExpectedCustodyHead, AuthorizedAt: now}
	if recovery && progress.DecisionDigest != nil && progress.RevocationDigest != nil {
		state.FinalDecisionDigest, state.FinalRevocationDigest = *progress.DecisionDigest, *progress.RevocationDigest
	}
	return state, nil
}

func validDeleteDecision(value Decision, authorization AuthorizationRequest, now time.Time) bool {
	command := authorization.Command
	return ValidateDecision(value) == nil && value.Outcome == Allow && value.ReasonCode == ReasonAuthorized &&
		value.AuthorizationDigest == authorization.AuthorizationDigest && value.IntentDigest == authorization.IntentDigest &&
		value.Operation == Delete && value.Case == command.Case && value.ActorID == command.ActorID &&
		value.ActorRevision == command.ActorRevision && value.ArtifactSetDigest != nil &&
		authorization.ArtifactSetDigest != nil && *value.ArtifactSetDigest == *authorization.ArtifactSetDigest &&
		value.PackageDigest == nil && value.ApprovalDigest != nil && command.ApprovalDigest != nil &&
		*value.ApprovalDigest == *command.ApprovalDigest && value.PolicyDigest == command.PolicyDigest &&
		value.ExpectedCaseRevision == authorization.CaseRevision &&
		sameHead(value.ExpectedCustodyHead, authorization.CurrentCustodyHead) && validTime(now) &&
		!now.Before(value.IssuedAt) && now.Before(value.ExpiresAt) && !value.ExpiresAt.After(command.Deadline)
}
