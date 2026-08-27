package evidencelifecycle

import (
	"context"
	"time"
)

type exportState struct {
	Command               Command
	IntentDigest          string
	Case                  CaseSnapshot
	Evidence              VerifiedEvidenceSet
	Redactions            []RedactionProof
	Custody               CustodyVerification
	Decision              Decision
	FinalDecisionDigest   string
	FinalRevocationDigest string
	CurrentCaseRevision   uint64
	RecoveredPhase        Phase
	AuthorizedAt          time.Time
}

func (service *ExportService) preflight(ctx context.Context, command Command, intent string) (exportState, error) {
	return service.authorizeExport(ctx, command, intent, Progress{}, false)
}

func (service *ExportService) authorizeExport(ctx context.Context, command Command, intent string,
	progress Progress, recovery bool) (exportState, error) {
	current, found, err := service.cases.LoadCase(ctx, command.Case)
	if err != nil {
		return exportState{}, mapExportDependency(ctx, "case_load_unavailable", err)
	}
	if !found {
		return exportState{}, newError(NotFound, "case_not_found", false, nil)
	}
	if !validCaseSnapshot(current) || current.Case != command.Case || current.State == "deleted" ||
		!recovery && current.Revision != command.ExpectedCaseRevision || recovery && progress.Phase != CaseRecorded &&
		current.Revision != command.ExpectedCaseRevision {
		return exportState{}, newError(Denied, "case_state_invalid", false, nil)
	}
	pending, err := service.cases.HasIncompleteHoldRelease(ctx, command.Case)
	if err != nil {
		return exportState{}, mapExportDependency(ctx, "hold_state_unavailable", err)
	}
	if pending {
		return exportState{}, newError(Denied, string(ReasonHoldReleaseIncomplete), false, nil)
	}
	evidence, err := service.evidence.ResolveEvidenceSet(ctx, command.Case, *command.ArtifactSetDigest)
	if err != nil {
		return exportState{}, mapExportDependency(ctx, "evidence_resolution_unavailable", err)
	}
	if !validVerifiedEvidenceSet(evidence, command, current.Classification) {
		return exportState{}, newError(Denied, "evidence_set_invalid", false, nil)
	}
	redactions, err := service.redactions.VerifyRedactionReceipts(ctx, command.Case, evidence)
	if err != nil {
		return exportState{}, mapExportDependency(ctx, "redaction_verification_unavailable", err)
	}
	if !validRedactionProofs(evidence, redactions) {
		return exportState{}, newError(Denied, "redaction_proof_invalid", false, nil)
	}
	head, err := service.custody.LoadCustodyHead(ctx, command.Case)
	if err != nil {
		return exportState{}, mapExportDependency(ctx, "custody_head_unavailable", err)
	}
	if !recovery && (!sameHead(head, command.ExpectedCustodyHead) || head.Sequence == 0) ||
		recovery && (head.Sequence < command.ExpectedCustodyHead.Sequence || command.ExpectedCustodyHead.Sequence == 0) {
		return exportState{}, newError(Conflict, string(ReasonStaleCustody), true, nil)
	}
	custody, err := service.custody.VerifyLifecycle(ctx, command.Case, 1, head.Sequence)
	if err != nil {
		return exportState{}, mapExportDependency(ctx, "custody_verification_unavailable", err)
	}
	if !validCustodyVerification(custody, head) {
		return exportState{}, newError(Denied, "custody_verification_invalid", false, nil)
	}
	originalCustody := custody
	if recovery {
		originalCustody, err = service.custody.VerifyLifecycle(ctx, command.Case, 1,
			command.ExpectedCustodyHead.Sequence)
		if err != nil {
			return exportState{}, mapExportDependency(ctx, "export_original_custody_unavailable", err)
		}
		if !validCustodyVerification(originalCustody, command.ExpectedCustodyHead) {
			return exportState{}, newError(Denied, "export_original_custody_invalid", false, nil)
		}
	}
	authorizationCommand, authorizationIntent := command, intent
	if recovery {
		authorizationCommand.ExpectedCaseRevision, authorizationCommand.ExpectedCustodyHead = current.Revision, head
		authorizationIntent, err = IntentBindingDigest(authorizationCommand)
		if err != nil {
			return exportState{}, err
		}
	}
	authorization := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: authorizationIntent, Command: authorizationCommand, CaseState: current.State,
		CaseClassification: current.Classification,
		CaseRevision:       current.Revision, RetainUntil: current.RetainUntil, LegalHold: current.LegalHold,
		HoldReleasePending: pending, CaseProvenanceDigest: current.ProvenanceDigest,
		ArtifactSetDigest: authorizationCommand.ArtifactSetDigest, CurrentCustodyHead: head}
	if recovery {
		authorization.ProgressDigest = &progress.ProgressDigest
	}
	authorization.AuthorizationDigest, err = AuthorizationBindingDigest(authorization)
	if err != nil || ValidateAuthorization(authorization) != nil {
		return exportState{}, newError(Denied, "export_authorization_invalid", false, err)
	}
	decision, err := service.authority.AuthorizeEvidenceLifecycle(ctx, authorization)
	if err != nil {
		return exportState{}, mapExportDependency(ctx, "export_authority_unavailable", err)
	}
	now := service.clock.Now()
	if !validExportDecision(decision, authorization, now) {
		return exportState{}, newError(Denied, "export_decision_invalid", false, nil)
	}
	state := exportState{Command: command, IntentDigest: intent, Case: current, Evidence: evidence,
		Redactions: redactions, Custody: originalCustody, Decision: decision,
		FinalDecisionDigest: decision.DecisionDigest, FinalRevocationDigest: decision.RevocationDigest,
		CurrentCaseRevision: current.Revision, AuthorizedAt: now}
	if recovery && progress.DecisionDigest != nil && progress.RevocationDigest != nil {
		state.FinalDecisionDigest, state.FinalRevocationDigest = *progress.DecisionDigest, *progress.RevocationDigest
	}
	if recovery {
		state.RecoveredPhase = progress.Phase
	}
	return state, nil
}
