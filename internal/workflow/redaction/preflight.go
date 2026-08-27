package redaction

import (
	"context"
	"errors"
	"time"
)

type preflight struct {
	authority Authority
	approvals ApprovalStore
	cases     CaseStore
	plans     PlanStore
	sources   SourceResolver
	custody   CustodyRecorder
	clock     Clock
}

type authorizedState struct {
	Command       Command
	IntentDigest  string
	Case          CaseSnapshot
	Rule          RuleSet
	Plan          ApprovedPlan
	Source        VerifiedSource
	Approval      ApprovalUseProof
	Authorization AuthorizationRequest
	Decision      Decision
	CustodyHead   CustodyHead
	AuthorizedAt  time.Time
}

func newPreflight(authority Authority, approvals ApprovalStore, cases CaseStore, plans PlanStore,
	sources SourceResolver, custody CustodyRecorder, clock Clock) (*preflight, error) {
	if authority == nil || approvals == nil || cases == nil || plans == nil || sources == nil || custody == nil || clock == nil {
		return nil, newError(InvalidInput, "preflight_dependencies_required", false, nil)
	}
	return &preflight{authority, approvals, cases, plans, sources, custody, clock}, nil
}

func (service *preflight) authorize(ctx context.Context, command Command) (authorizedState, error) {
	if err := contextError(ctx); err != nil {
		return authorizedState{}, err
	}
	now, err := service.currentTime()
	if err != nil {
		return authorizedState{}, err
	}
	if err = ValidateCommand(command, now); err != nil {
		return authorizedState{}, err
	}
	opCtx, cancel := context.WithTimeout(ctx, command.Deadline.Sub(now))
	defer cancel()
	intent, err := IntentBindingDigest(command)
	if err != nil {
		return authorizedState{}, err
	}
	current, rule, plan, source, head, err := service.resolveCurrent(opCtx, command, now)
	if err != nil {
		return authorizedState{}, err
	}
	approval, err := service.authorizeApproval(opCtx, command, plan, intent, now)
	if err != nil {
		return authorizedState{}, err
	}
	// Approval use is the only state-changing preflight step. Re-resolve every
	// other dependency afterward so no earlier snapshot can authorize plaintext.
	current, rule, plan, source, head, err = service.resolveCurrent(opCtx, command, now)
	if err != nil {
		return authorizedState{}, err
	}
	if err = service.verifyApproval(opCtx, approval, command, plan, intent, now); err != nil {
		return authorizedState{}, err
	}
	request := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: cloneCommand(command), Plan: clonePlan(plan), CaseState: current.State,
		CaseClassification: current.Classification, CaseRevision: current.Revision,
		CaseProvenanceDigest: current.ProvenanceDigest, SourceVerificationDigest: source.VerificationDigest,
		ApprovalUse: approval, CurrentCustodyHead: cloneHead(head)}
	request.AuthorizationDigest, err = AuthorizationBindingDigest(request)
	if err != nil || ValidateAuthorization(request) != nil {
		return authorizedState{}, newError(InternalFailure, "authorization_build_failed", false, err)
	}
	decision, err := service.authority.AuthorizeRedaction(opCtx, cloneAuthorization(request))
	if err != nil {
		return authorizedState{}, mapDependency(opCtx, "authority_unavailable", err)
	}
	authorizedAt, err := service.currentTime()
	if err != nil {
		return authorizedState{}, err
	}
	if err = validateBoundDecision(decision, request, authorizedAt); err != nil {
		return authorizedState{}, err
	}
	if decision.Outcome != Allow {
		return authorizedState{}, newError(Denied, string(decision.ReasonCode), false, nil)
	}
	return authorizedState{cloneCommand(command), intent, current, cloneRule(rule), clonePlan(plan), source,
		approval, cloneAuthorization(request), cloneDecision(decision), cloneHead(head), authorizedAt}, nil
}

func (service *preflight) currentTime() (time.Time, error) {
	now := service.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(InternalFailure, "clock_invalid", false, nil)
	}
	return now, nil
}

func mapDependency(ctx context.Context, reason string, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	return newError(Unavailable, reason, true, err)
}
