package redaction

import (
	"context"
	"time"
)

type orchestrator struct {
	preflight  *preflight
	derivation *derivationService
	custody    CustodyRecorder
	store      Store
	auditor    Auditor
	clock      Clock
}

func newOrchestrator(preflight *preflight, derivation *derivationService, custody CustodyRecorder,
	store Store, auditor Auditor, clock Clock) (*orchestrator, error) {
	if preflight == nil || derivation == nil || custody == nil || store == nil || auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "orchestrator_dependencies_required", false, nil)
	}
	return &orchestrator{preflight, derivation, custody, store, auditor, clock}, nil
}

func (service *orchestrator) execute(ctx context.Context, command Command) (Result, error) {
	result, err := service.executeOperation(ctx, command)
	if err == nil {
		return result, nil
	}
	if auditErr := service.auditDenial(ctx, command, err); auditErr != nil {
		return Result{}, auditErr
	}
	return Result{}, err
}

func (service *orchestrator) executeOperation(ctx context.Context, command Command) (Result, error) {
	state, err := service.preflight.authorize(ctx, command)
	if err != nil {
		return Result{}, err
	}
	opCtx, cancel := context.WithTimeout(ctx, command.Deadline.Sub(state.AuthorizedAt))
	defer cancel()
	progress, recovered, err := service.recoverOrPlan(opCtx, state)
	if err != nil {
		return Result{}, err
	}
	if recovered != nil {
		return Result{Receipt: *recovered, Replayed: true}, nil
	}
	published, progress, err := service.publishOrResume(opCtx, state, progress)
	if err != nil {
		return Result{}, err
	}
	custody, progress, err := service.custodyOrResume(opCtx, state, published, progress)
	if err != nil {
		return Result{}, err
	}
	record, err := buildRedactionRecord(state, published, custody, progress.UpdatedAt)
	if err != nil {
		return Result{}, err
	}
	event, expectedEventDigest, err := completedRedactionEvent(record, custody)
	if err != nil {
		return Result{}, err
	}
	audit, err := service.appendAndVerifyAudit(ctx, command.Case, event, expectedEventDigest)
	if err != nil {
		return Result{}, err
	}
	record.AuditEventDigest = audit.EventDigest
	record.RecordDigest, err = RecordBindingDigest(record)
	if err != nil || ValidateRecord(record) != nil {
		return Result{}, newError(InternalFailure, "record_build_failed", false, err)
	}
	receipt, err := buildRedactionReceipt(state, record, progress.UpdatedAt)
	if err != nil {
		return Result{}, err
	}
	stored, replayed, err := service.store.Commit(opCtx, state.Command.IdempotencyKey, state.IntentDigest, record, receipt)
	if err != nil {
		return Result{}, mapDependency(opCtx, "redaction_commit_unavailable", err)
	}
	if ValidateReceipt(stored) != nil || stored.IntentDigest != state.IntentDigest ||
		stored.IdempotencyDigest != progress.IdempotencyDigest {
		return Result{}, newError(Denied, "stored_receipt_invalid", false, nil)
	}
	return Result{Receipt: stored, Replayed: replayed}, nil
}

func (service *orchestrator) nowBeforeRelease(state authorizedState) (time.Time, error) {
	now := service.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(InternalFailure, "clock_invalid", false, nil)
	}
	if !now.Before(state.Command.Deadline) || !now.Before(state.Decision.ExpiresAt) ||
		!now.Before(state.Plan.ValidUntil) || !now.Before(state.Approval.ValidUntil) {
		return time.Time{}, newError(Denied, "authorization_expired_before_custody", false, nil)
	}
	return now, nil
}

func (service *orchestrator) recordCustody(ctx context.Context, state authorizedState,
	published publicationResult) (CustodyProof, error) {
	request := custodyRequestFor(state, published)
	proof, _, err := service.custody.RecordRedaction(ctx, request)
	if err != nil {
		return CustodyProof{}, mapDependency(ctx, "custody_record_unavailable", err)
	}
	if !validCustodyProof(proof) {
		return CustodyProof{}, newError(Denied, "custody_proof_invalid", false, nil)
	}
	if err = service.custody.VerifyRedaction(ctx, request, proof); err != nil {
		return CustodyProof{}, mapDependency(ctx, "custody_verification_unavailable", err)
	}
	return proof, nil
}

func custodyRequestFor(state authorizedState, published publicationResult) CustodyRequest {
	return CustodyRequest{Command: cloneCommand(state.Command), Derived: published.Derived.Reference,
		MappingDigest: published.Derivation.Mapping.MappingDigest, ApprovalDigest: state.Approval.UseDigest,
		DecisionDigest: state.Decision.DecisionDigest, ExpectedHead: cloneHead(state.CustodyHead),
		Deadline: state.Command.Deadline}
}

func validCustodyProof(value CustodyProof) bool {
	return value.Sequence > 0 && allDigests(value.ReceiptDigest, value.RecordDigest, value.ChainHash, value.AuditDigest)
}
