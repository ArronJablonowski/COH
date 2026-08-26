package caselifecycle

import (
	"context"
	"errors"
	"time"
)

type Controller struct {
	authority Authority
	auditor   Auditor
	store     Store
	clock     Clock
}

func New(authority Authority, auditor Auditor, store Store, clock Clock) (*Controller, error) {
	if authority == nil || auditor == nil || store == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	return &Controller{authority: authority, auditor: auditor, store: store, clock: clock}, nil
}

func (controller *Controller) Execute(ctx context.Context, command Command) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateCommand(command, now); err != nil {
		return Result{}, err
	}
	opCtx, cancel := operationContext(ctx, command.Deadline, now)
	defer cancel()
	intent, err := CommandBindingDigest(command)
	if err != nil {
		return Result{}, err
	}
	idempotency := IdempotencyBindingDigest(command.IdempotencyKey)
	recovered, found, err := controller.store.Recover(opCtx, command.Case, idempotency)
	if err != nil {
		return Result{}, mapDependency(opCtx, "receipt_recovery_unavailable", err)
	}
	if found {
		return controller.replay(opCtx, command, intent, idempotency, recovered, now)
	}
	current, exists, err := controller.store.Load(opCtx, command.Case)
	if err != nil {
		return Result{}, mapDependency(opCtx, "case_load_unavailable", err)
	}
	if exists && (validateRecord(current) != nil || current.Case != command.Case) {
		return Result{}, controller.deny(ctx, command, intent, Decision{}, "stored_record_invalid", now, current.Revision)
	}
	if command.Operation == Create && exists {
		return Result{}, controller.deny(ctx, command, intent, Decision{}, "case_already_exists", now, current.Revision)
	}
	if command.Operation != Create && !exists {
		return Result{}, controller.deny(ctx, command, intent, Decision{}, "case_not_found", now, 0)
	}
	if (!exists && command.ExpectedRevision != 0) || (exists && current.Revision != command.ExpectedRevision) {
		return Result{}, controller.deny(ctx, command, intent, Decision{}, "stale_revision", now, current.Revision)
	}
	decision, err := controller.authorize(opCtx, command, intent, currentPointer(current, exists), now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != "allow" {
		return Result{}, controller.deny(ctx, command, intent, decision, decision.ReasonCode, now, command.ExpectedRevision)
	}
	next, event, err := buildTransition(command, intent, idempotency, currentPointer(current, exists), decision, now)
	if err != nil {
		return Result{}, controller.deny(ctx, command, intent, decision, Reason(err), now, command.ExpectedRevision)
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: command.RequestID, Operation: command.Operation, Case: command.Case,
		IntentDigest: intent, IdempotencyDigest: idempotency, DecisionDigest: decision.DecisionDigest,
		RevocationDigest: decision.RevocationDigest, AuditEventDigest: next.AuditEventDigest,
		Command: cloneCommand(command), Record: cloneRecord(next), CreatedAt: now}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || validateReceipt(receipt) != nil {
		return Result{}, newError(InternalFailure, "receipt_build_failed", false, err)
	}
	stored, replayed, err := controller.store.Commit(opCtx, command.IdempotencyKey, intent,
		command.ExpectedRevision, next, receipt)
	if err != nil {
		return Result{}, mapDependency(opCtx, "case_commit_unavailable", err)
	}
	if err = validateStoredReceipt(stored, command, intent, idempotency); err != nil {
		return Result{}, err
	}
	if replayed {
		event, err = allowedEventFromReceipt(stored)
		if err != nil {
			return Result{}, err
		}
	}
	if err = controller.appendAudit(ctx, event); err != nil {
		return Result{}, err
	}
	if replayed {
		if err = controller.appendAudit(ctx, replayEvent(command, decision, stored, now)); err != nil {
			return Result{}, err
		}
	}
	return resultFromReceipt(stored, replayed), nil
}

func (controller *Controller) replay(ctx context.Context, command Command, intent, idempotency string,
	receipt Receipt, now time.Time) (Result, error) {
	if err := validateStoredReceipt(receipt, command, intent, idempotency); err != nil {
		return Result{}, controller.deny(ctx, command, intent, Decision{}, Reason(err), now, command.ExpectedRevision)
	}
	var current *Record
	if command.Operation != Create {
		value := cloneRecord(receipt.Record)
		current = &value
	}
	decision, err := controller.authorize(ctx, command, intent, current, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != "allow" {
		return Result{}, controller.deny(ctx, command, intent, decision, decision.ReasonCode, now, receipt.Record.Revision)
	}
	event, err := allowedEventFromReceipt(receipt)
	if err != nil {
		return Result{}, err
	}
	if err = controller.appendAudit(ctx, event); err != nil {
		return Result{}, err
	}
	if err = controller.appendAudit(ctx, replayEvent(command, decision, receipt, now)); err != nil {
		return Result{}, err
	}
	return resultFromReceipt(receipt, true), nil
}

func (controller *Controller) authorize(ctx context.Context, command Command, intent string,
	current *Record, now time.Time) (Decision, error) {
	request := authorizationFor(command, intent, current)
	request.AuthorizationDigest, _ = AuthorizationBindingDigest(request)
	if err := validateAuthorization(request); err != nil {
		return Decision{}, err
	}
	decision, err := controller.authority.AuthorizeCase(ctx, request)
	if err != nil {
		return Decision{}, mapDependency(ctx, "authority_unavailable", err)
	}
	if validateDecision(decision) != nil || decision.AuthorizationDigest != request.AuthorizationDigest ||
		decision.IntentDigest != intent || decision.Operation != command.Operation || decision.Case != command.Case ||
		decision.ActorID != command.ActorID || decision.ActorRevision != command.ActorRevision ||
		decision.ExpectedRevision != command.ExpectedRevision || decision.PolicyDigest != command.PolicyDigest ||
		decision.IssuedAt.After(now) || !decision.ExpiresAt.After(now) || decision.ExpiresAt.After(command.Deadline) {
		return Decision{}, newError(Denied, "decision_binding_invalid", false, nil)
	}
	return decision, nil
}

func authorizationFor(command Command, intent string, current *Record) AuthorizationRequest {
	value := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: cloneCommand(command)}
	if current != nil {
		value.CurrentState = clonePointer(&current.State)
		value.CurrentClassification = clonePointer(&current.Classification)
		value.CurrentAssigneeActorID = clonePointer(&current.AssigneeActorID)
		value.CurrentLegalHold = clonePointer(&current.LegalHold)
		value.CurrentRetainUntil = clonePointer(&current.RetainUntil)
		value.CurrentProvenanceDigest = clonePointer(&current.ProvenanceDigest)
	}
	return value
}

func validateStoredReceipt(value Receipt, command Command, intent, idempotency string) error {
	if validateReceipt(value) != nil || value.RequestID != command.RequestID || value.Operation != command.Operation ||
		value.Case != command.Case || value.IntentDigest != intent || value.IdempotencyDigest != idempotency {
		return newError(Denied, "stored_receipt_invalid", false, nil)
	}
	return nil
}

func resultFromReceipt(value Receipt, replayed bool) Result {
	return Result{Record: cloneRecord(value.Record), Receipt: cloneReceipt(value), Replayed: replayed}
}

func currentPointer(value Record, found bool) *Record {
	if !found {
		return nil
	}
	copyValue := cloneRecord(value)
	return &copyValue
}

func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(InternalFailure, "clock_invalid", false, nil)
	}
	return now, nil
}

func operationContext(ctx context.Context, deadline, now time.Time) (context.Context, context.CancelFunc) {
	remaining := deadline.Sub(now)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, remaining)
}

func mapDependency(ctx context.Context, reason string, err error) error {
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "request_canceled", false, context.Canceled)
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
	}
	if CodeOf(err) != Unavailable {
		return err
	}
	return newError(Unavailable, reason, true, nil)
}
