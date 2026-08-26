package caselifecycle

import (
	"math"
	"time"
)

func buildTransition(command Command, intent, idempotency string, current *Record,
	decision Decision, now time.Time) (Record, auditEvent, error) {
	if command.Operation == Create {
		return buildCreate(command, intent, idempotency, decision, now)
	}
	if current == nil || validateRecord(*current) != nil || current.Case != command.Case || current.State == Deleted {
		return Record{}, auditEvent{}, newError(Denied, "transition_state_invalid", false, nil)
	}
	next := cloneRecord(*current)
	next.PolicyDigest = command.PolicyDigest
	next.IntentDigest = intent
	next.IdempotencyDigest = idempotency
	next.DecisionDigest = decision.DecisionDigest
	next.RevocationDigest = decision.RevocationDigest
	next.PreviousProvenanceDigest = clonePointer(&current.ProvenanceDigest)
	next.UpdatedAt = now
	next.Revision = current.Revision + 1
	if next.Revision > math.MaxInt64 {
		return Record{}, auditEvent{}, newError(Conflict, "revision_exhausted", false, nil)
	}
	switch command.Operation {
	case Classify:
		if classificationRank(*command.TargetClassification) < classificationRank(current.Classification) {
			return Record{}, auditEvent{}, newError(Denied, "classification_reduction_denied", false, nil)
		}
		next.Classification = *command.TargetClassification
	case Assign:
		next.AssigneeActorID = *command.AssigneeActorID
	case PlaceHold:
		if current.LegalHold {
			return Record{}, auditEvent{}, newError(Denied, "case_already_held", false, nil)
		}
		next.LegalHold = true
		next.HoldReasonDigest = clonePointer(command.ReasonDigest)
	case ReleaseHold:
		if !current.LegalHold {
			return Record{}, auditEvent{}, newError(Denied, "case_not_held", false, nil)
		}
		next.LegalHold = false
		next.HoldReasonDigest = nil
	case Close:
		if current.State != Open {
			return Record{}, auditEvent{}, newError(Denied, "close_state_invalid", false, nil)
		}
		next.State = Closed
	case Reopen:
		if current.State != Closed {
			return Record{}, auditEvent{}, newError(Denied, "reopen_state_invalid", false, nil)
		}
		next.State = Open
	case Export:
		if current.ExportCount == math.MaxInt64 {
			return Record{}, auditEvent{}, newError(Conflict, "export_count_exhausted", false, nil)
		}
		next.LastExportManifestDigest = clonePointer(command.ExportManifestDigest)
		next.ExportCount++
	case Delete:
		if current.LegalHold {
			return Record{}, auditEvent{}, newError(Denied, "legal_hold_active", false, nil)
		}
		if now.Before(current.RetainUntil) {
			return Record{}, auditEvent{}, newError(Denied, "retention_active", false, nil)
		}
		next.State = Deleted
		next.DeletionReasonDigest = clonePointer(command.ReasonDigest)
		next.DeletedByActorID = clonePointer(&command.ActorID)
	default:
		return Record{}, auditEvent{}, newError(InvalidInput, "operation_invalid", false, nil)
	}
	return finalizeTransition(command, intent, decision, next, now)
}

func buildCreate(command Command, intent, idempotency string, decision Decision,
	now time.Time) (Record, auditEvent, error) {
	value := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion, Case: command.Case,
		CreatorActorID: command.ActorID, OwnerActorID: command.ActorID, AssigneeActorID: *command.AssigneeActorID,
		Classification: *command.TargetClassification, State: Open, RetentionPolicyID: *command.RetentionPolicyID,
		RetainUntil: *command.RetainUntil, PolicyDigest: command.PolicyDigest, IntentDigest: intent,
		IdempotencyDigest: idempotency, DecisionDigest: decision.DecisionDigest,
		RevocationDigest: decision.RevocationDigest, CreatedAt: now, UpdatedAt: now, Revision: 1}
	return finalizeTransition(command, intent, decision, value, now)
}

func finalizeTransition(command Command, intent string, decision Decision, value Record,
	now time.Time) (Record, auditEvent, error) {
	event, eventDigest, err := allowedEvent(command, intent, decision, value, now)
	if err != nil {
		return Record{}, auditEvent{}, err
	}
	value.AuditEventDigest = eventDigest
	value.ProvenanceDigest, err = RecordProvenanceDigest(value)
	if err != nil || validateRecord(value) != nil {
		return Record{}, auditEvent{}, newError(InternalFailure, "record_build_failed", false, err)
	}
	return value, event, nil
}
