package broker

import (
	"context"
	"time"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

func (service *approvalService) commit(ctx context.Context, operation, idempotencyKey string, expectedRevision uint64,
	record lifecycle.Record, actor policy.ActorAuthority, fingerprint approvalfingerprint.Fingerprint, now time.Time) (approvalResult, error) {
	metadata, err := metadataRecord(record)
	if err != nil {
		return approvalResult{}, service.failure(ctx, operation, record.ApprovalID, actor, fingerprint, expectedRevision, err, now)
	}
	transaction := workflow.Transaction{ContractVersion: workflow.StorageContractVersion, IdempotencyKey: idempotencyKey,
		Mutations: []workflow.Mutation{{Kind: workflow.MutationPut, Key: metadata.Key,
			ExpectedRevision: expectedRevision, Record: &metadata}},
		Outbox: []workflow.OutboxMessage{{ID: record.LastEventID, Case: metadata.Key.Case,
			Topic: "approval." + operation, PayloadRef: "record:approval:" + record.ApprovalID + ":" + uintText(record.Revision),
			PayloadDigest: metadata.Digest}}}
	result, err := service.store.Transact(ctx, transaction)
	if err != nil {
		resultErr := mapStorageError(err)
		return approvalResult{}, service.failure(ctx, operation, record.ApprovalID, actor, fingerprint, expectedRevision, resultErr, now)
	}
	return approvalResult{Record: record, Replayed: result.Replayed}, nil
}

func (service *approvalService) failure(ctx context.Context, operation, approvalID string, actor policy.ActorAuthority,
	fingerprint approvalfingerprint.Fingerprint, revision uint64, resultErr error, now time.Time) error {
	if resultErr == nil {
		resultErr = lifecycle.NewError(lifecycle.Unavailable, "approval_lifecycle_unavailable")
	}
	eventID, idErr := service.newEventID(now)
	if idErr != nil {
		return lifecycle.NewError(lifecycle.Unavailable, "audit_unavailable")
	}
	outcome := "denied"
	switch lifecycle.Code(resultErr) {
	case lifecycle.InvalidInput:
		outcome = "invalid"
	case lifecycle.Canceled:
		outcome = "canceled"
	case lifecycle.Timeout:
		outcome = "timeout"
	case lifecycle.Unavailable:
		outcome = "unavailable"
	}
	event := lifecycle.Event{SchemaVersion: lifecycle.SchemaVersion, ContractVersion: lifecycle.ContractVersion,
		EventID: eventID, Operation: operation, Outcome: outcome, ReasonCode: lifecycle.Reason(resultErr),
		ApprovalID: safeUUID(approvalID), OrganizationID: safeUUID(fingerprint.OrganizationID),
		TenantID: safeUUID(fingerprint.TenantID), CaseID: safeUUID(fingerprint.CaseID),
		FingerprintDigest: safeDigest(fingerprint.FingerprintDigest), ActorID: safeUUID(actor.ActorID),
		ActorRevision: actor.Revision, RecordRevision: revision, OccurredAt: formatTime(now)}
	if event.ActorID == "" {
		event.ActorRevision = 0
	}
	if err := lifecycle.ValidateEvent(event); err != nil {
		return lifecycle.NewError(lifecycle.Unavailable, "audit_unavailable")
	}
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if service == nil || service.audit == nil || service.audit.AppendApprovalLifecycleEvent(auditCtx, event) != nil {
		return lifecycle.NewError(lifecycle.Unavailable, "audit_unavailable")
	}
	return resultErr
}

func safeUUID(value string) string {
	if uuidPattern.MatchString(value) {
		return value
	}
	return ""
}

func safeDigest(value string) string {
	if digestPattern.MatchString(value) {
		return value
	}
	return ""
}

func uintText(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}
