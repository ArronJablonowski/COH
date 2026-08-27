package custody

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func (controller *Controller) loadCase(ctx context.Context, scope domain.CaseRef) (CaseSnapshot, error) {
	current, found, err := controller.cases.LoadCase(ctx, scope)
	if err != nil {
		return CaseSnapshot{}, mapDependency(ctx, "case_load_unavailable", err)
	}
	if !found {
		return CaseSnapshot{}, newError(NotFound, "case_not_found", false, nil)
	}
	if !validCaseSnapshot(current) || current.Case != scope {
		return CaseSnapshot{}, newError(Denied, "case_snapshot_invalid", false, nil)
	}
	return current, nil
}

func (controller *Controller) loadHead(ctx context.Context, scope domain.CaseRef) (Head, error) {
	head, err := controller.ledger.LoadHead(ctx, scope)
	if err != nil {
		return Head{}, mapDependency(ctx, "custody_head_unavailable", err)
	}
	if !validHead(head) || head.Case != scope {
		return Head{}, newError(Denied, "custody_head_invalid", false, nil)
	}
	return head, nil
}

func (controller *Controller) previousProvenance(ctx context.Context, head Head) (*string, error) {
	if head.Sequence == 0 {
		return nil, nil
	}
	record, err := controller.readOne(ctx, head.Case, head.Sequence)
	if err != nil {
		return nil, err
	}
	if record.Sequence != head.Sequence || record.ChainHash != head.ChainHash ||
		head.LastRecordAt == nil || !record.OccurredAt.Equal(*head.LastRecordAt) {
		return nil, newError(Denied, "custody_head_record_invalid", false, nil)
	}
	return clonePointer(&record.ProvenanceDigest), nil
}

func (controller *Controller) loadReceiptRecord(ctx context.Context, receipt Receipt, command Command,
	intent, idempotency string) (Record, error) {
	if err := validateReceipt(receipt); err != nil {
		return Record{}, err
	}
	record, err := controller.readOne(ctx, receipt.Case, receipt.Sequence)
	if err != nil {
		return Record{}, err
	}
	if err = validateReceiptRecord(receipt, record, command, intent, idempotency); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (controller *Controller) readOne(ctx context.Context, scope domain.CaseRef, sequence uint64) (Record, error) {
	values, err := controller.ledger.Read(ctx, scope, sequence-1, 1)
	if err != nil {
		return Record{}, mapDependency(ctx, "custody_record_unavailable", err)
	}
	if len(values) != 1 || values[0].Sequence != sequence || validateRecord(values[0]) != nil {
		return Record{}, newError(Denied, "custody_record_invalid", false, nil)
	}
	return cloneRecord(values[0]), nil
}

func (controller *Controller) verifyRecordToHead(ctx context.Context, first Record, head Head) error {
	if first.Case != head.Case || first.Sequence > head.Sequence {
		return newError(Denied, "custody_interval_invalid", false, nil)
	}
	after := first.Sequence - 1
	expectedSequence, expectedHash := first.Sequence, first.PreviousChainHash
	var last Record
	for expectedSequence <= head.Sequence {
		batch, err := controller.ledger.Read(ctx, head.Case, after, custodyReadBatch)
		if err != nil {
			return mapDependency(ctx, "custody_interval_unavailable", err)
		}
		if len(batch) == 0 || len(batch) > int(custodyReadBatch) {
			return newError(Denied, "custody_interval_incomplete", false, nil)
		}
		for _, record := range batch {
			if expectedSequence > head.Sequence || validateRecord(record) != nil ||
				record.Sequence != expectedSequence || record.PreviousChainHash != expectedHash {
				return newError(Denied, "custody_interval_integrity", false, nil)
			}
			if record.Sequence == first.Sequence && record.RecordDigest != first.RecordDigest {
				return newError(Denied, "custody_receipt_record_changed", false, nil)
			}
			last, expectedHash = record, record.ChainHash
			expectedSequence++
			after = record.Sequence
			if expectedSequence > head.Sequence {
				break
			}
		}
	}
	if last.Sequence != head.Sequence || last.ChainHash != head.ChainHash || head.LastRecordAt == nil ||
		!last.OccurredAt.Equal(*head.LastRecordAt) {
		return newError(Denied, "custody_durable_head_invalid", false, nil)
	}
	return nil
}

func (controller *Controller) verifyLifecycle(ctx context.Context, command Command,
	current CaseSnapshot, now time.Time) error {
	if current.State == "deleted" && !(command.Operation == Delete && command.Phase == Completed) {
		return newError(Denied, "case_state_denied", false, nil)
	}
	if command.Operation == Delete && command.Phase == Authorized {
		if current.LegalHold {
			return newError(Denied, "legal_hold_active", false, nil)
		}
		if now.Before(current.RetainUntil) {
			return newError(Denied, "retention_active", false, nil)
		}
		return nil
	}
	if command.LifecycleReceiptDigest == nil {
		return nil
	}
	receipt, found, err := controller.cases.ResolveLifecycleReceipt(ctx, command.Case,
		*command.LifecycleReceiptDigest)
	if err != nil {
		return mapDependency(ctx, "lifecycle_receipt_unavailable", err)
	}
	if !found || !validLifecycleReceipt(receipt) || receipt.Case != command.Case ||
		receipt.ReceiptDigest != *command.LifecycleReceiptDigest || receipt.Revision != current.Revision {
		return newError(Denied, "lifecycle_receipt_invalid", false, nil)
	}
	switch command.Operation {
	case PlaceHold:
		if receipt.Operation != "place_hold" || !receipt.LegalHold || !current.LegalHold {
			return newError(Denied, "hold_receipt_invalid", false, nil)
		}
	case ReleaseHold:
		if receipt.Operation != "release_hold" || receipt.LegalHold || current.LegalHold {
			return newError(Denied, "hold_release_receipt_invalid", false, nil)
		}
	case Delete:
		if command.Phase != Completed || receipt.Operation != "delete" || receipt.LegalHold ||
			current.LegalHold || current.State != "deleted" {
			return newError(Denied, "deletion_receipt_invalid", false, nil)
		}
	default:
		return newError(Denied, "lifecycle_operation_invalid", false, nil)
	}
	return nil
}

func (controller *Controller) verifyPriorAuthorization(ctx context.Context, command Command, head Head) error {
	if command.PriorAuthorizationDigest == nil {
		return nil
	}
	receipt, found, err := controller.ledger.ResolveReceipt(ctx, command.Case, *command.PriorAuthorizationDigest)
	if err != nil {
		return mapDependency(ctx, "prior_authorization_unavailable", err)
	}
	if !found || validateReceipt(receipt) != nil || receipt.Case != command.Case ||
		receipt.ReceiptDigest != *command.PriorAuthorizationDigest {
		return newError(Denied, "prior_authorization_invalid", false, nil)
	}
	record, err := controller.readOne(ctx, receipt.Case, receipt.Sequence)
	if err != nil {
		return err
	}
	if err = validateReceiptRecordDirect(receipt, record); err != nil {
		return err
	}
	if err = controller.verifyRecordToHead(ctx, record, head); err != nil {
		return err
	}
	prior := record.Command
	if prior.Phase != Authorized || prior.Operation != command.Operation || prior.Case != command.Case ||
		prior.Subject != command.Subject || prior.PolicyDigest != command.PolicyDigest ||
		!sameOptionalDigest(prior.PurposeDigest, command.PurposeDigest) ||
		!sameOptionalDigest(prior.DestinationDigest, command.DestinationDigest) ||
		!sameOptionalDigest(prior.RecipientDigest, command.RecipientDigest) ||
		!sameOptionalDigest(prior.ReasonDigest, command.ReasonDigest) ||
		!sameOptionalDigest(prior.ArtifactSetDigest, command.ArtifactSetDigest) {
		return newError(Denied, "prior_authorization_scope_changed", false, nil)
	}
	return nil
}

func (controller *Controller) verifyAudit(ctx context.Context, receipt Receipt, appended AuditProof) error {
	proof, err := controller.auditor.VerifyCustodyEvent(ctx, receipt.Case,
		receipt.AuditEventDigest, receipt.RecordDigest)
	if err != nil {
		return mapDependency(ctx, "audit_verification_unavailable", err)
	}
	if !validAuditProof(proof) || proof.EventDigest != receipt.AuditEventDigest ||
		proof.EventDigest != appended.EventDigest || proof.Sequence != appended.Sequence ||
		proof.ChainHash != appended.ChainHash {
		return newError(Denied, "audit_verification_invalid", false, nil)
	}
	return nil
}

func validateReceiptRecord(receipt Receipt, record Record, command Command, intent, idempotency string) error {
	if err := validateReceiptRecordDirect(receipt, record); err != nil {
		return err
	}
	if receipt.Case != command.Case ||
		receipt.IdempotencyDigest != idempotency || receipt.IntentDigest != intent || record.IntentDigest != intent ||
		receipt.RequestID != command.RequestID || record.Command.RequestID != command.RequestID {
		return newError(Denied, "receipt_record_binding_invalid", false, nil)
	}
	recordIntent, err := CommandBindingDigest(record.Command)
	if err != nil || recordIntent != intent || IdempotencyBindingDigest(record.Command.IdempotencyKey) != idempotency {
		return newError(Denied, "receipt_command_binding_invalid", false, err)
	}
	return nil
}

func validateReceiptRecordDirect(receipt Receipt, record Record) error {
	if validateReceipt(receipt) != nil || validateRecord(record) != nil || receipt.Case != record.Case ||
		receipt.RequestID != record.Command.RequestID || receipt.IntentDigest != record.IntentDigest ||
		receipt.DecisionDigest != record.DecisionDigest || receipt.CustodyID != record.CustodyID ||
		receipt.Sequence != record.Sequence || receipt.RecordDigest != record.RecordDigest ||
		receipt.ChainHash != record.ChainHash || receipt.AuditEventDigest != record.AuditEventDigest ||
		receipt.ProvenanceDigest != record.ProvenanceDigest || !receipt.CreatedAt.Equal(record.OccurredAt) {
		return newError(Denied, "receipt_record_binding_invalid", false, nil)
	}
	return nil
}

func sameOptionalDigest(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validCaseSnapshot(value CaseSnapshot) bool {
	return validCase(value.Case) && validCaseState(value.State) && validClassification(value.Classification) &&
		value.Revision > 0 && allDigests(value.RetentionPolicyDigest, value.ProvenanceDigest) &&
		validTime(value.RetainUntil)
}

func validLifecycleReceipt(value LifecycleReceiptSnapshot) bool {
	return validCase(value.Case) && (value.Operation == "place_hold" || value.Operation == "release_hold" ||
		value.Operation == "delete") && value.Revision > 0 &&
		allDigests(value.ReceiptDigest, value.ProvenanceDigest)
}
