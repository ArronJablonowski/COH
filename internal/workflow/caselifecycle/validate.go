package caselifecycle

import (
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

func validateCommand(value Command, now time.Time) error {
	if err := validateCommandShape(value); err != nil {
		return err
	}
	if !value.Deadline.After(now) {
		return newError(InvalidInput, "command_deadline_invalid", false, nil)
	}
	if value.Operation == Create && !value.RetainUntil.After(now) {
		return newError(Denied, "retention_invalid", false, nil)
	}
	return nil
}

func validateCommandShape(value Command) error {
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey, 1, 256) ||
		!validOperation(value.Operation) || !validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) ||
		value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		!digestPattern.MatchString(value.PolicyDigest) || value.ExpectedRevision > math.MaxInt64 ||
		!validTime(value.Deadline) {
		return newError(InvalidInput, "command_invalid", false, nil)
	}
	if pointerValid(value.TargetClassification, validClassification) != nil ||
		pointerValid(value.AssigneeActorID, uuidPattern.MatchString) != nil ||
		pointerValid(value.RetentionPolicyID, uuidPattern.MatchString) != nil ||
		pointerTimeValid(value.RetainUntil) != nil || pointerValid(value.ReasonDigest, digestPattern.MatchString) != nil ||
		pointerValid(value.ExportManifestDigest, digestPattern.MatchString) != nil {
		return newError(InvalidInput, "command_field_invalid", false, nil)
	}
	createFields := value.TargetClassification != nil && value.AssigneeActorID != nil &&
		value.RetentionPolicyID != nil && value.RetainUntil != nil && value.ReasonDigest == nil &&
		value.ExportManifestDigest == nil && value.ExpectedRevision == 0
	classifyFields := value.TargetClassification != nil && noCommandPointers(value, "classification")
	assignFields := value.AssigneeActorID != nil && noCommandPointers(value, "assignee")
	reasonFields := value.ReasonDigest != nil && noCommandPointers(value, "reason")
	exportFields := value.ExportManifestDigest != nil && noCommandPointers(value, "export")
	emptyFields := noCommandPointers(value, "")
	switch value.Operation {
	case Create:
		if !createFields {
			return newError(InvalidInput, "create_fields_invalid", false, nil)
		}
	case Classify:
		if value.ExpectedRevision == 0 || !classifyFields {
			return newError(InvalidInput, "classify_fields_invalid", false, nil)
		}
	case Assign:
		if value.ExpectedRevision == 0 || !assignFields {
			return newError(InvalidInput, "assign_fields_invalid", false, nil)
		}
	case PlaceHold, ReleaseHold, Delete:
		if value.ExpectedRevision == 0 || !reasonFields {
			return newError(InvalidInput, "reason_fields_invalid", false, nil)
		}
	case Export:
		if value.ExpectedRevision == 0 || !exportFields {
			return newError(InvalidInput, "export_fields_invalid", false, nil)
		}
	case Close, Reopen:
		if value.ExpectedRevision == 0 || !emptyFields {
			return newError(InvalidInput, "transition_fields_invalid", false, nil)
		}
	default:
		return newError(InvalidInput, "operation_invalid", false, nil)
	}
	return nil
}

func noCommandPointers(value Command, allowed string) bool {
	return (allowed == "classification" || value.TargetClassification == nil) &&
		(allowed == "assignee" || value.AssigneeActorID == nil) &&
		value.RetentionPolicyID == nil && value.RetainUntil == nil &&
		(allowed == "reason" || value.ReasonDigest == nil) &&
		(allowed == "export" || value.ExportManifestDigest == nil)
}

func validateAuthorization(value AuthorizationRequest) error {
	if err := validateAuthorizationShape(value, true); err != nil {
		return err
	}
	expected, err := AuthorizationBindingDigest(value)
	if err != nil || value.AuthorizationDigest != expected {
		return newError(Denied, "authorization_digest_invalid", false, nil)
	}
	return nil
}

func validateAuthorizationShape(value AuthorizationRequest, bound bool) error {
	if value.SchemaVersion != AuthorizationSchemaVersion || value.ContractVersion != ContractVersion ||
		(bound && !digestPattern.MatchString(value.AuthorizationDigest)) || (!bound && value.AuthorizationDigest != "") ||
		!digestPattern.MatchString(value.IntentDigest) || validateCommandShape(value.Command) != nil {
		return newError(InvalidInput, "authorization_invalid", false, nil)
	}
	commandDigest, err := CommandBindingDigest(value.Command)
	if err != nil || commandDigest != value.IntentDigest {
		return newError(Denied, "authorization_intent_invalid", false, nil)
	}
	currentMissing := value.CurrentState == nil && value.CurrentClassification == nil &&
		value.CurrentAssigneeActorID == nil && value.CurrentLegalHold == nil &&
		value.CurrentRetainUntil == nil && value.CurrentProvenanceDigest == nil
	currentComplete := value.CurrentState != nil && validState(*value.CurrentState) &&
		value.CurrentClassification != nil && validClassification(*value.CurrentClassification) &&
		value.CurrentAssigneeActorID != nil && uuidPattern.MatchString(*value.CurrentAssigneeActorID) &&
		value.CurrentLegalHold != nil && value.CurrentRetainUntil != nil && validTime(*value.CurrentRetainUntil) &&
		value.CurrentProvenanceDigest != nil && digestPattern.MatchString(*value.CurrentProvenanceDigest)
	if value.Command.Operation == Create && !currentMissing || value.Command.Operation != Create && !currentComplete {
		return newError(InvalidInput, "authorization_current_invalid", false, nil)
	}
	return nil
}

func validateDecision(value Decision) error {
	if err := validateDecisionShape(value, true); err != nil {
		return err
	}
	expected, err := DecisionBindingDigest(value)
	if err != nil || value.DecisionDigest != expected {
		return newError(Denied, "decision_digest_invalid", false, nil)
	}
	return nil
}

func validateDecisionShape(value Decision, bound bool) error {
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.DecisionID) ||
		(bound && !digestPattern.MatchString(value.DecisionDigest)) || (!bound && value.DecisionDigest != "") ||
		!digestPattern.MatchString(value.AuthorizationDigest) || !digestPattern.MatchString(value.IntentDigest) ||
		!validOperation(value.Operation) || !validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) ||
		value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 || value.ExpectedRevision > math.MaxInt64 ||
		!digestPattern.MatchString(value.PolicyDigest) || !digestPattern.MatchString(value.RevocationDigest) ||
		(value.Outcome != "allow" && value.Outcome != "deny") || !tokenPattern.MatchString(value.ReasonCode) ||
		!validTime(value.IssuedAt) || !validTime(value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) ||
		value.Revision == 0 || value.Revision > math.MaxInt64 {
		return newError(Denied, "decision_invalid", false, nil)
	}
	return nil
}

func validateRecord(value Record) error {
	if err := validateRecordShape(value, true); err != nil {
		return err
	}
	expected, err := RecordProvenanceDigest(value)
	if err != nil || expected != value.ProvenanceDigest {
		return newError(Denied, "record_provenance_invalid", false, nil)
	}
	return nil
}

func validateRecordShape(value Record, bound bool) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.CreatorActorID) ||
		value.OwnerActorID != value.CreatorActorID || !uuidPattern.MatchString(value.AssigneeActorID) ||
		!validClassification(value.Classification) || !validState(value.State) ||
		!uuidPattern.MatchString(value.RetentionPolicyID) || !validTime(value.RetainUntil) ||
		!digestPattern.MatchString(value.PolicyDigest) || !digestPattern.MatchString(value.IntentDigest) ||
		!digestPattern.MatchString(value.IdempotencyDigest) || !digestPattern.MatchString(value.DecisionDigest) ||
		!digestPattern.MatchString(value.RevocationDigest) || !digestPattern.MatchString(value.AuditEventDigest) ||
		(bound && !digestPattern.MatchString(value.ProvenanceDigest)) || (!bound && value.ProvenanceDigest != "") ||
		!validTime(value.CreatedAt) || !validTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) ||
		!value.RetainUntil.After(value.CreatedAt) || value.Revision == 0 || value.Revision > math.MaxInt64 {
		return newError(Denied, "record_invalid", false, nil)
	}
	if value.LegalHold != (value.HoldReasonDigest != nil) ||
		pointerValid(value.HoldReasonDigest, digestPattern.MatchString) != nil ||
		pointerValid(value.LastExportManifestDigest, digestPattern.MatchString) != nil ||
		pointerValid(value.DeletionReasonDigest, digestPattern.MatchString) != nil ||
		pointerValid(value.DeletedByActorID, uuidPattern.MatchString) != nil ||
		pointerValid(value.PreviousProvenanceDigest, digestPattern.MatchString) != nil {
		return newError(Denied, "record_optional_invalid", false, nil)
	}
	if (value.ExportCount == 0) != (value.LastExportManifestDigest == nil) {
		return newError(Denied, "record_export_invalid", false, nil)
	}
	if value.State == Deleted {
		if value.LegalHold || value.DeletionReasonDigest == nil || value.DeletedByActorID == nil ||
			value.UpdatedAt.Before(value.RetainUntil) {
			return newError(Denied, "record_deletion_invalid", false, nil)
		}
	} else if value.DeletionReasonDigest != nil || value.DeletedByActorID != nil {
		return newError(Denied, "record_deletion_invalid", false, nil)
	}
	if value.Revision == 1 && value.PreviousProvenanceDigest != nil ||
		value.Revision > 1 && value.PreviousProvenanceDigest == nil {
		return newError(Denied, "record_chain_invalid", false, nil)
	}
	return nil
}

func validateReceipt(value Receipt) error {
	if err := validateReceiptShape(value, true); err != nil {
		return err
	}
	expected, err := ReceiptBindingDigest(value)
	if err != nil || expected != value.ReceiptDigest {
		return newError(Denied, "receipt_digest_invalid", false, nil)
	}
	return nil
}

func validateReceiptShape(value Receipt, bound bool) error {
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validOperation(value.Operation) || !validCase(value.Case) ||
		!digestPattern.MatchString(value.IntentDigest) || !digestPattern.MatchString(value.IdempotencyDigest) ||
		!digestPattern.MatchString(value.DecisionDigest) || !digestPattern.MatchString(value.RevocationDigest) ||
		!digestPattern.MatchString(value.AuditEventDigest) || validateCommandShape(value.Command) != nil ||
		validateRecord(value.Record) != nil ||
		!validTime(value.CreatedAt) ||
		(bound && !digestPattern.MatchString(value.ReceiptDigest)) || (!bound && value.ReceiptDigest != "") {
		return newError(Denied, "receipt_invalid", false, nil)
	}
	if value.Case != value.Record.Case || value.IntentDigest != value.Record.IntentDigest ||
		value.Command.RequestID != value.RequestID || value.Command.Operation != value.Operation ||
		value.Command.Case != value.Case || value.Command.PolicyDigest != value.Record.PolicyDigest ||
		value.IdempotencyDigest != value.Record.IdempotencyDigest || value.DecisionDigest != value.Record.DecisionDigest ||
		value.RevocationDigest != value.Record.RevocationDigest || value.AuditEventDigest != value.Record.AuditEventDigest ||
		value.CreatedAt != value.Record.UpdatedAt {
		return newError(Denied, "receipt_binding_invalid", false, nil)
	}
	intent, err := CommandBindingDigest(value.Command)
	if err != nil || intent != value.IntentDigest || IdempotencyBindingDigest(value.Command.IdempotencyKey) != value.IdempotencyDigest {
		return newError(Denied, "receipt_command_invalid", false, err)
	}
	return nil
}

func classificationRank(value Classification) int {
	switch value {
	case Public:
		return 1
	case Internal:
		return 2
	case Confidential:
		return 3
	case Restricted:
		return 4
	default:
		return 0
	}
}

func validOperation(value Operation) bool {
	switch value {
	case Create, Classify, Assign, PlaceHold, ReleaseHold, Close, Reopen, Export, Delete:
		return true
	default:
		return false
	}
}

func validState(value State) bool { return value == Open || value == Closed || value == Deleted }

func validClassification(value Classification) bool { return classificationRank(value) > 0 }

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func pointerValid[T any](value *T, validate func(T) bool) error {
	if value != nil && !validate(*value) {
		return newError(InvalidInput, "optional_value_invalid", false, nil)
	}
	return nil
}

func pointerTimeValid(value *time.Time) error {
	if value != nil && !validTime(*value) {
		return newError(InvalidInput, "optional_time_invalid", false, nil)
	}
	return nil
}
