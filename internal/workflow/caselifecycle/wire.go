package caselifecycle

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type commandWire struct {
	SchemaVersion        string          `json:"schema_version"`
	ContractVersion      string          `json:"contract_version"`
	RequestID            string          `json:"request_id"`
	IdempotencyKey       string          `json:"idempotency_key"`
	Operation            Operation       `json:"operation"`
	Case                 caseWire        `json:"case"`
	ActorID              string          `json:"actor_id"`
	ActorRevision        uint64          `json:"actor_revision"`
	TargetClassification *Classification `json:"target_classification"`
	AssigneeActorID      *string         `json:"assignee_actor_id"`
	RetentionPolicyID    *string         `json:"retention_policy_id"`
	RetainUntil          *string         `json:"retain_until"`
	ReasonDigest         *string         `json:"reason_digest"`
	ExportManifestDigest *string         `json:"export_manifest_digest"`
	PolicyDigest         string          `json:"policy_digest"`
	ExpectedRevision     uint64          `json:"expected_revision"`
	Deadline             string          `json:"deadline"`
}

type authorizationWire struct {
	SchemaVersion           string          `json:"schema_version"`
	ContractVersion         string          `json:"contract_version"`
	AuthorizationDigest     string          `json:"authorization_digest"`
	IntentDigest            string          `json:"intent_digest"`
	Command                 commandWire     `json:"command"`
	CurrentState            *State          `json:"current_state"`
	CurrentClassification   *Classification `json:"current_classification"`
	CurrentAssigneeActorID  *string         `json:"current_assignee_actor_id"`
	CurrentLegalHold        *bool           `json:"current_legal_hold"`
	CurrentRetainUntil      *string         `json:"current_retain_until"`
	CurrentProvenanceDigest *string         `json:"current_provenance_digest"`
}

type decisionWire struct {
	SchemaVersion       string    `json:"schema_version"`
	ContractVersion     string    `json:"contract_version"`
	DecisionID          string    `json:"decision_id"`
	DecisionDigest      string    `json:"decision_digest"`
	AuthorizationDigest string    `json:"authorization_digest"`
	IntentDigest        string    `json:"intent_digest"`
	Operation           Operation `json:"operation"`
	Case                caseWire  `json:"case"`
	ActorID             string    `json:"actor_id"`
	ActorRevision       uint64    `json:"actor_revision"`
	ExpectedRevision    uint64    `json:"expected_revision"`
	PolicyDigest        string    `json:"policy_digest"`
	RevocationDigest    string    `json:"revocation_digest"`
	Outcome             string    `json:"outcome"`
	ReasonCode          string    `json:"reason_code"`
	IssuedAt            string    `json:"issued_at"`
	ExpiresAt           string    `json:"expires_at"`
	Revision            uint64    `json:"revision"`
}

type recordWire struct {
	SchemaVersion            string         `json:"schema_version"`
	ContractVersion          string         `json:"contract_version"`
	Case                     caseWire       `json:"case"`
	CreatorActorID           string         `json:"creator_actor_id"`
	OwnerActorID             string         `json:"owner_actor_id"`
	AssigneeActorID          string         `json:"assignee_actor_id"`
	Classification           Classification `json:"classification"`
	State                    State          `json:"state"`
	RetentionPolicyID        string         `json:"retention_policy_id"`
	RetainUntil              string         `json:"retain_until"`
	LegalHold                bool           `json:"legal_hold"`
	HoldReasonDigest         *string        `json:"hold_reason_digest"`
	LastExportManifestDigest *string        `json:"last_export_manifest_digest"`
	ExportCount              uint64         `json:"export_count"`
	DeletionReasonDigest     *string        `json:"deletion_reason_digest"`
	DeletedByActorID         *string        `json:"deleted_by_actor_id"`
	PolicyDigest             string         `json:"policy_digest"`
	IntentDigest             string         `json:"intent_digest"`
	IdempotencyDigest        string         `json:"idempotency_digest"`
	DecisionDigest           string         `json:"decision_digest"`
	RevocationDigest         string         `json:"revocation_digest"`
	AuditEventDigest         string         `json:"audit_event_digest"`
	PreviousProvenanceDigest *string        `json:"previous_provenance_digest"`
	ProvenanceDigest         string         `json:"provenance_digest"`
	CreatedAt                string         `json:"created_at"`
	UpdatedAt                string         `json:"updated_at"`
	Revision                 uint64         `json:"revision"`
}

type receiptWire struct {
	SchemaVersion     string      `json:"schema_version"`
	ContractVersion   string      `json:"contract_version"`
	RequestID         string      `json:"request_id"`
	Operation         Operation   `json:"operation"`
	Case              caseWire    `json:"case"`
	IntentDigest      string      `json:"intent_digest"`
	IdempotencyDigest string      `json:"idempotency_digest"`
	DecisionDigest    string      `json:"decision_digest"`
	RevocationDigest  string      `json:"revocation_digest"`
	AuditEventDigest  string      `json:"audit_event_digest"`
	Command           commandWire `json:"command"`
	Record            recordWire  `json:"record"`
	CreatedAt         string      `json:"created_at"`
	ReceiptDigest     string      `json:"receipt_digest"`
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{value.OrganizationID, value.TenantID, value.CaseID}
}

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func commandToWire(value Command) commandWire {
	return commandWire{value.SchemaVersion, value.ContractVersion, value.RequestID, value.IdempotencyKey,
		value.Operation, caseToWire(value.Case), value.ActorID, value.ActorRevision,
		clonePointer(value.TargetClassification), clonePointer(value.AssigneeActorID),
		clonePointer(value.RetentionPolicyID), timeToWire(value.RetainUntil), clonePointer(value.ReasonDigest),
		clonePointer(value.ExportManifestDigest), value.PolicyDigest, value.ExpectedRevision, formatTime(value.Deadline)}
}

func commandFromWire(value commandWire) (Command, error) {
	deadline, err := parseTime(value.Deadline)
	if err != nil {
		return Command{}, err
	}
	retainUntil, err := timeFromWire(value.RetainUntil)
	if err != nil {
		return Command{}, err
	}
	return Command{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, IdempotencyKey: value.IdempotencyKey, Operation: value.Operation,
		Case: caseFromWire(value.Case), ActorID: value.ActorID, ActorRevision: value.ActorRevision,
		TargetClassification: clonePointer(value.TargetClassification), AssigneeActorID: clonePointer(value.AssigneeActorID),
		RetentionPolicyID: clonePointer(value.RetentionPolicyID), RetainUntil: retainUntil,
		ReasonDigest: clonePointer(value.ReasonDigest), ExportManifestDigest: clonePointer(value.ExportManifestDigest),
		PolicyDigest: value.PolicyDigest, ExpectedRevision: value.ExpectedRevision, Deadline: deadline}, nil
}

func authorizationToWire(value AuthorizationRequest) authorizationWire {
	return authorizationWire{value.SchemaVersion, value.ContractVersion, value.AuthorizationDigest,
		value.IntentDigest, commandToWire(value.Command), clonePointer(value.CurrentState),
		clonePointer(value.CurrentClassification), clonePointer(value.CurrentAssigneeActorID),
		clonePointer(value.CurrentLegalHold), timeToWire(value.CurrentRetainUntil),
		clonePointer(value.CurrentProvenanceDigest)}
}

func authorizationFromWire(value authorizationWire) (AuthorizationRequest, error) {
	command, err := commandFromWire(value.Command)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	retainUntil, err := timeFromWire(value.CurrentRetainUntil)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	return AuthorizationRequest{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		AuthorizationDigest: value.AuthorizationDigest, IntentDigest: value.IntentDigest, Command: command,
		CurrentState: clonePointer(value.CurrentState), CurrentClassification: clonePointer(value.CurrentClassification),
		CurrentAssigneeActorID: clonePointer(value.CurrentAssigneeActorID), CurrentLegalHold: clonePointer(value.CurrentLegalHold),
		CurrentRetainUntil: retainUntil, CurrentProvenanceDigest: clonePointer(value.CurrentProvenanceDigest)}, nil
}

func decisionToWire(value Decision) decisionWire {
	return decisionWire{value.SchemaVersion, value.ContractVersion, value.DecisionID, value.DecisionDigest,
		value.AuthorizationDigest, value.IntentDigest, value.Operation, caseToWire(value.Case), value.ActorID,
		value.ActorRevision, value.ExpectedRevision, value.PolicyDigest, value.RevocationDigest, value.Outcome,
		value.ReasonCode, formatTime(value.IssuedAt), formatTime(value.ExpiresAt), value.Revision}
}

func decisionFromWire(value decisionWire) (Decision, error) {
	issuedAt, err := parseTime(value.IssuedAt)
	if err != nil {
		return Decision{}, err
	}
	expiresAt, err := parseTime(value.ExpiresAt)
	if err != nil {
		return Decision{}, err
	}
	return Decision{value.SchemaVersion, value.ContractVersion, value.DecisionID, value.DecisionDigest,
		value.AuthorizationDigest, value.IntentDigest, value.Operation, caseFromWire(value.Case), value.ActorID,
		value.ActorRevision, value.ExpectedRevision, value.PolicyDigest, value.RevocationDigest, value.Outcome,
		value.ReasonCode, issuedAt, expiresAt, value.Revision}, nil
}

func recordToWire(value Record) recordWire {
	return recordWire{value.SchemaVersion, value.ContractVersion, caseToWire(value.Case), value.CreatorActorID,
		value.OwnerActorID, value.AssigneeActorID, value.Classification, value.State, value.RetentionPolicyID,
		formatTime(value.RetainUntil), value.LegalHold, clonePointer(value.HoldReasonDigest),
		clonePointer(value.LastExportManifestDigest), value.ExportCount, clonePointer(value.DeletionReasonDigest),
		clonePointer(value.DeletedByActorID), value.PolicyDigest, value.IntentDigest, value.IdempotencyDigest,
		value.DecisionDigest, value.RevocationDigest, value.AuditEventDigest,
		clonePointer(value.PreviousProvenanceDigest), value.ProvenanceDigest, formatTime(value.CreatedAt),
		formatTime(value.UpdatedAt), value.Revision}
}

func recordFromWire(value recordWire) (Record, error) {
	retainUntil, err := parseTime(value.RetainUntil)
	if err != nil {
		return Record{}, err
	}
	createdAt, err := parseTime(value.CreatedAt)
	if err != nil {
		return Record{}, err
	}
	updatedAt, err := parseTime(value.UpdatedAt)
	if err != nil {
		return Record{}, err
	}
	return Record{value.SchemaVersion, value.ContractVersion, caseFromWire(value.Case), value.CreatorActorID,
		value.OwnerActorID, value.AssigneeActorID, value.Classification, value.State, value.RetentionPolicyID,
		retainUntil, value.LegalHold, clonePointer(value.HoldReasonDigest), clonePointer(value.LastExportManifestDigest),
		value.ExportCount, clonePointer(value.DeletionReasonDigest), clonePointer(value.DeletedByActorID),
		value.PolicyDigest, value.IntentDigest, value.IdempotencyDigest, value.DecisionDigest,
		value.RevocationDigest, value.AuditEventDigest, clonePointer(value.PreviousProvenanceDigest),
		value.ProvenanceDigest, createdAt, updatedAt, value.Revision}, nil
}

func receiptToWire(value Receipt) receiptWire {
	return receiptWire{value.SchemaVersion, value.ContractVersion, value.RequestID, value.Operation,
		caseToWire(value.Case), value.IntentDigest, value.IdempotencyDigest, value.DecisionDigest,
		value.RevocationDigest, value.AuditEventDigest, commandToWire(value.Command), recordToWire(value.Record), formatTime(value.CreatedAt),
		value.ReceiptDigest}
}

func receiptFromWire(value receiptWire) (Receipt, error) {
	command, err := commandFromWire(value.Command)
	if err != nil {
		return Receipt{}, err
	}
	record, err := recordFromWire(value.Record)
	if err != nil {
		return Receipt{}, err
	}
	createdAt, err := parseTime(value.CreatedAt)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{value.SchemaVersion, value.ContractVersion, value.RequestID, value.Operation,
		caseFromWire(value.Case), value.IntentDigest, value.IdempotencyDigest, value.DecisionDigest,
		value.RevocationDigest, value.AuditEventDigest, command, record, createdAt, value.ReceiptDigest}, nil
}

func timeToWire(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := formatTime(*value)
	return &formatted
}

func timeFromWire(value *string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := parseTime(*value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
