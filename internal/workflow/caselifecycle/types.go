// Package caselifecycle owns the tenant- and case-scoped lifecycle boundary.
package caselifecycle

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const (
	CommandSchemaVersion       = "coh.case-command/v1"
	AuthorizationSchemaVersion = "coh.case-authorization/v1"
	DecisionSchemaVersion      = "coh.case-decision/v1"
	RecordSchemaVersion        = "coh.case-lifecycle/v1"
	ReceiptSchemaVersion       = "coh.case-receipt/v1"
	ContractVersion            = "1.0.0"
)

type Operation string

const (
	Create      Operation = "create"
	Classify    Operation = "classify"
	Assign      Operation = "assign"
	PlaceHold   Operation = "place_hold"
	ReleaseHold Operation = "release_hold"
	Close       Operation = "close"
	Reopen      Operation = "reopen"
	Export      Operation = "export"
	Delete      Operation = "delete"
)

type State string

const (
	Open    State = "open"
	Closed  State = "closed"
	Deleted State = "deleted"
)

type Classification string

const (
	Public       Classification = "public"
	Internal     Classification = "internal"
	Confidential Classification = "confidential"
	Restricted   Classification = "restricted"
)

type Command struct {
	SchemaVersion        string
	ContractVersion      string
	RequestID            string
	IdempotencyKey       string
	Operation            Operation
	Case                 domain.CaseRef
	ActorID              string
	ActorRevision        uint64
	TargetClassification *Classification
	AssigneeActorID      *string
	RetentionPolicyID    *string
	RetainUntil          *time.Time
	ReasonDigest         *string
	ExportManifestDigest *string
	PolicyDigest         string
	ExpectedRevision     uint64
	Deadline             time.Time
}

type AuthorizationRequest struct {
	SchemaVersion           string
	ContractVersion         string
	AuthorizationDigest     string
	IntentDigest            string
	Command                 Command
	CurrentState            *State
	CurrentClassification   *Classification
	CurrentAssigneeActorID  *string
	CurrentLegalHold        *bool
	CurrentRetainUntil      *time.Time
	CurrentProvenanceDigest *string
}

type Decision struct {
	SchemaVersion       string
	ContractVersion     string
	DecisionID          string
	DecisionDigest      string
	AuthorizationDigest string
	IntentDigest        string
	Operation           Operation
	Case                domain.CaseRef
	ActorID             string
	ActorRevision       uint64
	ExpectedRevision    uint64
	PolicyDigest        string
	RevocationDigest    string
	Outcome             string
	ReasonCode          string
	IssuedAt            time.Time
	ExpiresAt           time.Time
	Revision            uint64
}

type Record struct {
	SchemaVersion            string
	ContractVersion          string
	Case                     domain.CaseRef
	CreatorActorID           string
	OwnerActorID             string
	AssigneeActorID          string
	Classification           Classification
	State                    State
	RetentionPolicyID        string
	RetainUntil              time.Time
	LegalHold                bool
	HoldReasonDigest         *string
	LastExportManifestDigest *string
	ExportCount              uint64
	DeletionReasonDigest     *string
	DeletedByActorID         *string
	PolicyDigest             string
	IntentDigest             string
	IdempotencyDigest        string
	DecisionDigest           string
	RevocationDigest         string
	AuditEventDigest         string
	PreviousProvenanceDigest *string
	ProvenanceDigest         string
	CreatedAt                time.Time
	UpdatedAt                time.Time
	Revision                 uint64
}

type Receipt struct {
	SchemaVersion     string
	ContractVersion   string
	RequestID         string
	Operation         Operation
	Case              domain.CaseRef
	IntentDigest      string
	IdempotencyDigest string
	DecisionDigest    string
	RevocationDigest  string
	AuditEventDigest  string
	Command           Command
	Record            Record
	CreatedAt         time.Time
	ReceiptDigest     string
}

type Result struct {
	Record   Record
	Receipt  Receipt
	Replayed bool
}

type Authority interface {
	AuthorizeCase(context.Context, AuthorizationRequest) (Decision, error)
}

type Auditor interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type Store interface {
	Load(context.Context, domain.CaseRef) (Record, bool, error)
	Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error)
	Commit(context.Context, string, string, uint64, Record, Receipt) (Receipt, bool, error)
}

type Clock interface{ Now() time.Time }

func cloneCommand(value Command) Command {
	result := value
	result.TargetClassification = clonePointer(value.TargetClassification)
	result.AssigneeActorID = clonePointer(value.AssigneeActorID)
	result.RetentionPolicyID = clonePointer(value.RetentionPolicyID)
	result.RetainUntil = clonePointer(value.RetainUntil)
	result.ReasonDigest = clonePointer(value.ReasonDigest)
	result.ExportManifestDigest = clonePointer(value.ExportManifestDigest)
	return result
}

func cloneAuthorization(value AuthorizationRequest) AuthorizationRequest {
	result := value
	result.Command = cloneCommand(value.Command)
	result.CurrentState = clonePointer(value.CurrentState)
	result.CurrentClassification = clonePointer(value.CurrentClassification)
	result.CurrentAssigneeActorID = clonePointer(value.CurrentAssigneeActorID)
	result.CurrentLegalHold = clonePointer(value.CurrentLegalHold)
	result.CurrentRetainUntil = clonePointer(value.CurrentRetainUntil)
	result.CurrentProvenanceDigest = clonePointer(value.CurrentProvenanceDigest)
	return result
}

func cloneRecord(value Record) Record {
	result := value
	result.HoldReasonDigest = clonePointer(value.HoldReasonDigest)
	result.LastExportManifestDigest = clonePointer(value.LastExportManifestDigest)
	result.DeletionReasonDigest = clonePointer(value.DeletionReasonDigest)
	result.DeletedByActorID = clonePointer(value.DeletedByActorID)
	result.PreviousProvenanceDigest = clonePointer(value.PreviousProvenanceDigest)
	return result
}

func cloneReceipt(value Receipt) Receipt {
	result := value
	result.Command = cloneCommand(value.Command)
	result.Record = cloneRecord(value.Record)
	return result
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
