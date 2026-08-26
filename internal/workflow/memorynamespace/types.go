// Package memorynamespace provides class-bound, reference-only memory stores.
package memorynamespace

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	SchemaVersion       = "coh.memory-namespace/v1"
	PutSchemaVersion    = "coh.memory-write/v1"
	GetSchemaVersion    = "coh.memory-read/v1"
	AccessSchemaVersion = "coh.memory-access/v1"
	ReviewSchemaVersion = "coh.memory-review/v1"
	ContractVersion     = "1.0.0"
	MaximumKeyBytes     = 128
)

type Namespace string

const (
	SessionMemory              Namespace = "session"
	CaseMemory                 Namespace = "case"
	AnalystPreferenceMemory    Namespace = "analyst_preference"
	ReviewedOrganizationMemory Namespace = "reviewed_organization"
)

type Operation string

const (
	Read  Operation = "read"
	Write Operation = "write"
)

// Scope is interpreted strictly by Namespace; unused identity fields must be empty.
type Scope struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
	SessionID      string `json:"session_id"`
	SubjectActorID string `json:"subject_actor_id"`
}

type RetentionPolicy struct {
	Class        string    `json:"class"`
	PolicyDigest string    `json:"policy_digest"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Review binds independently reviewed organization memory to current authority.
type Review struct {
	ReviewID        string    `json:"review_id"`
	ReviewerActorID string    `json:"reviewer_actor_id"`
	Revision        uint64    `json:"revision"`
	AuthorityDigest string    `json:"authority_digest"`
	ReviewedAt      time.Time `json:"reviewed_at"`
	ValidUntil      time.Time `json:"valid_until"`
}

type PutRequest struct {
	SchemaVersion    string             `json:"schema_version"`
	ContractVersion  string             `json:"contract_version"`
	RequestID        string             `json:"request_id"`
	IdempotencyKey   string             `json:"idempotency_key"`
	ActorID          string             `json:"actor_id"`
	Namespace        Namespace          `json:"namespace"`
	Scope            Scope              `json:"scope"`
	Key              string             `json:"key"`
	Value            domain.ArtifactRef `json:"value"`
	ValueType        string             `json:"value_type"`
	Retention        RetentionPolicy    `json:"retention"`
	Review           Review             `json:"review"`
	PolicyDigest     string             `json:"policy_digest"`
	ExpectedRevision uint64             `json:"expected_revision"`
	Deadline         time.Time          `json:"deadline"`
}

type GetRequest struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	RequestID       string    `json:"request_id"`
	ActorID         string    `json:"actor_id"`
	Namespace       Namespace `json:"namespace"`
	Scope           Scope     `json:"scope"`
	Key             string    `json:"key"`
	PolicyDigest    string    `json:"policy_digest"`
	Deadline        time.Time `json:"deadline"`
}

type AccessRequest struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	RequestID       string    `json:"request_id"`
	ActorID         string    `json:"actor_id"`
	Operation       Operation `json:"operation"`
	Namespace       Namespace `json:"namespace"`
	Scope           Scope     `json:"scope"`
	Key             string    `json:"key"`
	ValueDigest     string    `json:"value_digest"`
	RetentionDigest string    `json:"retention_digest"`
	PolicyDigest    string    `json:"policy_digest"`
	Deadline        time.Time `json:"deadline"`
}

type Decision struct {
	SchemaVersion       string    `json:"schema_version"`
	ContractVersion     string    `json:"contract_version"`
	Allowed             bool      `json:"allowed"`
	ReasonCode          string    `json:"reason_code"`
	AccessRequestDigest string    `json:"access_request_digest"`
	DecisionDigest      string    `json:"decision_digest"`
	DecidedAt           time.Time `json:"decided_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type ReviewRequest struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	RequestID       string    `json:"request_id"`
	ActorID         string    `json:"actor_id"`
	WriterActorID   string    `json:"writer_actor_id"`
	Operation       Operation `json:"operation"`
	Scope           Scope     `json:"scope"`
	Key             string    `json:"key"`
	ValueDigest     string    `json:"value_digest"`
	Review          Review    `json:"review"`
	PolicyDigest    string    `json:"policy_digest"`
	Deadline        time.Time `json:"deadline"`
}

type ReviewDecision struct {
	SchemaVersion       string    `json:"schema_version"`
	ContractVersion     string    `json:"contract_version"`
	Allowed             bool      `json:"allowed"`
	ReasonCode          string    `json:"reason_code"`
	ReviewRequestDigest string    `json:"review_request_digest"`
	DecisionDigest      string    `json:"decision_digest"`
	DecidedAt           time.Time `json:"decided_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type Record struct {
	SchemaVersion            string             `json:"schema_version"`
	ContractVersion          string             `json:"contract_version"`
	Namespace                Namespace          `json:"namespace"`
	Scope                    Scope              `json:"scope"`
	Key                      string             `json:"key"`
	Value                    domain.ArtifactRef `json:"value"`
	ValueType                string             `json:"value_type"`
	Retention                RetentionPolicy    `json:"retention"`
	Review                   Review             `json:"review"`
	WriterActorID            string             `json:"writer_actor_id"`
	PolicyDigest             string             `json:"policy_digest"`
	IntentDigest             string             `json:"intent_digest"`
	IdempotencyDigest        string             `json:"idempotency_digest"`
	AccessDecisionDigest     string             `json:"access_decision_digest"`
	ReviewDecisionDigest     string             `json:"review_decision_digest"`
	PreviousProvenanceDigest string             `json:"previous_provenance_digest"`
	ProvenanceDigest         string             `json:"provenance_digest"`
	CreatedAt                time.Time          `json:"created_at"`
	UpdatedAt                time.Time          `json:"updated_at"`
	Revision                 uint64             `json:"revision"`
}

type Result struct {
	Record   Record
	Replayed bool
}

type Authority interface {
	AuthorizeMemory(context.Context, AccessRequest) (Decision, error)
}

type ReviewAuthority interface {
	AuthorizeReview(context.Context, ReviewRequest) (ReviewDecision, error)
}

// Store instances are bound to exactly one Namespace at construction.
type Store interface {
	Namespace() Namespace
	Load(context.Context, Scope, string) (Record, bool, error)
	Recover(context.Context, Scope, string, string) (Record, bool, error)
	Commit(context.Context, string, string, uint64, Record) (Record, bool, error)
}

type Clock interface{ Now() time.Time }
