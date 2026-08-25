package workflow

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const StorageContractVersion = "coh.storage/v1"

type MutationKind string

const (
	MutationPut    MutationKind = "put"
	MutationDelete MutationKind = "delete"
)

// RecordKey is the complete authorization and persistence identity of metadata.
type RecordKey struct {
	Case domain.CaseRef
	Kind string
	ID   string
}

// MetadataRecord contains exact canonical domain bytes and their bound digest.
type MetadataRecord struct {
	Key       RecordKey
	Schema    string
	Revision  uint64
	Canonical []byte
	Digest    string
}

// Mutation applies one optimistic-concurrency check. ExpectedRevision zero means
// the record must not exist; a put writes ExpectedRevision+1.
type Mutation struct {
	Kind             MutationKind
	Key              RecordKey
	ExpectedRevision uint64
	Record           *MetadataRecord
}

// OutboxMessage is committed atomically with metadata. Payloads remain behind
// immutable references; the storage port never transports evidence bytes.
type OutboxMessage struct {
	ID            string
	Case          domain.CaseRef
	Topic         string
	PayloadRef    string
	PayloadDigest string
}

// Transaction is an atomic, idempotent metadata and outbox change set.
type Transaction struct {
	ContractVersion string
	IdempotencyKey  string
	Mutations       []Mutation
	Outbox          []OutboxMessage
}

type CommitResult struct {
	IdempotencyKey string
	CommitSequence uint64
	Replayed       bool
	RecordVersions map[string]uint64
	OutboxIDs      []string
}

type OutboxClaim struct {
	OrganizationID string
	TenantID       string
	WorkerID       string
	Limit          uint16
	LeaseUntil     time.Time
}

type OutboxDelivery struct {
	Message OutboxMessage
	LeaseID string
}

type OutboxOutcome string

const (
	OutboxDelivered  OutboxOutcome = "delivered"
	OutboxRetry      OutboxOutcome = "retry"
	OutboxDeadLetter OutboxOutcome = "dead_letter"
)

type OutboxSettlement struct {
	OrganizationID string
	TenantID       string
	MessageID      string
	LeaseID        string
	Outcome        OutboxOutcome
	EvidenceDigest string
}

type MigrationDirection string

const (
	MigrationApply    MigrationDirection = "apply"
	MigrationRollback MigrationDirection = "rollback"
)

// MigrationPlan identifies adapter-owned migration logic without carrying SQL,
// callbacks, shell commands, or another executable escape surface.
type MigrationPlan struct {
	ContractVersion string
	Component       string
	Version         uint64
	Checksum        string
	BackupDigest    string
	Direction       MigrationDirection
}

type MigrationState string

const (
	MigrationPending    MigrationState = "pending"
	MigrationInProgress MigrationState = "in_progress"
	MigrationApplied    MigrationState = "applied"
	MigrationRolledBack MigrationState = "rolled_back"
)

type MigrationResult struct {
	Component    string
	Version      uint64
	Checksum     string
	State        MigrationState
	ResumeDigest string
	Replayed     bool
}
