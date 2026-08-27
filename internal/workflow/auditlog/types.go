// Package auditlog coordinates durable, fail-closed audit appends and
// checkpoint verification through adapter-owned persistence and key ports.
package auditlog

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const readBatchSize = uint16(512)

type Commit struct {
	IdempotencyKey string
	RequestDigest  string
	ExpectedHead   tamperaudit.Head
	Record         tamperaudit.Record
	Checkpoint     *tamperaudit.Checkpoint
}

type AppendResult struct {
	Sequence     uint64
	ChainHash    string
	CheckpointID string
	Replayed     bool
}

type Store interface {
	LoadHead(context.Context, string, string) (tamperaudit.Head, error)
	CommitAudit(context.Context, Commit) (AppendResult, error)
	ReadAuditRecords(context.Context, string, string, uint64, uint16) ([]tamperaudit.Record, error)
	ReadAuditCheckpoints(context.Context, string, string) ([]tamperaudit.Checkpoint, error)
}

// CheckpointSigner fills only signing-key identity/revision, algorithm, and
// signature. The service verifies every other field and resolves the returned
// public authority before allowing persistence.
type CheckpointSigner interface {
	SignAuditCheckpoint(context.Context, tamperaudit.Checkpoint) (tamperaudit.Checkpoint, error)
}

type KeyResolver interface {
	ResolveAuditKey(context.Context, string, uint64) (KeyAuthority, error)
}

type KeyAuthority struct {
	KeyID      string
	Revision   uint64
	PublicKey  ed25519.PublicKey
	ValidFrom  time.Time
	ValidUntil time.Time
	RevokedAt  *time.Time
}

type Clock interface{ Now() time.Time }

type IDSource interface {
	NewAuditID(time.Time) (string, error)
}

type Service struct {
	store    Store
	signer   CheckpointSigner
	resolver KeyResolver
	clock    Clock
	ids      IDSource
}

type VerificationReport struct {
	OrganizationID      string
	TenantID            string
	RecordCount         uint64
	CheckpointCount     uint64
	HeadSequence        uint64
	HeadHash            string
	LastCheckpoint      uint64
	UncheckpointedCount uint64
}

// CheckpointProof is the independently verified, non-secret proof material
// required to bind a custody interval into an evidence lifecycle manifest.
type CheckpointProof struct {
	CheckpointID       string
	CheckpointDigest   string
	Sequence           uint64
	SigningKeyRevision uint64
	ProofDigest        string
}
