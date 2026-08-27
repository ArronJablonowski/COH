package investigationprojection

import "context"

// AuthorityVerifier verifies exact authoritative heads without returning raw
// case, evidence, custody, audit, provenance, or event content.
type AuthorityVerifier interface {
	VerifyCurrent(context.Context, Scope, StateVersion) (Watermark, error)
	VerifyExact(context.Context, Scope, StateVersion, Watermark) error
}

// FactStore returns immutable facts from one case-local authoritative log.
type FactStore interface {
	LoadFacts(context.Context, Scope, uint64, uint64) ([]Fact, error)
}

// CheckpointStore persists derived state atomically. It is never an authority
// source: every loaded value is independently verified by the service.
type CheckpointStore interface {
	LoadLatest(context.Context, Scope, Kind) (Projection, Checkpoint, bool, error)
	Commit(context.Context, *string, Projection, Checkpoint) (Projection, Checkpoint, error)
}

type EvidenceRequest struct {
	Scope         Scope
	Kind          Kind
	StateVersion  StateVersion
	Watermark     Watermark
	FactSetDigest string
}

type EvidenceDigests struct {
	AuditDigest      string
	ProvenanceDigest string
}

// EvidenceBuilder records the derived projection operation in authoritative
// audit and provenance facilities and returns only their immutable digests.
type EvidenceBuilder interface {
	BuildProjectionEvidence(context.Context, EvidenceRequest) (EvidenceDigests, error)
}

type Dependencies struct {
	Authority   AuthorityVerifier
	Facts       FactStore
	Checkpoints CheckpointStore
	Evidence    EvidenceBuilder
}
