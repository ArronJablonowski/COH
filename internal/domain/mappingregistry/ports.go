package mappingregistry

import "context"

// EvidenceVerifier checks immutable identity only and returns no source bytes.
type EvidenceVerifier interface {
	VerifyBinding(context.Context, Case, SourceBinding) error
}

// SignatureVerifier owns public-key trust and revocation. Private/public key
// material never crosses this domain boundary.
type SignatureVerifier interface {
	VerifySignature(context.Context, SignatureRequest) (SignatureDecision, error)
}

// SourceSchemaResolver verifies that the requested exact source schema is
// current for the bound source; it cannot return event data.
type SourceSchemaResolver interface {
	VerifySourceSchema(context.Context, Case, SourceMatcher) error
}

// RegistryStore owns optimistic revision and idempotency. Commit atomically
// persists command, outcome, receipt, audit, and provenance.
type RegistryStore interface {
	LoadReceipt(context.Context, string) (Receipt, bool, error)
	LoadCommandDigest(context.Context, string) (string, bool, error)
	Begin(context.Context, Command, string) (bool, error)
	LoadSnapshots(context.Context, Case, SourceMatcher) ([]RegistrySnapshot, error)
	LoadSignedMapping(context.Context, string) (SignedMapping, bool, error)
	Commit(context.Context, Commit) error
}

type AuditBuilder interface {
	BuildAudit(context.Context, string, string, Status, Reason) (AuditRecord, error)
}
type ProvenanceBuilder interface {
	BuildProvenance(context.Context, string, string, string) (ProvenanceRecord, error)
}

type Dependencies struct {
	Evidence      EvidenceVerifier
	Signatures    SignatureVerifier
	SourceSchemas SourceSchemaResolver
	Store         RegistryStore
	Audit         AuditBuilder
	Provenance    ProvenanceBuilder
	Clock         Clock
}
