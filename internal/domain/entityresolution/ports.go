package entityresolution

import "context"

// EvidenceVerifier confirms current case and immutable COH-E10/CYB-80/CYB-81
// identities without returning source or identifier values.
type EvidenceVerifier interface {
	VerifyCase(context.Context, Scope, string) (CaseDecision, error)
	VerifyObservation(context.Context, Scope, IdentifierBinding, EvidenceBinding) (EvidenceDecision, error)
}

// MatchVerifier owns the non-exportable case match key and verifies opaque
// match digests and key-rotation alias proofs.
type MatchVerifier interface {
	VerifyMatch(context.Context, MatchRequest) (MatchDecision, error)
	VerifyAlias(context.Context, Scope, AliasProof) (MatchDecision, error)
}

// AuthorizationVerifier checks exact current authority for analytical
// mutations. Policy source and grants never cross this boundary.
type AuthorizationVerifier interface {
	VerifyAuthorization(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
}

// ObservationStore is case-partitioned and returns immutable observations.
type ObservationStore interface {
	LoadObservation(context.Context, Scope, ObservationRef) (Observation, bool, error)
	LoadObservationsByMatch(context.Context, Scope, IdentifierBinding) ([]ObservationRef, error)
}

// EntityStore is case-partitioned and returns exact immutable revisions.
type EntityStore interface {
	LoadEntity(context.Context, Scope, EntityRef) (Entity, bool, error)
	LoadEntitiesByMatch(context.Context, Scope, IdentifierBinding) ([]EntityRef, error)
	LoadHistory(context.Context, Scope, string) (History, bool, error)
}

// DurableStore owns idempotency and atomically commits all terminal state.
type DurableStore interface {
	LoadReceipt(context.Context, string) (Receipt, bool, error)
	LoadOutcome(context.Context, string) (Outcome, bool, error)
	LoadCommandDigest(context.Context, string) (string, bool, error)
	Begin(context.Context, Command, string) (bool, error)
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
	Matches       MatchVerifier
	Authorization AuthorizationVerifier
	Observations  ObservationStore
	Entities      EntityStore
	Durable       DurableStore
	Audit         AuditBuilder
	Provenance    ProvenanceBuilder
	Clock         Clock
}
