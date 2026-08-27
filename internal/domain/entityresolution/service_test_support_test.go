package entityresolution

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

type memoryEntityServiceStore struct {
	mu              sync.Mutex
	digests         map[string]string
	active          map[string]bool
	receipts        map[string]Receipt
	outcomes        map[string]Outcome
	observations    map[ObservationRef]Observation
	candidates      map[string]Candidate
	entities        map[string]storedTransitionEntity
	histories       map[string]History
	results         map[string]Commit
	commits         []Commit
	denials         []Commit
	failAfterCommit bool
}

func newMemoryEntityServiceStore() *memoryEntityServiceStore {
	return &memoryEntityServiceStore{digests: make(map[string]string), active: make(map[string]bool), receipts: make(map[string]Receipt),
		outcomes: make(map[string]Outcome), observations: make(map[ObservationRef]Observation), candidates: make(map[string]Candidate),
		entities: make(map[string]storedTransitionEntity), histories: make(map[string]History), results: make(map[string]Commit)}
}

func (store *memoryEntityServiceStore) LoadCommandDigest(_ context.Context, key string) (string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	digest, found := store.digests[key]
	return digest, found, nil
}
func (store *memoryEntityServiceStore) LoadCommit(_ context.Context, key string) (Commit, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	commit, found := store.results[key]
	return commit, found, nil
}
func (store *memoryEntityServiceStore) Begin(_ context.Context, command Command, digest string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.digests[command.IdempotencyKey]; found {
		if existing == digest && !store.active[command.IdempotencyKey] && store.receipts[command.IdempotencyKey] == (Receipt{}) {
			store.active[command.IdempotencyKey] = true
			return true, nil
		}
		return false, nil
	}
	store.digests[command.IdempotencyKey] = digest
	store.active[command.IdempotencyKey] = true
	return true, nil
}
func (store *memoryEntityServiceStore) Commit(ctx context.Context, commit Commit) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if commit.Receipt.ReasonCode == IdempotencyConflict {
		store.denials = append(store.denials, commit)
		return nil
	}
	if _, exists := store.receipts[commit.Command.IdempotencyKey]; exists {
		return errors.New("duplicate commit")
	}
	store.commits = append(store.commits, commit)
	store.results[commit.Command.IdempotencyKey] = commit
	store.receipts[commit.Command.IdempotencyKey] = commit.Receipt
	store.outcomes[commit.Receipt.OutcomeDigest] = commit.Outcome
	store.active[commit.Command.IdempotencyKey] = false
	if commit.Observation != nil {
		_, digest, _ := CanonicalObservation(ctx, *commit.Observation)
		ref := ObservationRef{ObservationID: commit.Observation.ObservationID, ObservationDigest: digest}
		store.observations[ref] = *commit.Observation
	}
	if commit.Candidate != nil {
		_, digest, _ := CanonicalCandidate(ctx, *commit.Candidate)
		store.candidates[digest] = *commit.Candidate
	}
	for _, entity := range commit.Entities {
		_, digest, _ := EntityRecordDigest(ctx, entity)
		ref := EntityRef{EntityID: entity.EntityID, Revision: entity.Revision, RecordDigest: digest}
		store.entities[entity.EntityID] = storedTransitionEntity{entity: entity, reference: ref}
	}
	if commit.History != nil {
		_, digest, _ := CanonicalHistory(ctx, *commit.History)
		store.histories[digest] = *commit.History
	}
	if store.failAfterCommit {
		store.failAfterCommit = false
		return errors.New("lost commit response")
	}
	return nil
}

func (store *memoryEntityServiceStore) LoadObservation(_ context.Context, _ Scope, reference ObservationRef) (Observation, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.observations[reference]
	return value, found, nil
}
func (store *memoryEntityServiceStore) LoadObservationsByMatch(_ context.Context, scope Scope, identifier IdentifierBinding) ([]ObservationRef, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := []ObservationRef{}
	for reference, observation := range store.observations {
		if observation.Scope == scope && observation.Identifier == identifier {
			result = append(result, reference)
		}
	}
	slices.SortFunc(result, compareObservationRef)
	return result, nil
}
func (store *memoryEntityServiceStore) LoadCurrentEntity(_ context.Context, _ Scope, entityID string) (Entity, EntityRef, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.entities[entityID]
	return value.entity, value.reference, found, nil
}
func (store *memoryEntityServiceStore) LoadEntity(_ context.Context, _ Scope, reference EntityRef) (Entity, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.entities[reference.EntityID]
	return value.entity, found && value.reference == reference, nil
}
func (store *memoryEntityServiceStore) LoadEntitiesByMatch(_ context.Context, scope Scope, identifier IdentifierBinding) ([]EntityRef, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := []EntityRef{}
	for _, value := range store.entities {
		if value.entity.Scope != scope || value.entity.Status != "active" {
			continue
		}
		for _, member := range value.entity.MemberObservations {
			if observation, found := store.observations[member]; found && observation.Identifier == identifier {
				result = append(result, value.reference)
				break
			}
		}
	}
	slices.SortFunc(result, compareEntityRef)
	return result, nil
}
func (store *memoryEntityServiceStore) LoadHistory(_ context.Context, _ Scope, digest string) (History, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.histories[digest]
	return value, found, nil
}
func (store *memoryEntityServiceStore) LoadCandidate(_ context.Context, _ Scope, digest string) (Candidate, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.candidates[digest]
	return value, found, nil
}

type serviceEvidenceVerifier struct{ err error }

func (value *serviceEvidenceVerifier) VerifyCase(context.Context, Scope, string) (CaseDecision, error) {
	return CaseDecision{Verified: true, Current: true, CaseRevision: 4, Classification: "restricted",
		DecisionDigest: testDigest("service-case")}, value.err
}
func (value *serviceEvidenceVerifier) VerifyObservation(context.Context, Scope, IdentifierBinding, EvidenceBinding) (EvidenceDecision, error) {
	return EvidenceDecision{Verified: true, DecisionDigest: testDigest("service-observation")}, value.err
}
func (value *serviceEvidenceVerifier) VerifyEvidenceLink(context.Context, Scope, EvidenceLink) (EvidenceDecision, error) {
	return EvidenceDecision{Verified: true, DecisionDigest: testDigest("service-link")}, value.err
}

type serviceMatchVerifier struct{}

func (*serviceMatchVerifier) VerifyMatch(_ context.Context, request MatchRequest) (MatchDecision, error) {
	return MatchDecision{Verified: true, KeyRevision: request.Identifier.DerivationKeyRevision,
		DecisionDigest: testDigest("service-match")}, nil
}
func (*serviceMatchVerifier) VerifyAlias(_ context.Context, _ Scope, alias AliasProof) (MatchDecision, error) {
	return MatchDecision{Verified: true, KeyRevision: alias.ToKeyRevision, DecisionDigest: alias.VerifierDecisionDigest}, nil
}

type serviceAuditBuilder struct{}

func (*serviceAuditBuilder) BuildAudit(_ context.Context, operationID, commandDigest string, status Status, reason Reason) (AuditRecord, error) {
	return AuditRecord{OperationID: operationID, CommandDigest: commandDigest, Status: status, Reason: reason,
		Digest: testDigest("service-audit-" + operationID)}, nil
}

type serviceProvenanceBuilder struct{}

func (*serviceProvenanceBuilder) BuildProvenance(_ context.Context, operationID, commandDigest, outcomeDigest string) (ProvenanceRecord, error) {
	return ProvenanceRecord{OperationID: operationID, CommandDigest: commandDigest, OutcomeDigest: outcomeDigest,
		Digest: testDigest("service-provenance-" + operationID)}, nil
}

type serviceClock struct{ now time.Time }

func (value serviceClock) Now() time.Time { return value.now }
