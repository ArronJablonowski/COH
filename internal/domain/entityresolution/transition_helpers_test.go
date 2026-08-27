package entityresolution

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

type storedTransitionEntity struct {
	entity    Entity
	reference EntityRef
}

type transitionStore struct {
	current   map[string]storedTransitionEntity
	histories map[string]History
	err       error
}

func (store *transitionStore) LoadCurrentEntity(_ context.Context, _ Scope, entityID string) (Entity, EntityRef, bool, error) {
	value, found := store.current[entityID]
	return value.entity, value.reference, found, store.err
}
func (store *transitionStore) LoadEntity(_ context.Context, _ Scope, reference EntityRef) (Entity, bool, error) {
	value, found := store.current[reference.EntityID]
	return value.entity, found && value.reference == reference, store.err
}
func (*transitionStore) LoadEntitiesByMatch(context.Context, Scope, IdentifierBinding) ([]EntityRef, error) {
	return nil, nil
}
func (store *transitionStore) LoadHistory(_ context.Context, _ Scope, digest string) (History, bool, error) {
	value, found := store.histories[digest]
	return value, found, store.err
}

type transitionAuthorization struct {
	decision AuthorizationDecision
	err      error
	last     AuthorizationRequest
}

func (value *transitionAuthorization) VerifyAuthorization(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
	value.last = request
	return value.decision, value.err
}

func validTransitionAuthorization() *transitionAuthorization {
	return &transitionAuthorization{decision: AuthorizationDecision{Allowed: true, ActorRevision: 3, CaseRevision: 7,
		DecisionDigest: testDigest("transition-authorization"), RevocationDigest: testDigest("transition-revocation"),
		ExpiresAt: "2026-08-27T02:00:00.000000000Z"}}
}

type transitionMatches struct {
	verified bool
	err      error
}

func (*transitionMatches) VerifyMatch(context.Context, MatchRequest) (MatchDecision, error) {
	return MatchDecision{}, nil
}
func (value *transitionMatches) VerifyAlias(_ context.Context, _ Scope, alias AliasProof) (MatchDecision, error) {
	return MatchDecision{Verified: value.verified, KeyRevision: alias.ToKeyRevision,
		DecisionDigest: alias.VerifierDecisionDigest}, value.err
}

func validTransitionMatches() *transitionMatches { return &transitionMatches{verified: true} }

func transitionEntity(t *testing.T, entityNumber, historyNumber int, evidence []ConfidenceEvidenceInput,
	classification string, historyOperation Operation, aliases ...AliasProof) (storedTransitionEntity, string, History) {
	t.Helper()
	confidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	members := make([]ObservationRef, 0, len(evidence))
	for _, item := range evidence {
		members = append(members, ObservationRef{ObservationID: item.Observation.ObservationID, ObservationDigest: item.ObservationDigest})
	}
	slices.SortFunc(members, compareObservationRef)
	entity := Entity{SchemaVersion: EntitySchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		EntityID: transitionUUID(entityNumber), Revision: 1, Scope: evidence[0].Observation.Scope, Status: "active",
		Classification: classification, MemberObservations: members, AliasProofs: append([]AliasProof(nil), aliases...), Confidence: confidence,
		CreationDecisionDigest: testDigest("transition-creation"), HistoryHeadDigest: testDigest("temporary-history"),
		AuditDigest: testDigest("transition-audit"), ProvenanceDigest: testDigest("transition-provenance"),
		CreatedAt: "2026-08-27T00:00:00.000000000Z", UpdatedAt: "2026-08-27T00:00:00.000000000Z"}
	slices.SortFunc(entity.AliasProofs, compareAliasProof)
	_, recordDigest, err := EntityRecordDigest(context.Background(), entity)
	if err != nil {
		t.Fatal(err)
	}
	reference := EntityRef{EntityID: entity.EntityID, Revision: entity.Revision, RecordDigest: recordDigest}
	history := History{SchemaVersion: HistorySchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		HistoryID: transitionUUID(historyNumber), Sequence: 1, Scope: entity.Scope, Operation: historyOperation,
		DecisionDigest: testDigest(fmt.Sprintf("history-decision-%d", historyNumber)), InputEntities: []EntityRef{},
		OutputEntities: []EntityRef{reference}, PreviousHistoryDigests: []string{}, CreatedAt: entity.CreatedAt}
	_, historyDigest, err := canonicalValue(history)
	if err != nil {
		t.Fatal(err)
	}
	entity.HistoryHeadDigest = historyDigest
	return storedTransitionEntity{entity: entity, reference: reference}, historyDigest, history
}

func transitionMetadata(t *testing.T, evidence []ConfidenceEvidenceInput, counter []Counterevidence, reason string) TransitionMetadata {
	t.Helper()
	confidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{Evidence: evidence, Counterevidence: counter})
	if err != nil {
		t.Fatal(err)
	}
	return TransitionMetadata{DecisionID: transitionUUID(40), HistoryID: transitionUUID(41), HistorySequence: 2,
		OperationID: transitionUUID(42), Scope: evidence[0].Observation.Scope, ActorID: transitionUUID(43), ActorRevision: 3,
		CommandDigest: testDigest("transition-command"), Reason: reason,
		SupportingEvidence: append([]EvidenceLink(nil), confidence.SupportingEvidence...),
		Counterevidence:    append([]Counterevidence(nil), confidence.Counterevidence...), Confidence: confidence,
		CreatedAt: "2026-08-27T01:00:00.000000000Z", Deadline: "2026-08-27T01:30:00.000000000Z"}
}

func transitionUUID(value int) string {
	return fmt.Sprintf("0198e300-2000-7000-8000-%012d", value)
}
