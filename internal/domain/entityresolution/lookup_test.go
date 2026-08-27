package entityresolution

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestLookupCandidateReturnsDeterministicExactCaseMatches(t *testing.T) {
	fixture := validLookupFixture(t)
	second := fixture.entity
	second.EntityID = testUUID(8)
	secondRef := EntityRef{EntityID: second.EntityID, Revision: second.Revision, RecordDigest: testDigest("entity-two")}
	fixture.entities.references = []EntityRef{secondRef, fixture.entityRef}
	fixture.entities.values[secondRef] = second

	result, err := LookupCandidate(context.Background(), fixture.dependencies(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Result != "ambiguous" || result.Scope != fixture.request.Observation.Scope ||
		result.Identifier != fixture.request.Observation.Identifier || result.Observation.ObservationDigest != fixture.request.ObservationDigest ||
		len(result.MatchingEntities) != 2 || result.MatchingEntities[0] != secondRef || result.MatchingEntities[1] != fixture.entityRef {
		t.Fatalf("result=%+v", result)
	}
	if result.CaseDecisionDigest != fixture.evidence.caseDecision.DecisionDigest ||
		result.EvidenceDecisionDigest != fixture.evidence.observationDecision.DecisionDigest ||
		result.MatchDecisionDigest != fixture.matches.decision.DecisionDigest {
		t.Fatalf("decision bindings=%+v", result)
	}
}

func TestLookupCandidateZeroOneAndSupersededMatches(t *testing.T) {
	for name, configure := range map[string]func(*lookupFixture){
		"zero": func(value *lookupFixture) {
			value.entities.references = nil
			value.entities.values = nil
		},
		"one": func(*lookupFixture) {},
		"superseded excluded": func(value *lookupFixture) {
			entity := value.entity
			entity.Status = "superseded"
			value.entities.values[value.entityRef] = entity
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := validLookupFixture(t)
			configure(&fixture)
			result, err := LookupCandidate(context.Background(), fixture.dependencies(), fixture.request)
			if err != nil {
				t.Fatal(err)
			}
			expectedResult, expectedCount := "new_candidate", 0
			if name == "one" {
				expectedResult, expectedCount = "single_match", 1
			}
			if result.Result != expectedResult || len(result.MatchingEntities) != expectedCount {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestLookupCandidateRejectsReturnedBoundaryDrift(t *testing.T) {
	tests := map[string]struct {
		mutate func(*lookupFixture)
		reason Reason
	}{
		"cross case entity": {func(value *lookupFixture) {
			entity := value.entity
			entity.Scope.CaseID = testUUID(9)
			value.entities.values[value.entityRef] = entity
		}, ScopeMismatch},
		"weak classification": {func(value *lookupFixture) {
			entity := value.entity
			entity.Classification = "public"
			value.entities.values[value.entityRef] = entity
		}, EvidenceBindingMismatch},
		"unbound entity": {func(value *lookupFixture) {
			entity := value.entity
			entity.MemberObservations = []ObservationRef{{ObservationID: testUUID(9), ObservationDigest: testDigest("other")}}
			value.entities.values[value.entityRef] = entity
		}, EvidenceBindingMismatch},
		"type confused observation": {func(value *lookupFixture) {
			observation := value.observation
			observation.Identifier.Role = "user.name"
			observation.Identifier.IdentifierType = "username"
			_, digest, err := CanonicalObservation(context.Background(), observation)
			if err != nil {
				panic(err)
			}
			delete(value.observations.values, value.observationRef)
			value.observationRef.ObservationDigest = digest
			value.observations.references[0] = value.observationRef
			value.observations.values[value.observationRef] = observation
		}, IdentifierIncompatible},
		"missing observation": {func(value *lookupFixture) {
			value.observations.values = nil
		}, EvidenceBindingMismatch},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := validLookupFixture(t)
			test.mutate(&fixture)
			result, err := LookupCandidate(context.Background(), fixture.dependencies(), fixture.request)
			if Code(err) != DeniedError || ErrorReason(err) != test.reason || !reflect.DeepEqual(result, CandidateLookupResult{}) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestLookupCandidateFailsClosedOnVerificationAndDependencies(t *testing.T) {
	tests := map[string]struct {
		mutate func(*lookupFixture)
		code   ErrorCode
		reason Reason
	}{
		"case denied":        {func(value *lookupFixture) { value.evidence.caseDecision.Verified = false }, DeniedError, EvidenceBindingMismatch},
		"evidence denied":    {func(value *lookupFixture) { value.evidence.observationDecision.Verified = false }, DeniedError, EvidenceBindingMismatch},
		"match denied":       {func(value *lookupFixture) { value.matches.decision.KeyRevision++ }, DeniedError, IdentifierIncompatible},
		"store unavailable":  {func(value *lookupFixture) { value.entities.listErr = errors.New("offline") }, UnavailableError, DependencyUnavailableReason},
		"missing dependency": {func(value *lookupFixture) { value.evidence = nil }, UnavailableError, DependencyUnavailableReason},
		"changed digest":     {func(value *lookupFixture) { value.request.ObservationDigest = testDigest("changed") }, InvalidInputError, InvalidInput},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := validLookupFixture(t)
			test.mutate(&fixture)
			result, err := LookupCandidate(context.Background(), fixture.dependencies(), fixture.request)
			if Code(err) != test.code || ErrorReason(err) != test.reason || !reflect.DeepEqual(result, CandidateLookupResult{}) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	fixture := validLookupFixture(t)
	if _, err := LookupCandidate(canceled, fixture.dependencies(), fixture.request); Code(err) != CanceledError || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err=%v", err)
	}
}

type lookupFixture struct {
	request        CandidateLookupRequest
	observation    Observation
	observationRef ObservationRef
	entity         Entity
	entityRef      EntityRef
	evidence       *lookupEvidence
	matches        *lookupMatches
	observations   *lookupObservationStore
	entities       *lookupEntityStore
}

func validLookupFixture(t *testing.T) lookupFixture {
	t.Helper()
	input, _, inputDigest, err := NewObservation(context.Background(), validObservationInput())
	if err != nil {
		t.Fatal(err)
	}
	observation := input
	observation.ObservationID = testUUID(7)
	_, observationDigest, err := CanonicalObservation(context.Background(), observation)
	if err != nil {
		t.Fatal(err)
	}
	observationRef := ObservationRef{ObservationID: observation.ObservationID, ObservationDigest: observationDigest}
	entityRef := EntityRef{EntityID: testUUID(9), Revision: 2, RecordDigest: testDigest("entity-one")}
	entity := Entity{SchemaVersion: EntitySchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		EntityID: entityRef.EntityID, Revision: entityRef.Revision, Scope: input.Scope, Status: "active",
		Classification: "confidential", MemberObservations: []ObservationRef{observationRef}}
	evidence := &lookupEvidence{caseDecision: CaseDecision{Verified: true, Current: true, CaseRevision: 4,
		Classification: "restricted", DecisionDigest: testDigest("case-decision")},
		observationDecision: EvidenceDecision{Verified: true, DecisionDigest: testDigest("evidence-decision")}}
	matches := &lookupMatches{decision: MatchDecision{Verified: true, KeyRevision: input.Identifier.DerivationKeyRevision,
		DecisionDigest: testDigest("match-decision")}}
	return lookupFixture{request: CandidateLookupRequest{Observation: input, ObservationDigest: inputDigest},
		observation: observation, observationRef: observationRef, entity: entity, entityRef: entityRef,
		evidence: evidence, matches: matches,
		observations: &lookupObservationStore{references: []ObservationRef{observationRef}, values: map[ObservationRef]Observation{observationRef: observation}},
		entities:     &lookupEntityStore{references: []EntityRef{entityRef}, values: map[EntityRef]Entity{entityRef: entity}}}
}

func (value lookupFixture) dependencies() Dependencies {
	return Dependencies{Evidence: value.evidence, Matches: value.matches, Observations: value.observations, Entities: value.entities}
}

type lookupEvidence struct {
	caseDecision        CaseDecision
	observationDecision EvidenceDecision
	err                 error
}

func (value *lookupEvidence) VerifyCase(context.Context, Scope, string) (CaseDecision, error) {
	return value.caseDecision, value.err
}
func (value *lookupEvidence) VerifyObservation(context.Context, Scope, IdentifierBinding, EvidenceBinding) (EvidenceDecision, error) {
	return value.observationDecision, value.err
}

type lookupMatches struct {
	decision MatchDecision
	err      error
}

func (value *lookupMatches) VerifyMatch(context.Context, MatchRequest) (MatchDecision, error) {
	return value.decision, value.err
}
func (*lookupMatches) VerifyAlias(context.Context, Scope, AliasProof) (MatchDecision, error) {
	return MatchDecision{}, nil
}

type lookupObservationStore struct {
	references []ObservationRef
	values     map[ObservationRef]Observation
	listErr    error
	loadErr    error
}

func (value *lookupObservationStore) LoadObservation(_ context.Context, _ Scope, reference ObservationRef) (Observation, bool, error) {
	observation, found := value.values[reference]
	return observation, found, value.loadErr
}
func (value *lookupObservationStore) LoadObservationsByMatch(context.Context, Scope, IdentifierBinding) ([]ObservationRef, error) {
	return append([]ObservationRef(nil), value.references...), value.listErr
}

type lookupEntityStore struct {
	references []EntityRef
	values     map[EntityRef]Entity
	listErr    error
	loadErr    error
}

func (value *lookupEntityStore) LoadEntity(_ context.Context, _ Scope, reference EntityRef) (Entity, bool, error) {
	entity, found := value.values[reference]
	return entity, found, value.loadErr
}
func (value *lookupEntityStore) LoadCurrentEntity(_ context.Context, _ Scope, entityID string) (Entity, EntityRef, bool, error) {
	for reference, entity := range value.values {
		if reference.EntityID == entityID {
			return entity, reference, true, value.loadErr
		}
	}
	return Entity{}, EntityRef{}, false, value.loadErr
}
func (value *lookupEntityStore) LoadEntitiesByMatch(context.Context, Scope, IdentifierBinding) ([]EntityRef, error) {
	return append([]EntityRef(nil), value.references...), value.listErr
}
func (*lookupEntityStore) LoadHistory(context.Context, Scope, string) (History, bool, error) {
	return History{}, false, nil
}
