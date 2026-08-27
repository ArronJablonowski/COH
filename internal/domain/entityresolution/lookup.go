package entityresolution

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
)

const (
	MaximumLookupObservations = 4096
	MaximumLookupEntities     = 1024
)

type CandidateLookupRequest struct {
	Observation       Observation
	ObservationDigest string
}

type CandidateLookupResult struct {
	Scope                  Scope
	Identifier             IdentifierBinding
	Observation            ObservationRef
	MatchingEntities       []EntityRef
	Result                 string
	CaseDecisionDigest     string
	EvidenceDecisionDigest string
	MatchDecisionDigest    string
}

func LookupCandidate(ctx context.Context, dependencies Dependencies, request CandidateLookupRequest) (CandidateLookupResult, error) {
	if err := checkContext(ctx); err != nil {
		return CandidateLookupResult{}, err
	}
	if nilDependency(dependencies.Evidence) || nilDependency(dependencies.Matches) || nilDependency(dependencies.Observations) ||
		nilDependency(dependencies.Entities) {
		return CandidateLookupResult{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	canonical, digest, err := CanonicalObservation(ctx, request.Observation)
	if err != nil || len(canonical) == 0 || digest != request.ObservationDigest || request.Observation.Validity != "current" {
		return CandidateLookupResult{}, newError(InvalidInputError, InvalidInput, err)
	}

	caseDecision, err := dependencies.Evidence.VerifyCase(ctx, request.Observation.Scope, request.Observation.Evidence.Classification)
	if err = dependencyError(ctx, err); err != nil {
		return CandidateLookupResult{}, err
	}
	if !validCaseDecision(caseDecision, request.Observation.Evidence.Classification) {
		return CandidateLookupResult{}, newError(DeniedError, EvidenceBindingMismatch, nil)
	}
	evidenceDecision, err := dependencies.Evidence.VerifyObservation(ctx, request.Observation.Scope,
		request.Observation.Identifier, request.Observation.Evidence)
	if err = dependencyError(ctx, err); err != nil {
		return CandidateLookupResult{}, err
	}
	if !evidenceDecision.Verified || !digestPattern.MatchString(evidenceDecision.DecisionDigest) {
		return CandidateLookupResult{}, newError(DeniedError, EvidenceBindingMismatch, nil)
	}
	matchDecision, err := dependencies.Matches.VerifyMatch(ctx, MatchRequest{Scope: request.Observation.Scope,
		Identifier: request.Observation.Identifier, Evidence: request.Observation.Evidence})
	if err = dependencyError(ctx, err); err != nil {
		return CandidateLookupResult{}, err
	}
	if !matchDecision.Verified || matchDecision.KeyRevision != request.Observation.Identifier.DerivationKeyRevision ||
		!digestPattern.MatchString(matchDecision.DecisionDigest) {
		return CandidateLookupResult{}, newError(DeniedError, IdentifierIncompatible, nil)
	}

	matchedObservations, err := loadMatchedObservations(ctx, dependencies, request.Observation, caseDecision.Classification)
	if err != nil {
		return CandidateLookupResult{}, err
	}
	matchedEntities, err := loadMatchedEntities(ctx, dependencies.Entities, request.Observation, caseDecision.Classification, matchedObservations)
	if err != nil {
		return CandidateLookupResult{}, err
	}
	result := "new_candidate"
	if len(matchedEntities) == 1 {
		result = "single_match"
	} else if len(matchedEntities) > 1 {
		result = "ambiguous"
	}
	return CandidateLookupResult{Scope: request.Observation.Scope, Identifier: request.Observation.Identifier,
		Observation:      ObservationRef{ObservationID: request.Observation.ObservationID, ObservationDigest: request.ObservationDigest},
		MatchingEntities: matchedEntities, Result: result, CaseDecisionDigest: caseDecision.DecisionDigest,
		EvidenceDecisionDigest: evidenceDecision.DecisionDigest, MatchDecisionDigest: matchDecision.DecisionDigest}, nil
}

func loadMatchedObservations(ctx context.Context, dependencies Dependencies, input Observation, caseClassification string) (map[ObservationRef]struct{}, error) {
	references, err := dependencies.Observations.LoadObservationsByMatch(ctx, input.Scope, input.Identifier)
	if err = dependencyError(ctx, err); err != nil {
		return nil, err
	}
	if len(references) > MaximumLookupObservations {
		return nil, newError(InvalidInputError, InvalidInput, nil)
	}
	matched := make(map[ObservationRef]struct{}, len(references))
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if !uuidPattern.MatchString(reference.ObservationID) || !digestPattern.MatchString(reference.ObservationDigest) {
			return nil, newError(InvalidInputError, InvalidInput, nil)
		}
		if _, duplicate := seen[reference.ObservationID]; duplicate {
			return nil, newError(InvalidInputError, InvalidInput, nil)
		}
		seen[reference.ObservationID] = struct{}{}
		observation, found, loadErr := dependencies.Observations.LoadObservation(ctx, input.Scope, reference)
		if loadErr = dependencyError(ctx, loadErr); loadErr != nil {
			return nil, loadErr
		}
		if !found {
			return nil, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		_, digest, validationErr := CanonicalObservation(ctx, observation)
		if validationErr != nil || digest != reference.ObservationDigest || observation.ObservationID != reference.ObservationID {
			return nil, newError(DeniedError, EvidenceBindingMismatch, validationErr)
		}
		if observation.Scope != input.Scope {
			return nil, newError(DeniedError, ScopeMismatch, nil)
		}
		if observation.Identifier != input.Identifier {
			return nil, newError(DeniedError, IdentifierIncompatible, nil)
		}
		if classificationRank(observation.Evidence.Classification) > classificationRank(caseClassification) {
			return nil, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		decision, verifyErr := dependencies.Evidence.VerifyObservation(ctx, input.Scope, observation.Identifier, observation.Evidence)
		if verifyErr = dependencyError(ctx, verifyErr); verifyErr != nil {
			return nil, verifyErr
		}
		if !decision.Verified || !digestPattern.MatchString(decision.DecisionDigest) {
			return nil, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		if observation.Validity == "current" {
			matched[reference] = struct{}{}
		}
	}
	return matched, nil
}

func loadMatchedEntities(ctx context.Context, store EntityStore, input Observation, caseClassification string,
	observations map[ObservationRef]struct{}) ([]EntityRef, error) {
	references, err := store.LoadEntitiesByMatch(ctx, input.Scope, input.Identifier)
	if err = dependencyError(ctx, err); err != nil {
		return nil, err
	}
	if len(references) > MaximumLookupEntities {
		return nil, newError(InvalidInputError, InvalidInput, nil)
	}
	seen := make(map[string]struct{}, len(references))
	active := make([]EntityRef, 0, len(references))
	for _, reference := range references {
		if !validEntityRef(reference) {
			return nil, newError(InvalidInputError, InvalidInput, nil)
		}
		if _, duplicate := seen[reference.EntityID]; duplicate {
			return nil, newError(InvalidInputError, InvalidInput, nil)
		}
		seen[reference.EntityID] = struct{}{}
		entity, found, loadErr := store.LoadEntity(ctx, input.Scope, reference)
		if loadErr = dependencyError(ctx, loadErr); loadErr != nil {
			return nil, loadErr
		}
		if !found {
			return nil, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		if entity.Scope != input.Scope {
			return nil, newError(DeniedError, ScopeMismatch, nil)
		}
		if !validLookupEntity(entity, reference) {
			return nil, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		if classificationRank(entity.Classification) < classificationRank(input.Evidence.Classification) ||
			classificationRank(entity.Classification) > classificationRank(caseClassification) {
			return nil, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		if entity.Status == "superseded" {
			continue
		}
		bound := false
		for _, member := range entity.MemberObservations {
			if _, exists := observations[member]; exists {
				bound = true
				break
			}
		}
		if !bound {
			return nil, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		active = append(active, reference)
	}
	slices.SortFunc(active, func(left, right EntityRef) int {
		if comparison := compareString(left.EntityID, right.EntityID); comparison != 0 {
			return comparison
		}
		if left.Revision < right.Revision {
			return -1
		}
		if left.Revision > right.Revision {
			return 1
		}
		return compareString(left.RecordDigest, right.RecordDigest)
	})
	return active, nil
}

func validCaseDecision(value CaseDecision, observationClassification string) bool {
	return value.Verified && value.Current && value.CaseRevision > 0 && value.CaseRevision <= math.MaxInt64 &&
		digestPattern.MatchString(value.DecisionDigest) && validClassification(value.Classification) &&
		classificationRank(value.Classification) >= classificationRank(observationClassification)
}

func validEntityRef(value EntityRef) bool {
	return uuidPattern.MatchString(value.EntityID) && value.Revision > 0 && value.Revision <= math.MaxInt64 &&
		digestPattern.MatchString(value.RecordDigest)
}

func validLookupEntity(value Entity, reference EntityRef) bool {
	if value.SchemaVersion != EntitySchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		value.EntityID != reference.EntityID || value.Revision != reference.Revision || !validClassification(value.Classification) ||
		!slices.Contains([]string{"active", "superseded"}, value.Status) || len(value.MemberObservations) == 0 ||
		len(value.MemberObservations) > MaximumLookupObservations {
		return false
	}
	seen := make(map[string]struct{}, len(value.MemberObservations))
	for _, member := range value.MemberObservations {
		if !uuidPattern.MatchString(member.ObservationID) || !digestPattern.MatchString(member.ObservationDigest) {
			return false
		}
		if _, duplicate := seen[member.ObservationID]; duplicate {
			return false
		}
		seen[member.ObservationID] = struct{}{}
	}
	return true
}

func dependencyError(ctx context.Context, err error) error {
	if contextErr := checkContext(ctx); contextErr != nil {
		return contextErr
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return newError(CanceledError, ContextCanceled, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(TimeoutError, ContextDeadline, err)
	}
	return newError(UnavailableError, DependencyUnavailableReason, err)
}

func classificationRank(value string) int {
	return slices.Index([]string{"public", "internal", "confidential", "restricted"}, value)
}

func compareString(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return slices.Contains([]reflect.Kind{reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice},
		reflected.Kind()) && reflected.IsNil()
}
