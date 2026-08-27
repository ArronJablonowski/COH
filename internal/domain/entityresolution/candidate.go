package entityresolution

import (
	"context"
)

func BuildCandidate(ctx context.Context, candidateID, operationID string, lookup CandidateLookupResult, confidence Confidence,
	createdAt string) (Candidate, []byte, string, error) {
	value := Candidate{SchemaVersion: CandidateSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		CandidateID: candidateID, OperationID: operationID, Scope: lookup.Scope, Identifier: lookup.Identifier,
		Observation: lookup.Observation, MatchingEntities: cloneSlice(lookup.MatchingEntities),
		Result: lookup.Result, Confidence: confidence, CreatedAt: createdAt}
	canonical, digest, err := CanonicalCandidate(ctx, value)
	if err != nil {
		return Candidate{}, nil, "", err
	}
	return value, canonical, digest, nil
}

func composeDeclaredConfidence(ctx context.Context, dependencies Dependencies, scope Scope, embedded *Observation,
	assessments []ConfidenceAssessment, counterevidence []Counterevidence, matchingEntityCount uint32,
	declared Confidence) (Confidence, error) {
	if !validConfidenceAssessments(assessments) || len(assessments) == 0 || nilDependency(dependencies.Evidence) {
		return Confidence{}, newError(InvalidInputError, ConfidenceInvalid, nil)
	}
	evidence := make([]ConfidenceEvidenceInput, 0, len(assessments))
	for _, assessment := range assessments {
		observation, found, err := loadAssessedObservation(ctx, dependencies.Observations, scope, embedded, assessment.Observation)
		if err != nil {
			return Confidence{}, err
		}
		if !found || observation.Scope != scope {
			return Confidence{}, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		decision, err := dependencies.Evidence.VerifyEvidenceLink(ctx, scope, assessment.EvidenceLink)
		if err = dependencyError(ctx, err); err != nil {
			return Confidence{}, err
		}
		if !decision.Verified || !digestPattern.MatchString(decision.DecisionDigest) {
			return Confidence{}, newError(DeniedError, EvidenceBindingMismatch, nil)
		}
		evidence = append(evidence, ConfidenceEvidenceInput{Observation: observation,
			ObservationDigest: assessment.Observation.ObservationDigest, Link: assessment.EvidenceLink,
			SourceQuality: assessment.SourceQuality, Recency: assessment.Recency})
	}
	computed, _, _, err := ComposeConfidence(ctx, ConfidenceInput{Evidence: evidence, Counterevidence: counterevidence,
		MatchingEntityCount: matchingEntityCount})
	if err != nil || !sameCanonicalValue(computed, declared) {
		return Confidence{}, newError(InvalidInputError, ConfidenceInvalid, err)
	}
	return computed, nil
}

func loadAssessedObservation(ctx context.Context, store ObservationStore, scope Scope, embedded *Observation,
	reference ObservationRef) (Observation, bool, error) {
	if embedded != nil && embedded.ObservationID == reference.ObservationID {
		_, digest, err := CanonicalObservation(ctx, *embedded)
		if err != nil || digest != reference.ObservationDigest {
			return Observation{}, false, newError(InvalidInputError, ConfidenceInvalid, err)
		}
		return *embedded, true, nil
	}
	if nilDependency(store) {
		return Observation{}, false, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	observation, found, err := store.LoadObservation(ctx, scope, reference)
	if err = dependencyError(ctx, err); err != nil {
		return Observation{}, false, err
	}
	if found {
		_, digest, validationErr := CanonicalObservation(ctx, observation)
		if validationErr != nil || digest != reference.ObservationDigest || observation.ObservationID != reference.ObservationID {
			return Observation{}, false, newError(DeniedError, EvidenceBindingMismatch, validationErr)
		}
	}
	return observation, found, nil
}
