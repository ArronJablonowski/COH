package entityresolution

import (
	"context"
	"slices"
)

func planResolve(ctx context.Context, dependencies Dependencies, command Command, candidate Candidate) (TransitionPlan, error) {
	if candidate.Result == "ambiguous" || len(candidate.MatchingEntities) > 1 {
		return TransitionPlan{}, newError(DeniedError, CandidateAmbiguous, nil)
	}
	if !sameCanonicalValue(command.InputEntities, candidate.MatchingEntities) || command.OutputEntityID == nil ||
		command.DecisionID == nil || command.HistoryID == nil || command.HistorySequence == nil || command.Confidence == nil {
		return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
	}
	observation, found, err := dependencies.Observations.LoadObservation(ctx, command.Scope, candidate.Observation)
	if err = dependencyError(ctx, err); err != nil {
		return TransitionPlan{}, err
	}
	if !found || observation.Scope != command.Scope {
		return TransitionPlan{}, newError(DeniedError, EvidenceBindingMismatch, nil)
	}
	_, observationDigest, err := CanonicalObservation(ctx, observation)
	if err != nil || observationDigest != candidate.Observation.ObservationDigest {
		return TransitionPlan{}, newError(DeniedError, EvidenceBindingMismatch, err)
	}
	metadata := transitionMetadataFromCommand(command, "")
	if len(candidate.MatchingEntities) == 0 {
		if err := ensureNewEntityIDs(ctx, dependencies.Entities, command.Scope, []string{*command.OutputEntityID}); err != nil {
			return TransitionPlan{}, err
		}
		output, err := newActiveDraft(ctx, *command.OutputEntityID, command.Scope, observation.Evidence.Classification,
			[]ObservationRef{candidate.Observation}, []AliasProof{}, *command.Confidence, []string{}, command.RequestedAt)
		if err != nil {
			return TransitionPlan{}, err
		}
		return finalizeTransition(metadata, Resolve, []EntityRef{}, []EntityRevisionDraft{output}, []EntityRevisionDraft{},
			[]Partition{}, []string{}, "")
	}
	entities, references, err := loadCurrentInputs(ctx, dependencies.Entities, command.Scope, command.InputEntities, 1)
	if err != nil {
		return TransitionPlan{}, err
	}
	input := entities[0]
	if input.EntityID != *command.OutputEntityID || input.UpdatedAt > command.RequestedAt {
		return TransitionPlan{}, newError(ConflictError, RevisionConflict, nil)
	}
	for _, member := range input.MemberObservations {
		if member.ObservationID == candidate.Observation.ObservationID {
			return TransitionPlan{}, newError(ConflictError, RevisionConflict, nil)
		}
	}
	members := cloneSlice(input.MemberObservations)
	members = append(members, candidate.Observation)
	slices.SortFunc(members, compareObservationRef)
	classification := input.Classification
	if classificationRank(observation.Evidence.Classification) > classificationRank(classification) {
		classification = observation.Evidence.Classification
	}
	value := input
	value.Revision++
	value.Classification = classification
	value.MemberObservations = members
	value.Confidence = *command.Confidence
	value.UpdatedAt = command.RequestedAt
	value.CreationDecisionDigest, value.HistoryHeadDigest, value.AuditDigest, value.ProvenanceDigest = "", "", "", ""
	value.PreviousProvenanceDigests = []string{input.ProvenanceDigest}
	_, recordDigest, err := EntityRecordDigest(ctx, value)
	if err != nil {
		return TransitionPlan{}, err
	}
	output := EntityRevisionDraft{Entity: value,
		Reference: EntityRef{EntityID: value.EntityID, Revision: value.Revision, RecordDigest: recordDigest}}
	if err := validateHistoryParents(ctx, dependencies.Entities, command.Scope, []string{input.HistoryHeadDigest}, *command.HistorySequence); err != nil {
		return TransitionPlan{}, err
	}
	return finalizeTransition(metadata, Resolve, references, []EntityRevisionDraft{output}, []EntityRevisionDraft{},
		[]Partition{}, []string{input.HistoryHeadDigest}, "")
}

func transitionMetadataFromCommand(command Command, commandDigest string) TransitionMetadata {
	return TransitionMetadata{DecisionID: *command.DecisionID, HistoryID: *command.HistoryID, HistorySequence: *command.HistorySequence,
		OperationID: command.OperationID, Scope: command.Scope, ActorID: command.ActorID, ActorRevision: command.ActorRevision,
		CommandDigest: commandDigest, Reason: command.Reason, SupportingEvidence: cloneSlice(command.SupportingEvidence),
		Counterevidence: cloneSlice(command.Counterevidence), Confidence: *command.Confidence,
		CreatedAt: command.RequestedAt, Deadline: command.Deadline, ReversesHistoryDigest: command.ReversesHistoryDigest}
}
