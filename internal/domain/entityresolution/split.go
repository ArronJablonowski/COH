package entityresolution

import (
	"context"
	"slices"
)

type SplitPartitionRequest struct {
	PartitionID        string
	OutputEntityID     string
	MemberObservations []ObservationRef
	AliasProofDigests  []string
	Confidence         Confidence
}

type SplitRequest struct {
	Metadata    TransitionMetadata
	InputEntity EntityRef
	Partitions  []SplitPartitionRequest
}

func PlanSplit(ctx context.Context, dependencies Dependencies, request SplitRequest) (TransitionPlan, error) {
	if err := checkContext(ctx); err != nil {
		return TransitionPlan{}, err
	}
	if err := validateTransitionMetadata(request.Metadata); err != nil || request.Metadata.ReversesHistoryDigest == nil ||
		!slices.Contains([]string{"counterevidence_split", "incorrect_observation", "analyst_rejection"}, request.Metadata.Reason) ||
		len(request.Metadata.Counterevidence) == 0 || len(request.Partitions) < 2 || len(request.Partitions) > 256 {
		return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, err)
	}
	entities, references, err := loadCurrentInputs(ctx, dependencies.Entities, request.Metadata.Scope, []EntityRef{request.InputEntity}, 1)
	if err != nil {
		return TransitionPlan{}, err
	}
	input := entities[0]
	if input.UpdatedAt > request.Metadata.CreatedAt {
		return TransitionPlan{}, newError(ConflictError, RevisionConflict, nil)
	}
	authorizationDigest, err := verifyTransitionAuthorization(ctx, dependencies.Authorization, Split, request.Metadata, references)
	if err != nil {
		return TransitionPlan{}, err
	}
	if err := validateHistoryAncestry(ctx, dependencies.Entities, request.Metadata.Scope, input.HistoryHeadDigest,
		*request.Metadata.ReversesHistoryDigest); err != nil {
		return TransitionPlan{}, err
	}
	if err := validateHistoryParents(ctx, dependencies.Entities, request.Metadata.Scope, []string{input.HistoryHeadDigest},
		request.Metadata.HistorySequence); err != nil {
		return TransitionPlan{}, err
	}

	partitions := append([]SplitPartitionRequest(nil), request.Partitions...)
	slices.SortFunc(partitions, func(left, right SplitPartitionRequest) int { return compareString(left.PartitionID, right.PartitionID) })
	memberSet := make(map[ObservationRef]struct{}, len(input.MemberObservations))
	for _, member := range input.MemberObservations {
		memberSet[member] = struct{}{}
	}
	aliasSet := make(map[string]AliasProof, len(input.AliasProofs))
	if err := verifyAliasProofs(ctx, dependencies.Matches, request.Metadata.Scope, input.AliasProofs); err != nil {
		return TransitionPlan{}, err
	}
	for _, alias := range input.AliasProofs {
		digest, digestErr := AliasProofDigest(alias)
		if digestErr != nil {
			return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, digestErr)
		}
		aliasSet[digest] = alias
	}
	assignedMembers := make(map[ObservationRef]struct{}, len(memberSet))
	assignedAliases := make(map[string]struct{}, len(aliasSet))
	seenOutputIDs := make(map[string]struct{}, len(partitions))
	outputIDs := make([]string, 0, len(partitions))
	for _, partition := range partitions {
		outputIDs = append(outputIDs, partition.OutputEntityID)
	}
	if err := ensureNewEntityIDs(ctx, dependencies.Entities, request.Metadata.Scope, outputIDs); err != nil {
		return TransitionPlan{}, err
	}
	decisionPartitions := make([]Partition, 0, len(partitions))
	outputs := make([]EntityRevisionDraft, 0, len(partitions))
	for index, partition := range partitions {
		if !tokenPattern.MatchString(partition.PartitionID) || index > 0 && partitions[index-1].PartitionID == partition.PartitionID ||
			!uuidPattern.MatchString(partition.OutputEntityID) || partition.OutputEntityID == input.EntityID ||
			len(partition.MemberObservations) == 0 || len(partition.MemberObservations) > MaximumLookupObservations ||
			!validConfidenceRecord(partition.Confidence) {
			return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
		}
		if _, duplicate := seenOutputIDs[partition.OutputEntityID]; duplicate {
			return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
		}
		seenOutputIDs[partition.OutputEntityID] = struct{}{}
		members := append([]ObservationRef(nil), partition.MemberObservations...)
		for memberIndex, member := range members {
			if !validObservationRef(member) || memberIndex > 0 && compareObservationRef(members[memberIndex-1], member) >= 0 {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
			}
			if _, exists := memberSet[member]; !exists {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
			}
			if _, duplicate := assignedMembers[member]; duplicate {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
			}
			assignedMembers[member] = struct{}{}
		}
		if !confidenceBoundToMembers(partition.Confidence, members) || !validDigestSet(partition.AliasProofDigests) {
			return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
		}
		aliases := make([]AliasProof, 0, len(partition.AliasProofDigests))
		for _, digest := range partition.AliasProofDigests {
			alias, exists := aliasSet[digest]
			if !exists {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
			}
			if _, duplicate := assignedAliases[digest]; duplicate {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
			}
			assignedAliases[digest] = struct{}{}
			aliases = append(aliases, alias)
		}
		slices.SortFunc(aliases, compareAliasProof)
		output, outputErr := newActiveDraft(ctx, partition.OutputEntityID, request.Metadata.Scope, input.Classification,
			members, aliases, partition.Confidence, request.Metadata.CreatedAt)
		if outputErr != nil {
			return TransitionPlan{}, outputErr
		}
		outputs = append(outputs, output)
		decisionPartitions = append(decisionPartitions, Partition{PartitionID: partition.PartitionID, OutputEntityID: partition.OutputEntityID,
			MemberObservations: members, AliasProofDigests: append([]string(nil), partition.AliasProofDigests...)})
	}
	if len(assignedMembers) != len(memberSet) || len(assignedAliases) != len(aliasSet) {
		return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
	}
	superseded, err := supersededDraft(ctx, input, request.Metadata.CreatedAt)
	if err != nil {
		return TransitionPlan{}, err
	}
	return finalizeTransition(request.Metadata, Split, references, outputs, []EntityRevisionDraft{superseded}, decisionPartitions,
		[]string{input.HistoryHeadDigest}, authorizationDigest)
}

func confidenceBoundToMembers(confidence Confidence, members []ObservationRef) bool {
	memberSet := make(map[ObservationRef]struct{}, len(members))
	for _, member := range members {
		memberSet[member] = struct{}{}
	}
	for _, link := range confidence.SupportingEvidence {
		if _, exists := memberSet[ObservationRef{ObservationID: link.ObservationID, ObservationDigest: link.ObservationDigest}]; !exists {
			return false
		}
	}
	return true
}
