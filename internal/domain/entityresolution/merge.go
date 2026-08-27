package entityresolution

import (
	"context"
	"slices"
)

type MergeRequest struct {
	Metadata       TransitionMetadata
	InputEntities  []EntityRef
	OutputEntityID string
}

func PlanMerge(ctx context.Context, dependencies Dependencies, request MergeRequest) (TransitionPlan, error) {
	if err := checkContext(ctx); err != nil {
		return TransitionPlan{}, err
	}
	if err := validateTransitionMetadata(request.Metadata); err != nil || request.Metadata.ReversesHistoryDigest != nil ||
		!slices.Contains([]string{"manual_merge", "independent_corroboration", "key_rotation"}, request.Metadata.Reason) ||
		!uuidPattern.MatchString(request.OutputEntityID) {
		return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, err)
	}
	for _, item := range request.Metadata.Counterevidence {
		if item.BlocksMerge {
			return TransitionPlan{}, newError(DeniedError, CounterevidenceBlocked, nil)
		}
	}
	entities, references, err := loadCurrentInputs(ctx, dependencies.Entities, request.Metadata.Scope, request.InputEntities, 2)
	if err != nil {
		return TransitionPlan{}, err
	}
	for _, reference := range references {
		if reference.EntityID == request.OutputEntityID {
			return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
		}
	}
	if err := ensureNewEntityIDs(ctx, dependencies.Entities, request.Metadata.Scope, []string{request.OutputEntityID}); err != nil {
		return TransitionPlan{}, err
	}
	authorizationDigest, err := verifyTransitionAuthorization(ctx, dependencies.Authorization, Merge, request.Metadata, references)
	if err != nil {
		return TransitionPlan{}, err
	}

	members := make([]ObservationRef, 0)
	memberIDs := make(map[string]struct{})
	aliases := make([]AliasProof, 0)
	aliasDigests := make(map[string]struct{})
	parents := make([]string, 0, len(entities))
	provenanceParents := make([]string, 0, len(entities))
	classification := "public"
	superseded := make([]EntityRevisionDraft, 0, len(entities))
	for _, entity := range entities {
		if entity.UpdatedAt > request.Metadata.CreatedAt {
			return TransitionPlan{}, newError(ConflictError, RevisionConflict, nil)
		}
		if classificationRank(entity.Classification) > classificationRank(classification) {
			classification = entity.Classification
		}
		for _, member := range entity.MemberObservations {
			if _, duplicate := memberIDs[member.ObservationID]; duplicate {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
			}
			memberIDs[member.ObservationID] = struct{}{}
			members = append(members, member)
		}
		for _, alias := range entity.AliasProofs {
			digest, digestErr := AliasProofDigest(alias)
			if digestErr != nil {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, digestErr)
			}
			if _, duplicate := aliasDigests[digest]; duplicate {
				return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
			}
			aliasDigests[digest] = struct{}{}
			aliases = append(aliases, alias)
		}
		parents = append(parents, entity.HistoryHeadDigest)
		provenanceParents = append(provenanceParents, entity.ProvenanceDigest)
		draft, draftErr := supersededDraft(ctx, entity, request.Metadata.CreatedAt)
		if draftErr != nil {
			return TransitionPlan{}, draftErr
		}
		superseded = append(superseded, draft)
	}
	slices.SortFunc(members, compareObservationRef)
	slices.SortFunc(aliases, compareAliasProof)
	if err := verifyAliasProofs(ctx, dependencies.Matches, request.Metadata.Scope, aliases); err != nil {
		return TransitionPlan{}, err
	}
	if err := validateHistoryParents(ctx, dependencies.Entities, request.Metadata.Scope, parents, request.Metadata.HistorySequence); err != nil {
		return TransitionPlan{}, err
	}
	output, err := newActiveDraft(ctx, request.OutputEntityID, request.Metadata.Scope, classification, members, aliases,
		request.Metadata.Confidence, uniqueSortedDigests(provenanceParents), request.Metadata.CreatedAt)
	if err != nil {
		return TransitionPlan{}, err
	}
	return finalizeTransition(request.Metadata, Merge, references, []EntityRevisionDraft{output}, superseded, []Partition{},
		uniqueSortedDigests(parents), authorizationDigest)
}

func AliasProofDigest(value AliasProof) (string, error) {
	if !validAliasProof(value) {
		return "", newError(InvalidInputError, TransitionInvalid, nil)
	}
	_, digest, err := canonicalValue(value)
	return digest, err
}

func uniqueSortedDigests(values []string) []string {
	result := cloneSlice(values)
	slices.Sort(result)
	return slices.Compact(result)
}
