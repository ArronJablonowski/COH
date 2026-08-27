package entityresolution

import (
	"context"
	"math"
	"slices"
)

func validateHistoryAncestry(ctx context.Context, store EntityStore, scope Scope, headDigest, targetDigest string) error {
	if !digestPattern.MatchString(headDigest) || !digestPattern.MatchString(targetDigest) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	found, err := validateHistoryGraph(ctx, store, scope, []string{headDigest}, 0, &targetDigest)
	if err != nil {
		return err
	}
	if !found {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func validateHistoryParents(ctx context.Context, store EntityStore, scope Scope, heads []string, newSequence uint64) error {
	if len(heads) == 0 || !validDigestSet(uniqueSortedDigests(heads)) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	_, err := validateHistoryGraph(ctx, store, scope, uniqueSortedDigests(heads), newSequence, nil)
	return err
}

func validateHistoryGraph(ctx context.Context, store EntityStore, scope Scope, heads []string, childSequence uint64,
	targetDigest *string) (bool, error) {
	state := make(map[string]uint8)
	sequences := make(map[string]uint64)
	count, targetFound := 0, false
	var walk func(string, uint64) error
	walk = func(digest string, childSequence uint64) error {
		if state[digest] == 1 {
			return newError(InvalidInputError, TransitionInvalid, nil)
		}
		if state[digest] == 2 {
			if childSequence != 0 && sequences[digest] >= childSequence {
				return newError(InvalidInputError, TransitionInvalid, nil)
			}
			return nil
		}
		count++
		if count > MaximumLookupObservations {
			return newError(InvalidInputError, TransitionInvalid, nil)
		}
		state[digest] = 1
		history, found, err := store.LoadHistory(ctx, scope, digest)
		if err = dependencyError(ctx, err); err != nil {
			return err
		}
		if !found || !validHistoryRecord(history) || history.Scope != scope || childSequence != 0 && history.Sequence >= childSequence {
			return newError(InvalidInputError, TransitionInvalid, nil)
		}
		sequences[digest] = history.Sequence
		_, actualDigest, err := canonicalValue(history)
		if err != nil || actualDigest != digest {
			return newError(InvalidInputError, TransitionInvalid, err)
		}
		if targetDigest != nil && digest == *targetDigest {
			if !slices.Contains([]Operation{Merge, Split}, history.Operation) {
				return newError(InvalidInputError, TransitionInvalid, nil)
			}
			targetFound = true
		}
		for _, parent := range history.PreviousHistoryDigests {
			if err := walk(parent, history.Sequence); err != nil {
				return err
			}
		}
		state[digest] = 2
		return nil
	}
	for _, head := range heads {
		if err := walk(head, childSequence); err != nil {
			return false, err
		}
	}
	return targetFound, nil
}

func validHistoryRecord(value History) bool {
	if value.SchemaVersion != HistorySchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		!uuidPattern.MatchString(value.HistoryID) || value.Sequence == 0 || value.Sequence > math.MaxInt64 || !validScope(value.Scope) ||
		!slices.Contains([]Operation{Resolve, Merge, Split, Reject, Reindex}, value.Operation) ||
		!digestPattern.MatchString(value.DecisionDigest) || len(value.InputEntities) > MaximumLookupObservations ||
		len(value.OutputEntities) > MaximumLookupObservations || len(value.PreviousHistoryDigests) > MaximumLookupObservations ||
		value.ReversesHistoryDigest != nil && !digestPattern.MatchString(*value.ReversesHistoryDigest) || !validTimestamp(value.CreatedAt) {
		return false
	}
	for index, reference := range value.InputEntities {
		if !validEntityRef(reference) || index > 0 && compareEntityRef(value.InputEntities[index-1], reference) >= 0 {
			return false
		}
	}
	for index, reference := range value.OutputEntities {
		if !validEntityRef(reference) || index > 0 && compareEntityRef(value.OutputEntities[index-1], reference) >= 0 {
			return false
		}
	}
	return validDigestSet(value.PreviousHistoryDigests)
}
