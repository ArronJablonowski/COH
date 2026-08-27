package investigationprojection

import (
	"context"
	"reflect"
	"slices"
)

type Value struct {
	Kind         Kind
	Claims       []Claim
	Hypotheses   []HypothesisValue
	Timeline     []TimelineEntry
	Completeness Completeness
}

type ReductionState struct {
	Scope         Scope
	StateVersion  StateVersion
	Watermark     Watermark
	FactCount     uint64
	FactSetDigest string
	Value         *Value
}

type Reducer struct{ kind Kind }

func NewReducer(kind Kind) (Reducer, error) {
	if !validKind(kind) {
		return Reducer{}, newError(InvalidInputError, InvalidInput, nil)
	}
	return Reducer{kind: kind}, nil
}

func (reducer Reducer) Reduce(ctx context.Context, previous *ReductionState, fact Fact,
	version StateVersion) (*ReductionState, error) {
	if !validKind(reducer.kind) || !validStateVersion(version) {
		return nil, newError(InvalidInputError, InvalidInput, nil)
	}
	_, factDigest, err := CanonicalFact(ctx, fact)
	if err != nil {
		return nil, err
	}
	if !factMatchesVersion(fact, version) {
		return nil, newError(DeniedError, AuthorityDenied, nil)
	}
	if err := validateReductionHead(previous, fact, version); err != nil {
		return nil, err
	}
	value, err := reduceValue(reducer.kind, previousValue(previous), fact)
	if err != nil {
		return nil, err
	}
	previousSetDigest := ""
	if previous != nil {
		previousSetDigest = previous.FactSetDigest
	}
	_, factSetDigest, err := canonicalValue(struct {
		PreviousDigest string `json:"previous_digest"`
		FactDigest     string `json:"fact_digest"`
		FactCount      uint64 `json:"fact_count"`
	}{previousSetDigest, factDigest, fact.Sequence})
	if err != nil {
		return nil, err
	}
	headDigest := factDigest
	return &ReductionState{Scope: fact.Scope, StateVersion: version,
		Watermark: Watermark{Sequence: fact.Sequence, HeadFactDigest: &headDigest, CommittedAt: fact.CommittedAt,
			AuthoritativeStateDigest: version.AuthoritativeStateDigest},
		FactCount: fact.Sequence, FactSetDigest: factSetDigest, Value: value}, nil
}

func validateReductionHead(previous *ReductionState, fact Fact, version StateVersion) error {
	if previous == nil {
		if fact.Sequence != 1 || fact.PreviousFactDigest != nil {
			return newError(ConflictError, IntegrityFailure, nil)
		}
		return nil
	}
	if previous.Value == nil || previous.Scope != fact.Scope {
		return newError(DeniedError, ScopeMismatch, nil)
	}
	if previous.StateVersion != version || previous.Watermark.AuthoritativeStateDigest != version.AuthoritativeStateDigest {
		return newError(ConflictError, IntegrityFailure, nil)
	}
	if previous.FactCount != previous.Watermark.Sequence || fact.Sequence != previous.FactCount+1 ||
		previous.Watermark.HeadFactDigest == nil || fact.PreviousFactDigest == nil ||
		*previous.Watermark.HeadFactDigest != *fact.PreviousFactDigest {
		return newError(ConflictError, IntegrityFailure, nil)
	}
	return nil
}

func factMatchesVersion(fact Fact, version StateVersion) bool {
	return fact.Binding.AuthoritativeStateDigest == version.AuthoritativeStateDigest &&
		fact.Binding.MappingManifestDigest == version.MappingManifestDigest &&
		fact.Binding.MappingRevision == version.MappingRevision
}

func previousValue(previous *ReductionState) *Value {
	if previous == nil {
		return nil
	}
	return previous.Value
}

func reduceValue(kind Kind, previous *Value, fact Fact) (*Value, error) {
	if previous != nil && previous.Kind != kind {
		return nil, newError(InvalidInputError, InvalidInput, nil)
	}
	value := &Value{Kind: kind, Claims: []Claim{}, Hypotheses: []HypothesisValue{}, Timeline: []TimelineEntry{},
		Completeness: cloneCompleteness(fact.Completeness)}
	if previous != nil {
		value.Claims = cloneSlice(previous.Claims)
		value.Hypotheses = cloneSlice(previous.Hypotheses)
		value.Timeline = cloneSlice(previous.Timeline)
		value.Completeness = cloneCompleteness(previous.Completeness)
	}
	changed, err := applyFact(value, fact)
	if err != nil {
		return nil, err
	}
	if previous != nil && !changed {
		return previous, nil
	}
	return value, nil
}

func applyFact(value *Value, fact Fact) (bool, error) {
	before := cloneValue(*value)
	if fact.FactType == "completeness" {
		value.Completeness = cloneCompleteness(fact.Completeness)
	}
	if value.Kind != Timeline && fact.FactType == "time_order" || value.Kind != Hypothesis &&
		fact.FactType == "hypothesis_disposition" {
		return !reflect.DeepEqual(before, *value), nil
	}
	if fact.ClaimID != nil && slices.Contains([]string{"claim", "evidence_support", "evidence_refute", "unknown", "entity_revision"}, fact.FactType) {
		if err := applyClaim(value, fact); err != nil {
			return false, err
		}
	}
	if value.Kind == Hypothesis && fact.FactType == "hypothesis_disposition" {
		if err := applyHypothesis(value, fact); err != nil {
			return false, err
		}
	}
	if value.Kind == Timeline && fact.FactType == "time_order" {
		if err := applyTimeline(value, fact); err != nil {
			return false, err
		}
	}
	return !reflect.DeepEqual(before, *value), nil
}

func applyClaim(value *Value, fact Fact) error {
	index, found := findClaim(value.Claims, *fact.ClaimID)
	if !found {
		if fact.FactType != "claim" || fact.Confidence == nil {
			return newError(ConflictError, IntegrityFailure, nil)
		}
		value.Claims = append(value.Claims, Claim{ClaimID: *fact.ClaimID, ClaimDigest: fact.PayloadDigest,
			SupportingEvidenceDigests: cloneSlice(fact.SupportingEvidenceDigests),
			CounterevidenceDigests:    cloneSlice(fact.CounterevidenceDigests), Unknowns: cloneSlice(fact.Unknowns),
			EntityRefs: cloneSlice(fact.EntityRefs), Confidence: *fact.Confidence, Completeness: cloneCompleteness(fact.Completeness)})
		slices.SortFunc(value.Claims, func(left, right Claim) int { return compareString(left.ClaimID, right.ClaimID) })
		return nil
	}
	claim := value.Claims[index]
	if fact.FactType == "claim" && claim.ClaimDigest != fact.PayloadDigest {
		return newError(ConflictError, ProjectionDivergent, nil)
	}
	claim.SupportingEvidenceDigests = unionStrings(claim.SupportingEvidenceDigests, fact.SupportingEvidenceDigests)
	claim.CounterevidenceDigests = unionStrings(claim.CounterevidenceDigests, fact.CounterevidenceDigests)
	claim.Unknowns = unionUnknowns(claim.Unknowns, fact.Unknowns)
	claim.EntityRefs = unionEntityRefs(claim.EntityRefs, fact.EntityRefs)
	if fact.Confidence != nil {
		claim.Confidence = *fact.Confidence
	}
	claim.Completeness = cloneCompleteness(fact.Completeness)
	value.Claims[index] = claim
	return nil
}

func applyHypothesis(value *Value, fact Fact) error {
	if fact.HypothesisID == nil || fact.HypothesisDisposition == nil || fact.Confidence == nil {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	index, found := findHypothesis(value.Hypotheses, *fact.HypothesisID)
	claimIDs := []string{}
	if fact.ClaimID != nil {
		claimIDs = []string{*fact.ClaimID}
	}
	if !found {
		value.Hypotheses = append(value.Hypotheses, HypothesisValue{HypothesisID: *fact.HypothesisID,
			ClaimIDs: claimIDs, Disposition: *fact.HypothesisDisposition,
			SupportingEvidenceDigests: cloneSlice(fact.SupportingEvidenceDigests),
			CounterevidenceDigests:    cloneSlice(fact.CounterevidenceDigests), Unknowns: cloneSlice(fact.Unknowns),
			Confidence: *fact.Confidence, Completeness: cloneCompleteness(fact.Completeness)})
		slices.SortFunc(value.Hypotheses, func(left, right HypothesisValue) int {
			return compareString(left.HypothesisID, right.HypothesisID)
		})
		return nil
	}
	hypothesis := value.Hypotheses[index]
	hypothesis.ClaimIDs = unionStrings(hypothesis.ClaimIDs, claimIDs)
	hypothesis.Disposition = *fact.HypothesisDisposition
	hypothesis.SupportingEvidenceDigests = unionStrings(hypothesis.SupportingEvidenceDigests, fact.SupportingEvidenceDigests)
	hypothesis.CounterevidenceDigests = unionStrings(hypothesis.CounterevidenceDigests, fact.CounterevidenceDigests)
	hypothesis.Unknowns = unionUnknowns(hypothesis.Unknowns, fact.Unknowns)
	hypothesis.Confidence, hypothesis.Completeness = *fact.Confidence, cloneCompleteness(fact.Completeness)
	value.Hypotheses[index] = hypothesis
	return nil
}

func applyTimeline(value *Value, fact Fact) error {
	if fact.TimeRelation == nil || fact.OrderConfidenceMillionths == nil || len(fact.TimeRefs) != 1 {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	for _, entry := range value.Timeline {
		if entry.EntryID == fact.SubjectID || entry.FactSequence == fact.Sequence {
			return newError(ConflictError, ProjectionDivergent, nil)
		}
	}
	claimIDs := []string{}
	if fact.ClaimID != nil {
		claimIDs = []string{*fact.ClaimID}
	}
	value.Timeline = append(value.Timeline, TimelineEntry{EntryID: fact.SubjectID, FactSequence: fact.Sequence,
		ClaimIDs: claimIDs, EntityRefs: cloneSlice(fact.EntityRefs), TimeRef: cloneTimeRef(fact.TimeRefs[0]), RelationToPrevious: *fact.TimeRelation,
		OrderConfidenceMillionths: *fact.OrderConfidenceMillionths, DuplicateOf: cloneString(fact.DuplicateOf),
		GapDigests: cloneSlice(fact.GapDigests), ConflictDigests: cloneSlice(fact.ConflictDigests),
		Unknowns: cloneSlice(fact.Unknowns)})
	return nil
}

func cloneValue(value Value) Value {
	value.Claims, value.Hypotheses, value.Timeline = cloneSlice(value.Claims), cloneSlice(value.Hypotheses), cloneSlice(value.Timeline)
	value.Completeness = cloneCompleteness(value.Completeness)
	return value
}

func cloneCompleteness(value Completeness) Completeness {
	value.QueriedSourceDigests = cloneSlice(value.QueriedSourceDigests)
	value.CompletedSourceDigests = cloneSlice(value.CompletedSourceDigests)
	value.GapDigests = cloneSlice(value.GapDigests)
	value.NegativeEvidenceDigests = cloneSlice(value.NegativeEvidenceDigests)
	value.ConflictDigests = cloneSlice(value.ConflictDigests)
	return value
}

func cloneTimeRef(value TimeRef) TimeRef {
	value.ComparisonDigest = cloneString(value.ComparisonDigest)
	return value
}

func cloneSlice[T any](values []T) []T {
	result := make([]T, len(values))
	copy(result, values)
	return result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func findClaim(values []Claim, id string) (int, bool) {
	index, found := slices.BinarySearchFunc(values, id, func(value Claim, target string) int {
		return compareString(value.ClaimID, target)
	})
	return index, found
}

func findHypothesis(values []HypothesisValue, id string) (int, bool) {
	index, found := slices.BinarySearchFunc(values, id, func(value HypothesisValue, target string) int {
		return compareString(value.HypothesisID, target)
	})
	return index, found
}

func unionStrings(left, right []string) []string {
	result := append(cloneSlice(left), right...)
	slices.Sort(result)
	return slices.Compact(result)
}

func unionUnknowns(left, right []Unknown) []Unknown {
	result := append(cloneSlice(left), right...)
	slices.SortFunc(result, compareUnknown)
	return slices.CompactFunc(result, func(first, second Unknown) bool { return compareUnknown(first, second) == 0 })
}

func unionEntityRefs(left, right []EntityRef) []EntityRef {
	result := append(cloneSlice(left), right...)
	slices.SortFunc(result, compareEntityRef)
	return slices.CompactFunc(result, func(first, second EntityRef) bool { return compareEntityRef(first, second) == 0 })
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
