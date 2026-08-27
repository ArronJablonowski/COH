package investigationprojection

import (
	"context"
	"math"
	"slices"
)

func validateFact(ctx context.Context, value Fact) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	allowedTypes := []string{"observation", "claim", "evidence_support", "evidence_refute", "unknown", "time_order",
		"completeness", "hypothesis_disposition", "entity_revision"}
	if value.SchemaVersion != FactSchemaVersion || value.ContractVersion != ContractVersion || value.ReducerVersion != ReducerVersion ||
		!uuidPattern.MatchString(value.FactID) || !validScope(value.Scope) || value.Sequence == 0 || value.Sequence > math.MaxInt64 ||
		!slices.Contains(allowedTypes, value.FactType) || !tokenPattern.MatchString(value.SubjectID) ||
		value.ClaimID != nil && !tokenPattern.MatchString(*value.ClaimID) || value.HypothesisID != nil &&
		!tokenPattern.MatchString(*value.HypothesisID) || value.DuplicateOf != nil && !tokenPattern.MatchString(*value.DuplicateOf) ||
		!validDigestSet(value.GapDigests) || !validDigestSet(value.ConflictDigests) ||
		!validDigestSet(value.SupportingEvidenceDigests) || !validDigestSet(value.CounterevidenceDigests) ||
		!validUnknowns(value.Unknowns) || !validEntityRefs(value.EntityRefs) || !validTimeRefs(value.TimeRefs) ||
		value.Confidence != nil && !validConfidence(*value.Confidence) || !validCompleteness(value.Completeness) ||
		!validBinding(value.Binding) || !digestPattern.MatchString(value.PayloadDigest) || !validTimestamp(value.CommittedAt) ||
		!sameEntityRefs(value.EntityRefs, value.Binding.EntityRefs) || !sameTimeRefs(value.TimeRefs, value.Binding.TimeRefs) {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	if value.Sequence == 1 && value.PreviousFactDigest != nil || value.Sequence > 1 &&
		(value.PreviousFactDigest == nil || !digestPattern.MatchString(*value.PreviousFactDigest)) {
		return newError(InvalidInputError, IntegrityFailure, nil)
	}
	if value.Binding.AuthoritativeStateDigest == "" {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	switch value.FactType {
	case "claim":
		if value.ClaimID == nil || value.Confidence == nil || value.HypothesisDisposition != nil ||
			value.TimeRelation != nil || value.OrderConfidenceMillionths != nil {
			return newError(InvalidInputError, InvalidInput, nil)
		}
	case "evidence_support", "evidence_refute", "unknown", "entity_revision":
		if value.ClaimID == nil || value.HypothesisDisposition != nil || value.TimeRelation != nil || value.OrderConfidenceMillionths != nil {
			return newError(InvalidInputError, InvalidInput, nil)
		}
	case "hypothesis_disposition":
		if value.HypothesisID == nil || value.HypothesisDisposition == nil ||
			!slices.Contains([]string{"open", "supported", "refuted", "inconclusive"}, *value.HypothesisDisposition) ||
			value.TimeRelation != nil || value.OrderConfidenceMillionths != nil {
			return newError(InvalidInputError, InvalidInput, nil)
		}
	case "time_order":
		if value.TimeRelation == nil || !slices.Contains([]string{"genesis", "before", "after", "overlap", "equal", "uncertain"}, *value.TimeRelation) ||
			value.OrderConfidenceMillionths == nil || *value.OrderConfidenceMillionths > 1_000_000 || len(value.TimeRefs) != 1 ||
			value.HypothesisDisposition != nil {
			return newError(InvalidInputError, InvalidInput, nil)
		}
	default:
		if value.HypothesisDisposition != nil || value.TimeRelation != nil || value.OrderConfidenceMillionths != nil {
			return newError(InvalidInputError, InvalidInput, nil)
		}
	}
	return nil
}

func validBinding(value AuthoritativeBinding) bool {
	if value.CaseRevision == 0 || value.CaseRevision > math.MaxInt64 || value.MappingRevision == 0 ||
		value.MappingRevision > math.MaxInt64 || value.NormalizedEventSchemaVersion != "coh.normalized-event-envelope/v1" ||
		!validEntityRefs(value.EntityRefs) || !validTimeRefs(value.TimeRefs) {
		return false
	}
	for _, digest := range []string{value.CaseDigest, value.ArtifactDigest, value.ManifestDigest, value.IngestReceiptDigest,
		value.CustodyHeadDigest, value.AuditHeadDigest, value.SourceProvenanceDigest, value.NormalizedEventDigest,
		value.MappingOutcomeDigest, value.MappingManifestDigest, value.AuthoritativeStateDigest} {
		if !digestPattern.MatchString(digest) {
			return false
		}
	}
	return true
}

func validateProjection(ctx context.Context, value Projection) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != ProjectionSchemaVersion || value.ContractVersion != ContractVersion || value.ReducerVersion != ReducerVersion ||
		!uuidPattern.MatchString(value.ProjectionID) || !validScope(value.Scope) || !validKind(value.Kind) ||
		!validStateVersion(value.StateVersion) || !validWatermark(value.Watermark) || value.FactCount != value.Watermark.Sequence ||
		value.StateVersion.AuthoritativeStateDigest != value.Watermark.AuthoritativeStateDigest ||
		!digestPattern.MatchString(value.FactSetDigest) || value.Claims == nil || value.Hypotheses == nil || value.Timeline == nil ||
		len(value.Claims) > MaximumOutputs || len(value.Hypotheses) > MaximumOutputs || len(value.Timeline) > MaximumOutputs ||
		!validCompleteness(value.Completeness) || !digestPattern.MatchString(value.AuditDigest) ||
		!digestPattern.MatchString(value.ProvenanceDigest) || !digestPattern.MatchString(value.ProjectionDigest) ||
		!validTimestamp(value.CreatedAt) || !validProjectionValues(value) {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	if value.Kind == Correlation && (len(value.Hypotheses) != 0 || len(value.Timeline) != 0) ||
		value.Kind == Hypothesis && len(value.Timeline) != 0 || value.Kind == Timeline && len(value.Hypotheses) != 0 {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	return nil
}

func validProjectionValues(value Projection) bool {
	for index, claim := range value.Claims {
		if !validClaim(claim) || index > 0 && value.Claims[index-1].ClaimID >= claim.ClaimID {
			return false
		}
	}
	for index, hypothesis := range value.Hypotheses {
		if !validHypothesis(hypothesis) || index > 0 && value.Hypotheses[index-1].HypothesisID >= hypothesis.HypothesisID {
			return false
		}
	}
	for index, entry := range value.Timeline {
		if !validTimelineEntry(entry) || index > 0 && value.Timeline[index-1].FactSequence >= entry.FactSequence {
			return false
		}
	}
	return true
}

func validClaim(value Claim) bool {
	return tokenPattern.MatchString(value.ClaimID) && digestPattern.MatchString(value.ClaimDigest) &&
		validDigestSet(value.SupportingEvidenceDigests) && validDigestSet(value.CounterevidenceDigests) &&
		validUnknowns(value.Unknowns) && validEntityRefs(value.EntityRefs) && validConfidence(value.Confidence) &&
		validCompleteness(value.Completeness)
}

func validHypothesis(value HypothesisValue) bool {
	return tokenPattern.MatchString(value.HypothesisID) && validTokenSet(value.ClaimIDs) &&
		slices.Contains([]string{"open", "supported", "refuted", "inconclusive"}, value.Disposition) &&
		validDigestSet(value.SupportingEvidenceDigests) && validDigestSet(value.CounterevidenceDigests) &&
		validUnknowns(value.Unknowns) && validConfidence(value.Confidence) && validCompleteness(value.Completeness)
}

func validTimelineEntry(value TimelineEntry) bool {
	return tokenPattern.MatchString(value.EntryID) && value.FactSequence > 0 && value.FactSequence <= math.MaxInt64 &&
		validTokenSet(value.ClaimIDs) && validEntityRefs(value.EntityRefs) && validTimeRefs([]TimeRef{value.TimeRef}) &&
		slices.Contains([]string{"genesis", "before", "after", "overlap", "equal", "uncertain"}, value.RelationToPrevious) &&
		value.OrderConfidenceMillionths <= 1_000_000 && (value.DuplicateOf == nil || tokenPattern.MatchString(*value.DuplicateOf)) &&
		validDigestSet(value.GapDigests) && validDigestSet(value.ConflictDigests) && validUnknowns(value.Unknowns)
}

func validateCheckpoint(ctx context.Context, value Checkpoint) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != CheckpointSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.CheckpointID) || !validScope(value.Scope) || !validKind(value.Kind) ||
		!validStateVersion(value.StateVersion) || !validWatermark(value.Watermark) ||
		value.StateVersion.AuthoritativeStateDigest != value.Watermark.AuthoritativeStateDigest ||
		!digestPattern.MatchString(value.FactSetDigest) || !digestPattern.MatchString(value.ProjectionDigest) ||
		value.PreviousCheckpointDigest != nil && !digestPattern.MatchString(*value.PreviousCheckpointDigest) ||
		!digestPattern.MatchString(value.AuditDigest) || !digestPattern.MatchString(value.ProvenanceDigest) ||
		!digestPattern.MatchString(value.CheckpointDigest) || !validTimestamp(value.CreatedAt) {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	return nil
}

func validateWatermarkRecord(ctx context.Context, value WatermarkRecord) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != WatermarkSchemaVersion || value.ContractVersion != ContractVersion || !validScope(value.Scope) ||
		!validStateVersion(value.StateVersion) || !validWatermark(value.Watermark) ||
		value.StateVersion.AuthoritativeStateDigest != value.Watermark.AuthoritativeStateDigest {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	return nil
}

func validateQuery(ctx context.Context, value Query) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != QuerySchemaVersion || value.ContractVersion != ContractVersion || !uuidPattern.MatchString(value.QueryID) ||
		!digestPattern.MatchString(value.IdempotencyKey) || !validScope(value.Scope) || !validKind(value.Kind) ||
		!slices.Contains([]string{"current", "exact"}, value.Consistency) || !validStateVersion(value.StateVersion) ||
		value.MaxFacts == 0 || value.MaxFacts > MaximumFacts || value.MaxOutputs == 0 || value.MaxOutputs > MaximumOutputs ||
		!validTimestamp(value.RequestedAt) || !validTimestamp(value.Deadline) || value.RequestedAt >= value.Deadline ||
		!digestPattern.MatchString(value.QueryDigest) || value.Consistency == "current" && value.RequestedWatermark != nil ||
		value.Consistency == "exact" && (value.RequestedWatermark == nil || !validWatermark(*value.RequestedWatermark)) {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	return nil
}

func validateCacheEntry(ctx context.Context, value CacheEntry) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != CacheSchemaVersion || value.ContractVersion != ContractVersion || !digestPattern.MatchString(value.CacheKey) ||
		!digestPattern.MatchString(value.QueryDigest) || !validScope(value.Scope) || !validKind(value.Kind) ||
		!validStateVersion(value.StateVersion) || !validWatermark(value.Watermark) ||
		value.StateVersion.AuthoritativeStateDigest != value.Watermark.AuthoritativeStateDigest ||
		!digestPattern.MatchString(value.CheckpointDigest) || !digestPattern.MatchString(value.ProjectionDigest) || !validTimestamp(value.VerifiedAt) {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	return nil
}

func sameEntityRefs(left, right []EntityRef) bool { return slices.Equal(left, right) }
func sameTimeRefs(left, right []TimeRef) bool     { return slices.EqualFunc(left, right, sameTimeRef) }
func sameTimeRef(left, right TimeRef) bool {
	return left.TimeRecordDigest == right.TimeRecordDigest && left.Precision == right.Precision &&
		left.UncertaintyDigest == right.UncertaintyDigest && (left.ComparisonDigest == nil && right.ComparisonDigest == nil ||
		left.ComparisonDigest != nil && right.ComparisonDigest != nil && *left.ComparisonDigest == *right.ComparisonDigest)
}
