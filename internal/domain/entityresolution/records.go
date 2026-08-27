package entityresolution

import (
	"context"
	"math"
	"slices"
)

func cloneSlice[T any](values []T) []T {
	result := make([]T, len(values))
	copy(result, values)
	return result
}

func CanonicalCommand(ctx context.Context, value Command) ([]byte, string, error) {
	if err := validateCommand(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalCandidate(ctx context.Context, value Candidate) ([]byte, string, error) {
	if err := validateCandidate(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalDecision(ctx context.Context, value Decision) ([]byte, string, error) {
	if err := validateDecision(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalHistory(ctx context.Context, value History) ([]byte, string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, "", err
	}
	if value.InputEntities == nil || value.OutputEntities == nil || value.PreviousHistoryDigests == nil || !validHistoryRecord(value) {
		return nil, "", newError(InvalidInputError, TransitionInvalid, nil)
	}
	return canonicalValue(value)
}

func CanonicalOutcome(ctx context.Context, value Outcome) ([]byte, string, error) {
	if err := validateOutcome(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalReceipt(ctx context.Context, value Receipt) ([]byte, string, error) {
	if err := validateReceipt(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func validateCommand(ctx context.Context, value Command) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		!uuidPattern.MatchString(value.OperationID) || !digestPattern.MatchString(value.IdempotencyKey) ||
		!slices.Contains([]Operation{Observe, Resolve, Merge, Split, Reject, Reindex}, value.Operation) || !validScope(value.Scope) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		!validTimestamp(value.RequestedAt) || !validTimestamp(value.Deadline) || value.RequestedAt >= value.Deadline ||
		value.InputEntities == nil || value.Partitions == nil || value.SupportingEvidence == nil || value.Counterevidence == nil ||
		value.ConfidenceAssessments == nil || !validEntityRefs(value.InputEntities) || !validPartitions(value.Partitions) ||
		!validConfidenceAssessments(value.ConfidenceAssessments) || !validOptionalUUID(value.CandidateID) ||
		!validOptionalUUID(value.DecisionID) || !validOptionalUUID(value.HistoryID) || !validOptionalUUID(value.OutputEntityID) ||
		value.HistorySequence != nil && (*value.HistorySequence == 0 || *value.HistorySequence > math.MaxInt64) ||
		value.ReversesHistoryDigest != nil && !digestPattern.MatchString(*value.ReversesHistoryDigest) ||
		value.CandidateDigest != nil && !digestPattern.MatchString(*value.CandidateDigest) {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	if value.Confidence != nil && (!validConfidenceRecord(*value.Confidence) ||
		!sameCanonicalValue(value.SupportingEvidence, value.Confidence.SupportingEvidence) ||
		!sameCanonicalValue(value.Counterevidence, value.Confidence.Counterevidence)) {
		return newError(InvalidInputError, ConfidenceInvalid, nil)
	}
	switch value.Operation {
	case Observe:
		if value.Observation == nil || value.CandidateID == nil || value.Confidence == nil || len(value.ConfidenceAssessments) == 0 ||
			value.Observation.OperationID != value.OperationID || value.Observation.Scope != value.Scope || value.CandidateDigest != nil ||
			value.DecisionID != nil || value.HistoryID != nil || value.HistorySequence != nil || value.OutputEntityID != nil ||
			value.ReversesHistoryDigest != nil || len(value.InputEntities) != 0 || len(value.Partitions) != 0 || value.Reason != "new_observation" {
			return newError(InvalidInputError, InvalidInput, nil)
		}
		_, _, err := CanonicalObservation(ctx, *value.Observation)
		return err
	case Resolve:
		if value.Observation != nil || value.CandidateID != nil || value.CandidateDigest == nil || value.DecisionID == nil ||
			value.HistoryID == nil || value.HistorySequence == nil || value.OutputEntityID == nil || value.Confidence == nil ||
			value.ReversesHistoryDigest != nil || len(value.ConfidenceAssessments) == 0 || len(value.InputEntities) > 1 || len(value.Partitions) != 0 ||
			!slices.Contains([]string{"exact_typed_match", "independent_corroboration"}, value.Reason) {
			return newError(InvalidInputError, InvalidInput, nil)
		}
	case Merge:
		if value.Observation != nil || value.CandidateID != nil || value.CandidateDigest != nil || value.DecisionID == nil ||
			value.HistoryID == nil || value.HistorySequence == nil || value.OutputEntityID == nil || value.Confidence == nil ||
			value.ReversesHistoryDigest != nil || len(value.ConfidenceAssessments) == 0 || len(value.InputEntities) < 2 || len(value.Partitions) != 0 ||
			!slices.Contains([]string{"manual_merge", "independent_corroboration", "key_rotation"}, value.Reason) {
			return newError(InvalidInputError, InvalidInput, nil)
		}
	case Split:
		if value.Observation != nil || value.CandidateID != nil || value.CandidateDigest != nil || value.DecisionID == nil ||
			value.HistoryID == nil || value.HistorySequence == nil || value.OutputEntityID != nil || value.Confidence == nil ||
			value.ReversesHistoryDigest == nil || len(value.ConfidenceAssessments) == 0 || len(value.InputEntities) != 1 || len(value.Partitions) < 2 ||
			len(value.Counterevidence) == 0 || !slices.Contains([]string{"counterevidence_split", "incorrect_observation", "analyst_rejection"}, value.Reason) {
			return newError(InvalidInputError, InvalidInput, nil)
		}
		for _, partition := range value.Partitions {
			if len(partition.ConfidenceAssessments) == 0 {
				return newError(InvalidInputError, InvalidInput, nil)
			}
		}
	default:
		return newError(InvalidInputError, InvalidInput, nil)
	}
	return nil
}

func validateCandidate(ctx context.Context, value Candidate) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != CandidateSchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		!uuidPattern.MatchString(value.CandidateID) || !uuidPattern.MatchString(value.OperationID) || !validScope(value.Scope) ||
		!validIdentifier(value.Identifier) || !validObservationRef(value.Observation) || value.MatchingEntities == nil ||
		!validEntityRefs(value.MatchingEntities) ||
		!validConfidenceRecord(value.Confidence) || !confidenceContainsObservation(value.Confidence, value.Observation) ||
		!validTimestamp(value.CreatedAt) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	expected := "new_candidate"
	if len(value.MatchingEntities) == 1 {
		expected = "single_match"
	} else if len(value.MatchingEntities) > 1 {
		expected = "ambiguous"
	}
	if value.Result != expected {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func validateDecision(ctx context.Context, value Decision) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		!uuidPattern.MatchString(value.DecisionID) || !uuidPattern.MatchString(value.OperationID) ||
		!slices.Contains([]Operation{Resolve, Merge, Split, Reject, Reindex}, value.Operation) || !validScope(value.Scope) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		value.AuthorizationDecisionDigest != nil && !digestPattern.MatchString(*value.AuthorizationDecisionDigest) ||
		value.ReversesHistoryDigest != nil && !digestPattern.MatchString(*value.ReversesHistoryDigest) ||
		value.InputEntities == nil || value.OutputEntities == nil || value.Partitions == nil || value.SupportingEvidence == nil ||
		value.Counterevidence == nil ||
		!validEntityRefs(value.InputEntities) || !validEntityRefs(value.OutputEntities) || !validPartitions(value.Partitions) ||
		!validConfidenceRecord(value.Confidence) || !sameCanonicalValue(value.SupportingEvidence, value.Confidence.SupportingEvidence) ||
		!sameCanonicalValue(value.Counterevidence, value.Confidence.Counterevidence) || !validTimestamp(value.CreatedAt) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	if slices.Contains([]Operation{Merge, Split, Reject, Reindex}, value.Operation) && value.AuthorizationDecisionDigest == nil {
		return newError(InvalidInputError, AuthorizationDenied, nil)
	}
	if value.Operation == Split && value.ReversesHistoryDigest == nil || value.Operation != Split && value.ReversesHistoryDigest != nil {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func validateOutcome(ctx context.Context, value Outcome) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != OutcomeSchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		!uuidPattern.MatchString(value.OperationID) || !digestPattern.MatchString(value.CommandDigest) ||
		!validStatusReason(value.Status, value.ReasonCode) || !validOptionalDigest(value.ObservationDigest) ||
		!validOptionalDigest(value.CandidateDigest) || !validOptionalDigest(value.DecisionDigest) ||
		!validOptionalDigest(value.HistoryDigest) || value.Entities == nil || !validEntityRefs(value.Entities) || !validTimestamp(value.CreatedAt) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	terminal := slices.Contains([]Status{Denied, Canceled, Timeout, DependencyUnavailable}, value.Status)
	if terminal && (value.ObservationDigest != nil || value.CandidateDigest != nil || value.DecisionDigest != nil ||
		value.HistoryDigest != nil || len(value.Entities) != 0) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func validateReceipt(ctx context.Context, value Receipt) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		!uuidPattern.MatchString(value.OperationID) || !digestPattern.MatchString(value.IdempotencyKey) ||
		!digestPattern.MatchString(value.CommandDigest) || !digestPattern.MatchString(value.OutcomeDigest) ||
		!validStatusReason(value.Status, value.ReasonCode) || !digestPattern.MatchString(value.AuditDigest) ||
		!digestPattern.MatchString(value.ProvenanceDigest) || value.PreviousProvenanceDigest != nil &&
		!digestPattern.MatchString(*value.PreviousProvenanceDigest) || !validTimestamp(value.CreatedAt) ||
		!validTimestamp(value.UpdatedAt) || value.UpdatedAt < value.CreatedAt {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func validStatusReason(status Status, reason Reason) bool {
	pairs := map[Status]Reason{Observed: ObservedReason, Resolved: ResolvedReason, Merged: MergedReason,
		SplitStatus: SplitReason, Rejected: RejectedReason, Reindexed: ReindexedReason, Canceled: ContextCanceled,
		Timeout: ContextDeadline, DependencyUnavailable: DependencyUnavailableReason}
	if expected, exists := pairs[status]; exists {
		return reason == expected
	}
	return status == Denied && slices.Contains([]Reason{InvalidInput, EvidenceBindingMismatch, ScopeMismatch,
		IdentifierIncompatible, CandidateAmbiguous, ConfidenceInvalid, CounterevidenceBlocked, TransitionInvalid,
		RevisionConflict, AuthorizationDenied, IdempotencyConflict}, reason)
}

func validPartitions(values []Partition) bool {
	if len(values) > 256 {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value.PartitionID) || !uuidPattern.MatchString(value.OutputEntityID) ||
			value.MemberObservations == nil || value.AliasProofDigests == nil || value.ConfidenceAssessments == nil ||
			len(value.MemberObservations) == 0 || len(value.MemberObservations) > MaximumLookupObservations ||
			!validConfidenceRecord(value.Confidence) || !confidenceBoundToMembers(value.Confidence, value.MemberObservations) ||
			!validConfidenceAssessments(value.ConfidenceAssessments) || !validDigestSet(value.AliasProofDigests) ||
			index > 0 && values[index-1].PartitionID >= value.PartitionID {
			return false
		}
		for memberIndex, member := range value.MemberObservations {
			if !validObservationRef(member) || memberIndex > 0 && compareObservationRef(value.MemberObservations[memberIndex-1], member) >= 0 {
				return false
			}
		}
	}
	return true
}

func validConfidenceAssessments(values []ConfidenceAssessment) bool {
	if len(values) > MaximumLookupObservations {
		return false
	}
	for index, value := range values {
		if !validObservationRef(value.Observation) || !validEvidenceLink(value.EvidenceLink) ||
			value.Observation.ObservationID != value.EvidenceLink.ObservationID ||
			value.Observation.ObservationDigest != value.EvidenceLink.ObservationDigest ||
			!validAssessment(value.SourceQuality, sourceQualityWeights) || !validAssessment(value.Recency, recencyWeights) ||
			index > 0 && compareObservationRef(values[index-1].Observation, value.Observation) >= 0 {
			return false
		}
	}
	return true
}

func validEntityRefs(values []EntityRef) bool {
	for index, value := range values {
		if !validEntityRef(value) || index > 0 && compareEntityRef(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}

func confidenceContainsObservation(value Confidence, observation ObservationRef) bool {
	for _, link := range value.SupportingEvidence {
		if link.ObservationID == observation.ObservationID && link.ObservationDigest == observation.ObservationDigest {
			return true
		}
	}
	return false
}

func validOptionalUUID(value *string) bool { return value == nil || uuidPattern.MatchString(*value) }
func validOptionalDigest(value *string) bool {
	return value == nil || digestPattern.MatchString(*value)
}
