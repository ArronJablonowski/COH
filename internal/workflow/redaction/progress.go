package redaction

func validateProgress(value Progress) error {
	if !validCase(value.Case) || !allDigests(value.IdempotencyDigest, value.IntentDigest, value.PlanDigest,
		value.DecisionDigest, value.ApprovalUseDigest) || !validTime(value.UpdatedAt) ||
		!boundedRevision(value.Revision) {
		return newError(InvalidInput, "progress_invalid", false, nil)
	}
	switch value.Phase {
	case PhasePlanned:
		if value.Revision != 1 || value.Derived != nil || value.Mapping != nil ||
			value.MappingDigest != nil || value.Custody != nil {
			return newError(InvalidInput, "progress_phase_invalid", false, nil)
		}
	case PhasePublished:
		if value.Revision != 2 || !validPublished(value.Derived) || !validPublished(value.Mapping) ||
			value.Mapping.Reference.Artifact.MediaType != mappingMediaType || !pointerDigest(value.MappingDigest) ||
			value.Custody != nil || value.Derived.Reference.Artifact.Digest == value.Mapping.Reference.Artifact.Digest {
			return newError(InvalidInput, "progress_phase_invalid", false, nil)
		}
	case PhaseCustodied:
		if value.Revision != 3 || !validPublished(value.Derived) || !validPublished(value.Mapping) ||
			value.Mapping.Reference.Artifact.MediaType != mappingMediaType || !pointerDigest(value.MappingDigest) ||
			value.Custody == nil || !validCustodyProof(*value.Custody) ||
			value.Derived.Reference.Artifact.Digest == value.Mapping.Reference.Artifact.Digest {
			return newError(InvalidInput, "progress_phase_invalid", false, nil)
		}
	default:
		return newError(InvalidInput, "progress_phase_invalid", false, nil)
	}
	return nil
}

func validPublished(value *PublishedEvidence) bool {
	return value != nil && validEvidence(value.Reference) && digestPattern.MatchString(value.ReceiptDigest) &&
		value.ReceiptDigest == value.Reference.IngestionReceiptDigest
}

func pointerDigest(value *string) bool {
	return value != nil && digestPattern.MatchString(*value)
}

func sameProgressIdentity(left, right Progress) bool {
	return left.Case == right.Case && left.IdempotencyDigest == right.IdempotencyDigest &&
		left.IntentDigest == right.IntentDigest && left.PlanDigest == right.PlanDigest &&
		left.ApprovalUseDigest == right.ApprovalUseDigest
}
