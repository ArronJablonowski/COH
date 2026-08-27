package custody

import "github.com/ArronJablonowski/COH/internal/domain"

func cloneEvidence(value EvidenceReference) EvidenceReference { return value }

func cloneEvidenceSlice(values []EvidenceReference) []EvidenceReference {
	result := make([]EvidenceReference, len(values))
	copy(result, values)
	return result
}

func cloneArtifactSlice(values []domain.ArtifactRef) []domain.ArtifactRef {
	result := make([]domain.ArtifactRef, len(values))
	copy(result, values)
	return result
}

func cloneStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneHead(value Head) Head {
	value.LastRecordAt = clonePointer(value.LastRecordAt)
	return value
}

func cloneCommand(value Command) Command {
	value.Subject = cloneEvidence(value.Subject)
	value.Parents = cloneEvidenceSlice(value.Parents)
	value.SourceIdentityDigest = clonePointer(value.SourceIdentityDigest)
	value.PurposeDigest = clonePointer(value.PurposeDigest)
	value.DestinationDigest = clonePointer(value.DestinationDigest)
	value.RecipientDigest = clonePointer(value.RecipientDigest)
	value.TransformationDigest = clonePointer(value.TransformationDigest)
	value.RuleDigest = clonePointer(value.RuleDigest)
	value.ReasonDigest = clonePointer(value.ReasonDigest)
	value.MappingDigest = clonePointer(value.MappingDigest)
	value.ApprovalDigest = clonePointer(value.ApprovalDigest)
	value.ExternalReceiptDigest = clonePointer(value.ExternalReceiptDigest)
	value.LifecycleReceiptDigest = clonePointer(value.LifecycleReceiptDigest)
	value.PriorAuthorizationDigest = clonePointer(value.PriorAuthorizationDigest)
	value.ArtifactSetDigest = clonePointer(value.ArtifactSetDigest)
	value.ExpectedHead = cloneHead(value.ExpectedHead)
	return value
}

func cloneRecord(value Record) Record {
	value.Command = cloneCommand(value.Command)
	value.PreviousProvenanceDigest = clonePointer(value.PreviousProvenanceDigest)
	return value
}
