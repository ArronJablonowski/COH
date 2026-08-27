package redaction

import "math"

func ValidateMapping(value Mapping) error {
	if err := validateMappingBase(value); err != nil || !allDigests(value.ProvenanceDigest, value.MappingDigest) {
		return newError(InvalidInput, "mapping_invalid", false, err)
	}
	provenance, err := MappingProvenanceDigest(value)
	if err != nil || provenance != value.ProvenanceDigest {
		return newError(Denied, "mapping_provenance_invalid", false, err)
	}
	want, err := MappingBindingDigest(value)
	if err != nil || want != value.MappingDigest {
		return newError(Denied, "mapping_digest_invalid", false, err)
	}
	return nil
}

func validateMappingBase(value Mapping) error {
	if value.SchemaVersion != MappingSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.MappingID) || !validCase(value.Case) || !validEvidence(value.Source) ||
		!validArtifact(value.DerivedArtifact) || value.DerivedArtifact.Digest == value.Source.Artifact.Digest ||
		!allDigests(value.PlanDigest, value.RuleDigest, value.ReasonDigest, value.ApprovalFingerprintDigest,
			value.PreviousProvenanceDigest) || !validTime(value.CreatedAt) || len(value.Entries) == 0 || len(value.Entries) > 4096 {
		return newError(InvalidInput, "mapping_base_invalid", false, nil)
	}
	previousSourceEnd, previousOutputEnd, delta := int64(0), int64(0), int64(0)
	for index, entry := range value.Entries {
		if entry.Ordinal != uint16(index+1) || entry.SourceStart < previousSourceEnd || entry.SourceStart < 0 ||
			entry.SourceEnd <= entry.SourceStart || entry.SourceEnd > value.Source.Artifact.Length ||
			entry.OutputStart < previousOutputEnd || entry.OutputStart != entry.SourceStart+delta ||
			entry.OutputEnd < entry.OutputStart || !allDigests(entry.SourceSegmentDigest, entry.ReplacementDigest) ||
			!validReplacement(entry.ReplacementMode) {
			return newError(InvalidInput, "mapping_entry_invalid", false, nil)
		}
		sourceLength, outputLength := entry.SourceEnd-entry.SourceStart, entry.OutputEnd-entry.OutputStart
		if entry.ReplacementMode == Remove && outputLength != 0 || entry.ReplacementMode == Mask && outputLength != sourceLength ||
			entry.ReplacementMode == Token && outputLength == 0 {
			return newError(InvalidInput, "mapping_replacement_invalid", false, nil)
		}
		delta += outputLength - sourceLength
		previousSourceEnd, previousOutputEnd = entry.SourceEnd, entry.OutputEnd
	}
	if value.Source.Artifact.Length+delta != value.DerivedArtifact.Length {
		return newError(InvalidInput, "mapping_output_length_invalid", false, nil)
	}
	return nil
}

func ValidateRecord(value Record) error {
	if err := validateRecordBase(value); err != nil || !allDigests(value.ProvenanceDigest, value.AuditEventDigest, value.RecordDigest) {
		return newError(InvalidInput, "record_invalid", false, err)
	}
	provenance, err := RecordProvenanceDigest(value)
	if err != nil || provenance != value.ProvenanceDigest {
		return newError(Denied, "record_provenance_invalid", false, err)
	}
	want, err := RecordBindingDigest(value)
	if err != nil || want != value.RecordDigest {
		return newError(Denied, "record_digest_invalid", false, err)
	}
	return nil
}

func validateRecordBase(value Record) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RedactionID) || !validCase(value.Case) || validateCommandShape(value.Command) != nil ||
		value.Command.Case != value.Case || !allDigests(value.IntentDigest, value.PlanDigest, value.DecisionDigest,
		value.RevocationDigest, value.ApprovalUseDigest, value.SourceVerificationDigest,
		value.DerivedIngestionReceiptDigest, value.MappingDigest, value.MappingIngestionReceiptDigest,
		value.CustodyReceiptDigest, value.PreviousProvenanceDigest) || !validEvidence(value.Derived) ||
		!validEvidence(value.MappingReference) || value.MappingReference.Artifact.MediaType != mappingMediaType ||
		value.Derived.Artifact.Digest == value.Command.Source.Artifact.Digest ||
		value.MappingReference.Artifact.Digest == value.Command.Source.Artifact.Digest ||
		value.MappingReference.Artifact.Digest == value.Derived.Artifact.Digest || !validTime(value.CreatedAt) ||
		value.PlanDigest != value.Command.PlanDigest ||
		value.DerivedIngestionReceiptDigest != value.Derived.IngestionReceiptDigest ||
		value.MappingIngestionReceiptDigest != value.MappingReference.IngestionReceiptDigest {
		return newError(InvalidInput, "record_base_invalid", false, nil)
	}
	intent, err := IntentBindingDigest(value.Command)
	if err != nil || intent != value.IntentDigest {
		return newError(Denied, "record_intent_invalid", false, err)
	}
	return nil
}

func ValidateReceipt(value Receipt) error {
	if err := validateReceiptShape(value, true); err != nil {
		return err
	}
	want, err := ReceiptBindingDigest(value)
	if err != nil || want != value.ReceiptDigest {
		return newError(Denied, "receipt_digest_invalid", false, err)
	}
	return nil
}

func validateReceiptShape(value Receipt, bound bool) error {
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validCase(value.Case) ||
		!allDigests(value.IdempotencyDigest, value.IntentDigest, value.RecordDigest, value.MappingDigest,
			value.CustodyReceiptDigest, value.AuditEventDigest, value.ProvenanceDigest) ||
		!uuidPattern.MatchString(value.RedactionID) || !validEvidence(value.Derived) || !validEvidence(value.MappingReference) ||
		value.MappingReference.Artifact.MediaType != mappingMediaType || value.Derived.Artifact.Digest == value.MappingReference.Artifact.Digest ||
		!validTime(value.CreatedAt) || (bound && !digestPattern.MatchString(value.ReceiptDigest)) ||
		(!bound && value.ReceiptDigest != "") {
		return newError(InvalidInput, "receipt_invalid", false, nil)
	}
	return nil
}

func boundedRevision(value uint64) bool { return value > 0 && value <= math.MaxInt64 }
func boundedBytes(value int64) bool     { return value > 0 && value <= maximumArtifactBytes }

func sortedUniqueStrings(values []string, valid func(string) bool) bool {
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func sortedUniqueModes(values []ReplacementMode) bool {
	for index, value := range values {
		if !validReplacement(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validDecisionReason(value DecisionReason) bool {
	switch value {
	case ReasonAuthorized, ReasonInvalidInput, ReasonCaseNotFound, ReasonCaseStateDenied, ReasonSourceNotFound,
		ReasonSourceInvalid, ReasonRuleInvalid, ReasonPlanInvalid, ReasonApprovalRequired, ReasonApprovalInvalid,
		ReasonRevoked, ReasonStaleActor, ReasonStaleCase, ReasonStaleCustody, ReasonSourceDrift,
		ReasonMappingInvalid, ReasonTransformInvalid, ReasonPublishFailed, ReasonCustodyFailed, ReasonChangedReplay:
		return true
	default:
		return false
	}
}

func sameHead(left, right CustodyHead) bool {
	if left.Case != right.Case || left.Sequence != right.Sequence || left.ChainHash != right.ChainHash ||
		(left.LastRecordAt == nil) != (right.LastRecordAt == nil) {
		return false
	}
	return left.LastRecordAt == nil || left.LastRecordAt.Equal(*right.LastRecordAt)
}
