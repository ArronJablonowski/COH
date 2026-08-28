package modelsurface

import "slices"

func validateVocabulary(value EventVocabulary) error {
	if value.SchemaVersion != VocabularySchema || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "vocabulary_contract")
	}
	if value.VocabularyRevision == 0 || value.VocabularyRevision > MaximumRevision ||
		len(value.Definitions) == 0 || len(value.Definitions) > 512 {
		return newError(InvalidInput, "vocabulary_bounds")
	}
	for index, definition := range value.Definitions {
		if !validToken(definition.EventType) || definition.EventVersion == 0 || definition.EventVersion > 65535 ||
			!validToken(definition.ProducerModule) || !validDigest(definition.PayloadSchemaDigest) ||
			!sortedUniqueStrings(definition.ConsumerModules, 64, validToken) || len(definition.ConsumerModules) == 0 {
			return newError(InvalidInput, "event_definition")
		}
		switch definition.EventClass {
		case "model_surface":
			if definition.Persistence != "durable" || !validProjectionRule(definition.ProjectionRule) {
				return newError(Denied, "event_class_binding")
			}
		case "log_only":
			if definition.Persistence != "durable" || definition.ProjectionRule != "none" {
				return newError(Denied, "event_class_binding")
			}
		case "live_coordination":
			if definition.Persistence != "ephemeral" || definition.ProjectionRule != "none" {
				return newError(Denied, "event_class_binding")
			}
		default:
			return newError(InvalidInput, "event_class")
		}
		if index > 0 {
			previous := value.Definitions[index-1]
			if previous.EventType > definition.EventType ||
				previous.EventType == definition.EventType && previous.EventVersion >= definition.EventVersion {
				return newError(Denied, "event_definition_order")
			}
		}
	}
	return nil
}

func validateContent(value ContentBinding) error {
	if !oneOf(value.Kind, "durable_record", "immutable_artifact") || !validToken(value.ContentID) ||
		!validDigest(value.Digest) || !validMediaType(value.MediaType, true) || value.Length > MaximumInputBytes ||
		!validClassification(value.Classification) || !value.Immutable {
		return newError(InvalidInput, "content_binding")
	}
	return nil
}

func validateSource(value Source) error {
	if value.SchemaVersion != SourceSchema || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "source_contract")
	}
	if !validUUID7(value.SourceRecordID) || !validToken(value.EventType) || value.EventVersion == 0 ||
		value.EventVersion > 65535 || value.EventClass != "model_surface" || !validProjectionRule(value.ProjectionRule) ||
		!validScope(value.Scope) || !validUUID7(value.RunID) || value.RecordRevision == 0 ||
		value.RecordRevision > MaximumRevision || !validDigest(value.RecordDigest) || validateContent(value.Content) != nil ||
		!oneOf(value.Trust, "trusted_control", "trusted_system", "trusted_user", "untrusted_external", "untrusted_model", "untrusted_retrieval") ||
		!validInstructionDisposition(value.InstructionDisposition) || !validTimestamp(value.OccurredAt) ||
		value.Sequence == 0 || value.Sequence > MaximumRevision || !value.Immutable {
		return newError(InvalidInput, "source")
	}
	if oneOf(value.Trust, "untrusted_external", "untrusted_model", "untrusted_retrieval") &&
		value.InstructionDisposition != "untrusted_data_only" ||
		value.ProjectionRule == "retrieved_context" && value.InstructionDisposition != "untrusted_data_only" ||
		value.InstructionDisposition == "trusted_control_instruction" && value.Trust != "trusted_control" ||
		value.InstructionDisposition == "trusted_system_instruction" && value.Trust != "trusted_system" ||
		value.InstructionDisposition == "trusted_user_instruction" && value.Trust != "trusted_user" ||
		value.Trust == "trusted_user" && value.InstructionDisposition != "trusted_user_instruction" {
		return newError(Denied, "instruction_disposition")
	}
	return nil
}

func validateProjectedItem(value ProjectedItem, expectedOrdinal uint64) error {
	if value.Ordinal != expectedOrdinal || !validProjectionRule(value.SurfaceKind) ||
		!oneOf(value.Role, "system", "developer", "user", "assistant", "tool", "data") ||
		!validUUID7(value.SourceRecordID) || value.SourceRevision == 0 || value.SourceRevision > MaximumRevision ||
		!validDigest(value.SourceDigest) || !oneOf(value.ContentKind, "durable_record", "immutable_artifact") ||
		!validToken(value.ContentID) || !validDigest(value.ContentDigest) || !validDigest(value.RenderedDigest) ||
		value.RenderedLength > MaximumInputBytes || !validInstructionDisposition(value.InstructionDisposition) {
		return newError(InvalidInput, "projected_item")
	}
	if value.SurfaceKind == "retrieved_context" && value.InstructionDisposition != "untrusted_data_only" {
		return newError(Denied, "projected_instruction")
	}
	if oneOf(value.InstructionDisposition, "trusted_control_instruction", "trusted_system_instruction") && !oneOf(value.Role, "system", "developer") ||
		value.InstructionDisposition == "trusted_user_instruction" && (value.Role != "user" || value.SurfaceKind != "message") ||
		value.SurfaceKind == "tool_schema" && value.InstructionDisposition == "untrusted_data_only" {
		return newError(Denied, "projected_instruction")
	}
	return nil
}

func validateProjection(value Projection) error {
	if value.SchemaVersion != ProjectionSchema || value.ContractVersion != ContractVersion ||
		value.ProjectionVersion != ProjectionVersion {
		return newError(Unsupported, "projection_contract")
	}
	if !validUUID7(value.ProjectionID) || !validScope(value.Scope) || !validUUID7(value.RunID) ||
		!validDigest(value.VocabularyDigest) || !validDigest(value.CompositionDigest) ||
		len(value.OrderedItems) == 0 || len(value.OrderedItems) > MaximumItems ||
		len(value.OrderedSourceRecordIDs) != len(value.OrderedItems) ||
		!sortedUniqueStrings(value.ArtifactDigests, MaximumItems, validDigest) ||
		!validDigest(value.SurfaceDigest) || !validTimestamp(value.CreatedAt) {
		return newError(InvalidInput, "projection")
	}
	derivedArtifacts := make([]string, 0, len(value.ArtifactDigests))
	for index, item := range value.OrderedItems {
		if err := validateProjectedItem(item, uint64(index+1)); err != nil {
			return err
		}
		if value.OrderedSourceRecordIDs[index] != item.SourceRecordID {
			return newError(Denied, "projection_source_order")
		}
		if item.ContentKind == "immutable_artifact" {
			derivedArtifacts = append(derivedArtifacts, item.ContentDigest)
		}
	}
	slices.Sort(derivedArtifacts)
	derivedArtifacts = slices.Compact(derivedArtifacts)
	if !slices.Equal(derivedArtifacts, value.ArtifactDigests) {
		return newError(Denied, "projection_artifact_set")
	}
	return nil
}

func validateBinding(value InferenceBinding) error {
	if value.SchemaVersion != BindingSchema || value.ContractVersion != ContractVersion ||
		value.ProjectionVersion != ProjectionVersion {
		return newError(Unsupported, "binding_contract")
	}
	if !validUUID7(value.RequestID) || !validUUID7(value.AttemptID) || !validScope(value.Scope) ||
		!validUUID7(value.RunID) || !validUUID7(value.ActorID) || !validToken(value.ProviderID) ||
		!validUUID7(value.ProjectionID) || !validDigest(value.ProjectionDigest) ||
		len(value.OrderedSourceRecordIDs) == 0 || len(value.OrderedSourceRecordIDs) > MaximumItems ||
		!sortedUniqueStrings(value.ArtifactDigests, MaximumItems, validDigest) ||
		!validDigest(value.VocabularyDigest) || !validDigest(value.CompositionDigest) ||
		!validDigest(value.SurfaceDigest) || !validDigest(value.AuthorizationDigest) ||
		!validDigest(value.PolicyDecisionDigest) || !validDigest(value.ApprovalDecisionDigest) ||
		!validDigest(value.AuditReservationDigest) || !validTimestamp(value.CreatedAt) ||
		!validTimestamp(value.Deadline) || !timestampBefore(value.CreatedAt, value.Deadline) {
		return newError(InvalidInput, "binding")
	}
	return nil
}
