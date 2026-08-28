package modelsurface

func validateStream(value StreamEvent) error {
	if value.SchemaVersion != StreamSchema || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "stream_contract")
	}
	if !validUUID7(value.RequestID) || !validUUID7(value.AttemptID) || !validDigest(value.BindingDigest) ||
		!validDigest(value.ProjectionDigest) || !validDigest(value.InputSurfaceDigest) || value.Sequence == 0 ||
		value.Sequence > MaximumRevision || !oneOf(value.Kind, "started", "chunk", "item", "terminal") ||
		len(value.SourceRecordIDs) == 0 || !sortedUniqueStrings(value.SourceRecordIDs, MaximumItems, validUUID7) || !validOptionalDigest(value.ChunkDigest) ||
		!validOptionalDigest(value.AssembledDigest) ||
		!oneOf(value.Outcome, "pending", "succeeded", "empty", "interrupted", "canceled", "timeout", "failed", "uncertain") ||
		!validTimestamp(value.ObservedAt) {
		return newError(InvalidInput, "stream_event")
	}
	if value.Kind != "terminal" && (value.Outcome != "pending" || value.AssembledDigest != "") ||
		value.Kind == "terminal" && (value.Outcome == "pending" || value.AssembledDigest == "") {
		return newError(Denied, "stream_outcome")
	}
	if value.Kind == "started" && value.ChunkDigest != "" ||
		oneOf(value.Kind, "chunk", "item") && value.ChunkDigest == "" {
		return newError(Denied, "stream_chunk")
	}
	return nil
}

func validateArtifact(value Artifact) error {
	if !validToken(value.ArtifactID) || !validDigest(value.Digest) || !validMediaType(value.MediaType, false) ||
		value.Length > MaximumInputBytes || !validClassification(value.Classification) || !value.Immutable {
		return newError(InvalidInput, "artifact")
	}
	return nil
}

func validateCoveredSource(value CoveredSource, expectedOrdinal uint64) error {
	if value.Ordinal != expectedOrdinal || !validUUID7(value.SourceRecordID) || !validDigest(value.SourceDigest) ||
		!sortedUniqueStrings(value.EvidenceIDs, 4096, validUUID7) || !validTimestamp(value.NormalizedTime) ||
		len(value.OriginalTimezone) == 0 || len(value.OriginalTimezone) > 128 ||
		!oneOf(value.Precision, "nanosecond", "microsecond", "millisecond", "second", "minute", "hour", "day", "unknown") ||
		value.ClockUncertaintyNanoseconds > 315576000000000000 ||
		!oneOf(value.OrderConfidence, "strict", "overlap", "ambiguous", "unknown") ||
		!oneOf(value.ResultState, "observed", "negative", "gap", "denied", "canceled", "timeout", "failed", "uncertain") ||
		!oneOf(value.Completeness, "complete", "partial", "truncated", "unknown") ||
		!oneOf(value.Uncertainty, "none", "clock", "bounded", "source", "unknown") {
		return newError(InvalidInput, "covered_source")
	}
	return nil
}

func validateCompaction(value CompactionReplacement) error {
	if value.SchemaVersion != CompactionSchema || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "compaction_contract")
	}
	if !validUUID7(value.ReplacementID) || !validScope(value.Scope) || !validUUID7(value.RunID) ||
		!validUUID7(value.CompactionID) || !validUUID7(value.ReplacementSourceRecordID) ||
		len(value.CoveredSources) == 0 || len(value.CoveredSources) > MaximumItems ||
		validateArtifact(value.SummaryArtifact) != nil || !validTimestamp(value.CreatedAt) {
		return newError(InvalidInput, "compaction")
	}
	identities := make([]string, len(value.CoveredSources))
	for index, source := range value.CoveredSources {
		if err := validateCoveredSource(source, uint64(index+1)); err != nil {
			return err
		}
		identities[index] = source.SourceRecordID
	}
	if !uniqueStrings(identities) || value.ReplacementSourceRecordID == identities[0] ||
		containsString(identities, value.ReplacementSourceRecordID) {
		return newError(Denied, "compaction_coverage")
	}
	return nil
}

func validateTransition(value Transition) error {
	if value.SchemaVersion != TransitionSchema || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "transition_contract")
	}
	if !validUUID7(value.TransitionID) || !validUUID7(value.RequestID) || !validUUID7(value.AttemptID) ||
		!validScope(value.Scope) || !validUUID7(value.RunID) ||
		!oneOf(value.Phase, "prepared", "verified", "dispatched", "streaming", "terminal") ||
		value.Revision == 0 || value.Revision > MaximumRevision || !validDigest(value.ProjectionDigest) ||
		!validOptionalDigest(value.BindingDigest) || !validToken(value.ProviderRoute) ||
		value.ProviderAttempt == 0 || value.ProviderAttempt > 32 || value.StreamCursor > MaximumRevision ||
		!oneOf(value.TerminalOutcome, "", "succeeded", "empty", "interrupted", "canceled", "timeout", "failed", "uncertain") ||
		!validOptionalDigest(value.PreviousTransitionDigest) || !validTimestamp(value.CreatedAt) ||
		!validTimestamp(value.UpdatedAt) {
		return newError(InvalidInput, "transition")
	}
	if value.Phase == "prepared" && (value.BindingDigest != "" || value.TerminalOutcome != "" || value.StreamCursor != 0) ||
		oneOf(value.Phase, "verified", "dispatched", "streaming") && (value.BindingDigest == "" || value.TerminalOutcome != "") ||
		value.Phase == "terminal" && (value.BindingDigest == "" || value.TerminalOutcome == "") ||
		value.Phase == "verified" && value.StreamCursor != 0 || value.Phase == "dispatched" && value.StreamCursor != 0 ||
		value.Revision == 1 && value.PreviousTransitionDigest != "" || value.Revision > 1 && value.PreviousTransitionDigest == "" ||
		!timestampAtOrAfter(value.UpdatedAt, value.CreatedAt) {
		return newError(Denied, "transition_phase")
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
