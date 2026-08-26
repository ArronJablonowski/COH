package contextcompact

// ReplacementReferences returns the only artifact reference that may replace
// active context. Callers must retain Result.Sources beside it.
func (value Result) ReplacementReferences() ([]string, error) {
	if value.Status != StatusCompleted || value.SummaryTrust != UntrustedEvidence ||
		!validArtifact(value.Summary) || len(value.Sources) == 0 || len(value.Sources) > MaximumSources ||
		!digestPattern.MatchString(value.ProvenanceDigest) {
		return nil, newError(Denied, "compaction_result_not_replaceable", false, nil)
	}
	seen := make(map[string]struct{}, len(value.Sources))
	for index, source := range value.Sources {
		if source.Sequence != uint32(index+1) || !validSource(source) {
			return nil, newError(Denied, "compaction_result_manifest_invalid", false, nil)
		}
		if _, duplicate := seen[source.EvidenceID]; duplicate {
			return nil, newError(Denied, "compaction_result_manifest_invalid", false, nil)
		}
		seen[source.EvidenceID] = struct{}{}
	}
	manifest, err := sourceManifestDigest(value.Sources)
	if err != nil || manifest != value.SourceManifestDigest {
		return nil, newError(Denied, "compaction_result_manifest_invalid", false, nil)
	}
	return []string{value.Summary.Digest}, nil
}
