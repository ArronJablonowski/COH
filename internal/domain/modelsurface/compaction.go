package modelsurface

import (
	"context"
)

// CoverageSnapshot is authoritative metadata for one projected source. For a
// prior replacement, CoveredSources contains its original leaf coverage.
type CoverageSnapshot struct {
	Scope          Scope
	RunID          string
	SourceRecordID string
	SourceDigest   string
	CoveredSources []CoveredSource
}

type CoverageReader interface {
	ReadCoverage(context.Context, Scope, string, string, string) (CoverageSnapshot, bool, error)
}

type CompactionRequest struct {
	ReplacementID             string
	CompactionID              string
	ReplacementSourceRecordID string
	CoveredSourceRecordIDs    []string
	SummaryArtifact           Artifact
	CreatedAt                 string
}

type Compactor struct {
	coverage  CoverageReader
	artifacts ArtifactReader
}

func NewCompactor(coverage CoverageReader, artifacts ArtifactReader) (*Compactor, error) {
	if coverage == nil || artifacts == nil {
		return nil, newError(InvalidInput, "compactor_dependencies")
	}
	return &Compactor{coverage: coverage, artifacts: artifacts}, nil
}

func (compactor *Compactor) Build(ctx context.Context, projectionDocument ValidatedDocument[Projection], request CompactionRequest) (ValidatedDocument[CompactionReplacement], error) {
	if compactor == nil || compactor.coverage == nil || compactor.artifacts == nil {
		return ValidatedDocument[CompactionReplacement]{}, newError(InvalidInput, "compactor_dependencies")
	}
	if err := contextError(ctx); err != nil {
		return ValidatedDocument[CompactionReplacement]{}, err
	}
	projection := projectionDocument.Value()
	sealed, err := SealProjection(ctx, projection)
	if err != nil || sealed.ProjectionDigest != projectionDocument.Digest() || projection.ProjectionDigest != projectionDocument.Digest() {
		return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "compaction_projection")
	}
	if !validUUID7(request.ReplacementID) || !validUUID7(request.CompactionID) || !validUUID7(request.ReplacementSourceRecordID) ||
		len(request.CoveredSourceRecordIDs) == 0 || len(request.CoveredSourceRecordIDs) > MaximumItems ||
		validateArtifact(request.SummaryArtifact) != nil || !validTimestamp(request.CreatedAt) {
		return ValidatedDocument[CompactionReplacement]{}, newError(InvalidInput, "compaction_request")
	}
	projected, err := exactCompactionRange(projection, request.CoveredSourceRecordIDs, request.ReplacementSourceRecordID)
	if err != nil {
		return ValidatedDocument[CompactionReplacement]{}, err
	}
	leaves := make([]CoveredSource, 0, len(projected))
	seen := make(map[string]struct{})
	for index, item := range projected {
		if err := contextError(ctx); err != nil {
			return ValidatedDocument[CompactionReplacement]{}, err
		}
		snapshot, found, readErr := compactor.coverage.ReadCoverage(ctx, projection.Scope, projection.RunID,
			request.CoveredSourceRecordIDs[index], item.SourceDigest)
		if readErr != nil {
			return ValidatedDocument[CompactionReplacement]{}, mapResolutionError(ctx, "coverage_unavailable")
		}
		if !found {
			return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "coverage_missing")
		}
		if snapshot.Scope != projection.Scope || snapshot.RunID != projection.RunID ||
			snapshot.SourceRecordID != request.CoveredSourceRecordIDs[index] || snapshot.SourceDigest != item.SourceDigest ||
			len(snapshot.CoveredSources) == 0 || len(leaves)+len(snapshot.CoveredSources) > MaximumItems {
			return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "coverage_binding")
		}
		for sourceIndex, source := range snapshot.CoveredSources {
			if err := validateCoveredSource(source, uint64(sourceIndex+1)); err != nil {
				return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "coverage_metadata")
			}
			if _, exists := seen[source.SourceRecordID]; exists || source.SourceRecordID == request.ReplacementSourceRecordID {
				return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "coverage_overlap")
			}
			seen[source.SourceRecordID] = struct{}{}
			source.Ordinal = uint64(len(leaves) + 1)
			source.EvidenceIDs = append([]string(nil), source.EvidenceIDs...)
			leaves = append(leaves, source)
		}
	}
	binding := ContentBinding{Kind: "immutable_artifact", ContentID: request.SummaryArtifact.ArtifactID,
		Digest: request.SummaryArtifact.Digest, MediaType: request.SummaryArtifact.MediaType, Length: request.SummaryArtifact.Length,
		Classification: request.SummaryArtifact.Classification, Immutable: request.SummaryArtifact.Immutable}
	artifact, found, readErr := compactor.artifacts.ReadArtifact(ctx, projection.Scope, projection.RunID, binding)
	if readErr != nil {
		return ValidatedDocument[CompactionReplacement]{}, mapResolutionError(ctx, "compaction_artifact_unavailable")
	}
	if !found {
		return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "compaction_artifact_missing")
	}
	if err := verifyContentSnapshot(ResolveRequest{Scope: projection.Scope, RunID: projection.RunID}, binding, artifact); err != nil {
		return ValidatedDocument[CompactionReplacement]{}, err
	}
	payload, err := DecodePayload(ctx, artifact.Bytes)
	if err != nil {
		return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "compaction_payload")
	}
	payloadValue := payload.Value()
	if payloadValue.SurfaceKind != "compaction_replacement" || payloadValue.Role != "data" ||
		!oneOf(payloadValue.ContentKind, "text", "input_json") {
		return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "compaction_payload")
	}
	replacement := CompactionReplacement{SchemaVersion: CompactionSchema, ContractVersion: ContractVersion,
		ReplacementID: request.ReplacementID, Scope: projection.Scope, RunID: projection.RunID, CompactionID: request.CompactionID,
		ReplacementSourceRecordID: request.ReplacementSourceRecordID, CoveredSources: leaves,
		SummaryArtifact: request.SummaryArtifact, CreatedAt: request.CreatedAt}
	canonical, _, err := CanonicalCompaction(ctx, replacement)
	if err != nil {
		return ValidatedDocument[CompactionReplacement]{}, err
	}
	return DecodeCompaction(ctx, canonical)
}

func exactCompactionRange(projection Projection, sourceIDs []string, replacementID string) ([]ProjectedItem, error) {
	if !uniqueStrings(sourceIDs) || containsString(sourceIDs, replacementID) {
		return nil, newError(Denied, "compaction_range")
	}
	start := -1
	for index, sourceID := range projection.OrderedSourceRecordIDs {
		if sourceID == sourceIDs[0] {
			start = index
			break
		}
	}
	if start < 0 || start+len(sourceIDs) > len(projection.OrderedItems) {
		return nil, newError(Denied, "compaction_range")
	}
	for index, sourceID := range sourceIDs {
		if projection.OrderedSourceRecordIDs[start+index] != sourceID {
			return nil, newError(Denied, "compaction_range")
		}
	}
	return append([]ProjectedItem(nil), projection.OrderedItems[start:start+len(sourceIDs)]...), nil
}
