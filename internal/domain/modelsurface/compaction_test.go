package modelsurface

import (
	"bytes"
	"context"
	"testing"
)

type coverageReaderStub struct {
	values map[string]CoverageSnapshot
	err    error
}

func (reader *coverageReaderStub) ReadCoverage(_ context.Context, _ Scope, _ string, sourceID, _ string) (CoverageSnapshot, bool, error) {
	value, found := reader.values[sourceID]
	value.CoveredSources = cloneCoveredSources(value.CoveredSources)
	return value, found, reader.err
}

func TestCompactorBuildsDeterministicLeafCoveringReplacement(t *testing.T) {
	compactor, projection, request := newCompactionFixture(t)
	first, err := compactor.Build(context.Background(), projection, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compactor.Build(context.Background(), projection, request)
	if err != nil || !bytes.Equal(first.CanonicalBytes(), second.CanonicalBytes()) {
		t.Fatalf("repeat err=%v", err)
	}
	value := first.Value()
	if len(value.CoveredSources) != 3 || value.CoveredSources[0].ResultState != "observed" ||
		value.CoveredSources[1].ResultState != "negative" || value.CoveredSources[1].Completeness != "partial" ||
		value.CoveredSources[2].Uncertainty != "source" || value.CoverageDigest == "" || value.ReplacementDigest != first.Digest() {
		t.Fatalf("replacement=%#v", value)
	}
	for index, source := range value.CoveredSources {
		if source.Ordinal != uint64(index+1) {
			t.Fatalf("source[%d]=%#v", index, source)
		}
	}
	value.CoveredSources[0].EvidenceIDs[0] = uuid(99)
	if first.Value().CoveredSources[0].EvidenceIDs[0] == uuid(99) {
		t.Fatal("replacement aliases mutation")
	}
}

func TestCompactorDeniesRangeCoverageAndArtifactDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Compactor, *ValidatedDocument[Projection], *CompactionRequest)
		reason string
	}{
		{"range order", func(_ *Compactor, _ *ValidatedDocument[Projection], request *CompactionRequest) {
			request.CoveredSourceRecordIDs[0], request.CoveredSourceRecordIDs[1] = request.CoveredSourceRecordIDs[1], request.CoveredSourceRecordIDs[0]
		}, "compaction_range"},
		{"missing coverage", func(compactor *Compactor, _ *ValidatedDocument[Projection], request *CompactionRequest) {
			delete(compactor.coverage.(*coverageReaderStub).values, request.CoveredSourceRecordIDs[0])
		}, "coverage_missing"},
		{"scope drift", func(compactor *Compactor, _ *ValidatedDocument[Projection], request *CompactionRequest) {
			value := compactor.coverage.(*coverageReaderStub).values[request.CoveredSourceRecordIDs[0]]
			value.Scope.TenantID = uuid(90)
			compactor.coverage.(*coverageReaderStub).values[request.CoveredSourceRecordIDs[0]] = value
		}, "coverage_binding"},
		{"leaf overlap", func(compactor *Compactor, _ *ValidatedDocument[Projection], request *CompactionRequest) {
			reader := compactor.coverage.(*coverageReaderStub)
			value := reader.values[request.CoveredSourceRecordIDs[1]]
			value.CoveredSources[0].SourceRecordID = reader.values[request.CoveredSourceRecordIDs[0]].CoveredSources[0].SourceRecordID
			reader.values[request.CoveredSourceRecordIDs[1]] = value
		}, "coverage_overlap"},
		{"artifact tamper", func(compactor *Compactor, _ *ValidatedDocument[Projection], request *CompactionRequest) {
			reader := compactor.artifacts.(*contentCatalogStub)
			value := reader.values[request.SummaryArtifact.Digest]
			value.Bytes = []byte("tampered")
			reader.values[request.SummaryArtifact.Digest] = value
		}, "content_binding"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compactor, projection, request := newCompactionFixture(t)
			test.mutate(compactor, &projection, &request)
			if _, err := compactor.Build(context.Background(), projection, request); Reason(err) != test.reason {
				t.Fatalf("err=%v reason=%s", err, Reason(err))
			}
		})
	}
}

func TestCompactionReplayIdentityChangesWithAnyPreservedMetadata(t *testing.T) {
	compactor, projection, request := newCompactionFixture(t)
	baseline, err := compactor.Build(context.Background(), projection, request)
	if err != nil {
		t.Fatal(err)
	}
	reader := compactor.coverage.(*coverageReaderStub)
	value := reader.values[request.CoveredSourceRecordIDs[1]]
	value.CoveredSources[0].Completeness = "truncated"
	reader.values[request.CoveredSourceRecordIDs[1]] = value
	changed, err := compactor.Build(context.Background(), projection, request)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Value().CoverageDigest == baseline.Value().CoverageDigest || changed.Digest() == baseline.Digest() {
		t.Fatal("coverage metadata drift retained replay identity")
	}
}

func newCompactionFixture(t *testing.T) (*Compactor, ValidatedDocument[Projection], CompactionRequest) {
	t.Helper()
	projectionBytes, _, err := CanonicalProjection(context.Background(), validProjection())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := DecodeProjection(context.Background(), projectionBytes)
	if err != nil {
		t.Fatal(err)
	}
	value := projection.Value()
	coverage := &coverageReaderStub{values: map[string]CoverageSnapshot{
		value.OrderedSourceRecordIDs[0]: {Scope: value.Scope, RunID: value.RunID, SourceRecordID: value.OrderedSourceRecordIDs[0], SourceDigest: value.OrderedItems[0].SourceDigest,
			CoveredSources: []CoveredSource{coverageSource(1, value.OrderedSourceRecordIDs[0], value.OrderedItems[0].SourceDigest, uuid(40), "observed", "complete", "none")}},
		value.OrderedSourceRecordIDs[1]: {Scope: value.Scope, RunID: value.RunID, SourceRecordID: value.OrderedSourceRecordIDs[1], SourceDigest: value.OrderedItems[1].SourceDigest,
			CoveredSources: []CoveredSource{
				coverageSource(1, value.OrderedSourceRecordIDs[1], value.OrderedItems[1].SourceDigest, uuid(41), "negative", "partial", "bounded"),
				coverageSource(2, uuid(42), digest('f'), uuid(43), "gap", "unknown", "source")}},
	}}
	summary, err := CanonicalPayload(SurfacePayload{SchemaVersion: PayloadSchema, ContractVersion: ContractVersion,
		SurfaceKind: "compaction_replacement", Role: "data", Name: "compaction.summary", ContentKind: "text",
		Content: []byte(`"Evidence-bound compacted summary."`)})
	if err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{ArtifactID: "compaction.summary", Digest: rawDigest(summary), MediaType: "application/json", Length: uint64(len(summary)), Classification: "restricted", Immutable: true}
	artifacts := &contentCatalogStub{values: map[string]ContentSnapshot{artifact.Digest: {Scope: value.Scope, RunID: value.RunID,
		Kind: "immutable_artifact", ContentID: artifact.ArtifactID, Digest: artifact.Digest, MediaType: artifact.MediaType,
		Classification: artifact.Classification, Immutable: true, Bytes: summary}}}
	compactor, err := NewCompactor(coverage, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	return compactor, projection, CompactionRequest{ReplacementID: uuid(50), CompactionID: uuid(51), ReplacementSourceRecordID: uuid(52),
		CoveredSourceRecordIDs: append([]string(nil), value.OrderedSourceRecordIDs...), SummaryArtifact: artifact, CreatedAt: timestamp(9)}
}

func coverageSource(ordinal uint64, sourceID, sourceDigest, evidenceID, result, completeness, uncertainty string) CoveredSource {
	return CoveredSource{Ordinal: ordinal, SourceRecordID: sourceID, SourceDigest: sourceDigest, EvidenceIDs: []string{evidenceID},
		NormalizedTime: timestamp(int(ordinal)), OriginalTimezone: "UTC", Precision: "second", ClockUncertaintyNanoseconds: 1,
		OrderConfidence: "strict", ResultState: result, Completeness: completeness, Uncertainty: uncertainty}
}

func cloneCoveredSources(values []CoveredSource) []CoveredSource {
	result := append([]CoveredSource(nil), values...)
	for index := range result {
		result[index].EvidenceIDs = append([]string(nil), result[index].EvidenceIDs...)
	}
	return result
}
