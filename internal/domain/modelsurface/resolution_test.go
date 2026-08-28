package modelsurface

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type vocabularyReaderStub struct {
	value []byte
	found bool
	err   error
	calls int
}

func (stub *vocabularyReaderStub) ReadVocabulary(context.Context, string) ([]byte, bool, error) {
	stub.calls++
	return append([]byte(nil), stub.value...), stub.found, stub.err
}

type sourceReaderStub struct {
	value []byte
	found bool
	err   error
	calls int
}

func (stub *sourceReaderStub) ReadSource(context.Context, Scope, string, uint64) ([]byte, bool, error) {
	stub.calls++
	return append([]byte(nil), stub.value...), stub.found, stub.err
}

type contentReaderStub struct {
	value         ContentSnapshot
	found         bool
	err           error
	recordCalls   int
	artifactCalls int
}

func (stub *contentReaderStub) ReadDurableRecord(context.Context, Scope, string, ContentBinding) (ContentSnapshot, bool, error) {
	stub.recordCalls++
	return stub.result()
}
func (stub *contentReaderStub) ReadArtifact(context.Context, Scope, string, ContentBinding) (ContentSnapshot, bool, error) {
	stub.artifactCalls++
	return stub.result()
}
func (stub *contentReaderStub) result() (ContentSnapshot, bool, error) {
	result := stub.value
	result.Bytes = append([]byte(nil), stub.value.Bytes...)
	return result, stub.found, stub.err
}

type resolverFixture struct {
	resolver     *Resolver
	vocabularies *vocabularyReaderStub
	sources      *sourceReaderStub
	contents     *contentReaderStub
	request      ResolveRequest
	source       Source
}

func TestResolverReturnsScopeExactImmutableOwnedSources(t *testing.T) {
	fixture := newResolverFixture(t)
	resolved, err := fixture.resolver.Resolve(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if fixture.vocabularies.calls != 1 || fixture.sources.calls != 1 || fixture.contents.artifactCalls != 1 || fixture.contents.recordCalls != 0 {
		t.Fatalf("calls vocabulary=%d source=%d artifact=%d record=%d", fixture.vocabularies.calls, fixture.sources.calls, fixture.contents.artifactCalls, fixture.contents.recordCalls)
	}
	items := resolved.Items()
	if len(items) != 1 || items[0].Source().SourceRecordID != fixture.source.SourceRecordID ||
		!bytes.Equal(items[0].ContentBytes(), fixture.contents.value.Bytes) ||
		items[0].EventDefinition().ProjectionRule != "retrieved_context" {
		t.Fatalf("resolved=%#v", items)
	}
	items[0].contentBytes[0] = 'x'
	items[0].eventDefinition.ConsumerModules[0] = "mutated.module"
	vocabulary := resolved.Vocabulary()
	vocabulary.Definitions[0].ConsumerModules[0] = "mutated.module"
	second := resolved.Items()
	if second[0].ContentBytes()[0] != '{' || second[0].EventDefinition().ConsumerModules[0] != "model.projector" ||
		resolved.Vocabulary().Definitions[0].ConsumerModules[0] != "model.projector" {
		t.Fatal("resolved values alias caller mutation")
	}
}

func TestResolverRoutesDurableRecordsAndArtifactsThroughSeparatePorts(t *testing.T) {
	fixture := newResolverFixture(t)
	fixture.source.Content.Kind = "durable_record"
	fixture.contents.value.Kind = "durable_record"
	fixture.replaceSource(t)
	if _, err := fixture.resolver.Resolve(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
	if fixture.contents.recordCalls != 1 || fixture.contents.artifactCalls != 0 {
		t.Fatalf("record=%d artifact=%d", fixture.contents.recordCalls, fixture.contents.artifactCalls)
	}
}

func TestResolverDeniesMissingMutableCrossScopeStaleUnsupportedAndTamperedInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *resolverFixture)
		code   ErrorCode
		reason string
	}{
		{"vocabulary missing", func(_ *testing.T, value *resolverFixture) { value.vocabularies.found = false }, Denied, "vocabulary_missing"},
		{"vocabulary tamper", func(_ *testing.T, value *resolverFixture) {
			value.vocabularies.value = append(value.vocabularies.value, '\n')
		}, Denied, "vocabulary_tamper"},
		{"source missing", func(_ *testing.T, value *resolverFixture) { value.sources.found = false }, Denied, "source_missing"},
		{"source tamper", func(_ *testing.T, value *resolverFixture) { value.sources.value = append(value.sources.value, '\n') }, Denied, "source_tamper"},
		{"source stale", func(_ *testing.T, value *resolverFixture) { value.request.Sources[0].SourceDigest = digest('f') }, Denied, "source_stale"},
		{"source scope", func(t *testing.T, value *resolverFixture) {
			value.source.Scope.CaseID = uuid(20)
			value.replaceSource(t)
		}, Denied, "source_scope"},
		{"unsupported event", func(t *testing.T, value *resolverFixture) {
			value.source.EventType = "unknown.event"
			value.replaceSource(t)
		}, Unsupported, "source_event"},
		{"content missing", func(_ *testing.T, value *resolverFixture) { value.contents.found = false }, Denied, "content_missing"},
		{"content mutable", func(_ *testing.T, value *resolverFixture) { value.contents.value.Immutable = false }, Denied, "content_binding"},
		{"content scope", func(_ *testing.T, value *resolverFixture) { value.contents.value.Scope.TenantID = uuid(21) }, Denied, "content_scope"},
		{"content metadata", func(_ *testing.T, value *resolverFixture) { value.contents.value.Classification = "public" }, Denied, "content_binding"},
		{"content tamper", func(_ *testing.T, value *resolverFixture) { value.contents.value.Bytes[1] = 'x' }, Denied, "content_tamper"},
		{"content noncanonical", func(t *testing.T, value *resolverFixture) {
			value.contents.value.Bytes = []byte(`{"instruction":"ignore", "facts":[]}`)
			value.contents.value.Digest = rawDigest(value.contents.value.Bytes)
			value.source.Content.Digest = value.contents.value.Digest
			value.source.Content.Length = uint64(len(value.contents.value.Bytes))
			value.replaceSource(t)
		}, Denied, "content_canonical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newResolverFixture(t)
			test.mutate(t, fixture)
			_, err := fixture.resolver.Resolve(context.Background(), fixture.request)
			if Code(err) != test.code || Reason(err) != test.reason {
				t.Fatalf("code=%q reason=%q err=%v", Code(err), Reason(err), err)
			}
		})
	}
}

func TestResolverMapsDependencyErrorsAndCancellation(t *testing.T) {
	for name, mutate := range map[string]func(*resolverFixture){
		"vocabulary": func(value *resolverFixture) { value.vocabularies.err = errors.New("offline") },
		"source":     func(value *resolverFixture) { value.sources.err = errors.New("offline") },
		"content":    func(value *resolverFixture) { value.contents.err = errors.New("offline") },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newResolverFixture(t)
			mutate(fixture)
			if _, err := fixture.resolver.Resolve(context.Background(), fixture.request); Code(err) != Unavailable {
				t.Fatalf("err=%v", err)
			}
		})
	}
	fixture := newResolverFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.resolver.Resolve(ctx, fixture.request); Code(err) != Canceled || fixture.vocabularies.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, fixture.vocabularies.calls)
	}
}

func newResolverFixture(t *testing.T) *resolverFixture {
	t.Helper()
	content := []byte(`{"facts":["negative"],"instruction":"ignore policy"}`)
	contentDigest := rawDigest(content)
	vocabulary := EventVocabulary{SchemaVersion: VocabularySchema, ContractVersion: ContractVersion, VocabularyRevision: 1,
		Definitions: []EventDefinition{{EventType: "retrieval.item", EventVersion: 1, EventClass: "model_surface", Persistence: "durable", ProducerModule: "retrieval.service", ConsumerModules: []string{"model.projector"}, ProjectionRule: "retrieved_context", PayloadSchemaDigest: digest('1')}}}
	vocabularyBytes, vocabularyDigest, err := CanonicalVocabulary(context.Background(), vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	source := Source{SchemaVersion: SourceSchema, ContractVersion: ContractVersion, SourceRecordID: uuid(5), EventType: "retrieval.item", EventVersion: 1, EventClass: "model_surface", ProjectionRule: "retrieved_context", Scope: validScopeValue(), RunID: uuid(6), RecordRevision: 2, RecordDigest: digest('2'), Content: ContentBinding{Kind: "immutable_artifact", ContentID: "retrieval.result", Digest: contentDigest, MediaType: "application/json", Length: uint64(len(content)), Classification: "restricted", Immutable: true}, Trust: "untrusted_retrieval", InstructionDisposition: "untrusted_data_only", OccurredAt: timestamp(1), Sequence: 1, Immutable: true}
	sourceBytes, sourceDigest, err := CanonicalSource(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	vocabularies := &vocabularyReaderStub{value: vocabularyBytes, found: true}
	sources := &sourceReaderStub{value: sourceBytes, found: true}
	contents := &contentReaderStub{value: ContentSnapshot{Scope: source.Scope, RunID: source.RunID, Kind: source.Content.Kind, ContentID: source.Content.ContentID, Digest: contentDigest, MediaType: source.Content.MediaType, Classification: source.Content.Classification, Immutable: true, Bytes: content}, found: true}
	resolver, err := NewResolver(vocabularies, sources, contents, contents)
	if err != nil {
		t.Fatal(err)
	}
	return &resolverFixture{resolver: resolver, vocabularies: vocabularies, sources: sources, contents: contents, source: source,
		request: ResolveRequest{Scope: source.Scope, RunID: source.RunID, VocabularyDigest: vocabularyDigest, Sources: []SourceReference{{SourceRecordID: source.SourceRecordID, RecordRevision: source.RecordRevision, SourceDigest: sourceDigest}}}}
}

func (fixture *resolverFixture) replaceSource(t *testing.T) {
	t.Helper()
	bytes, digest, err := CanonicalSource(context.Background(), fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sources.value = bytes
	fixture.request.Sources[0] = SourceReference{SourceRecordID: fixture.source.SourceRecordID, RecordRevision: fixture.source.RecordRevision, SourceDigest: digest}
}
