package modelsurface

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type SourceReference struct {
	SourceRecordID string
	RecordRevision uint64
	SourceDigest   string
}

type ResolveRequest struct {
	Scope            Scope
	RunID            string
	VocabularyDigest string
	Sources          []SourceReference
}

// ContentSnapshot is returned by the owning durable-record or immutable-artifact
// store after an exact scope-authorized lookup. It contains data, not authority.
type ContentSnapshot struct {
	Scope          Scope
	RunID          string
	Kind           string
	ContentID      string
	Digest         string
	MediaType      string
	Classification string
	Immutable      bool
	Bytes          []byte
}

// VocabularyReader resolves one exact digest through a narrow read-only port.
type VocabularyReader interface {
	ReadVocabulary(context.Context, string) ([]byte, bool, error)
}

// SourceReader resolves one exact scope, identity, and revision through a
// narrow read-only port.
type SourceReader interface {
	ReadSource(context.Context, Scope, string, uint64) ([]byte, bool, error)
}

// DurableRecordReader resolves one source-owned durable content binding. It
// exposes no query, mutation, callback, or generic storage surface.
type DurableRecordReader interface {
	ReadDurableRecord(context.Context, Scope, string, ContentBinding) (ContentSnapshot, bool, error)
}

// ArtifactReader resolves one exact immutable artifact content binding.
type ArtifactReader interface {
	ReadArtifact(context.Context, Scope, string, ContentBinding) (ContentSnapshot, bool, error)
}

type Resolver struct {
	vocabularies VocabularyReader
	sources      SourceReader
	records      DurableRecordReader
	artifacts    ArtifactReader
}

func NewResolver(vocabularies VocabularyReader, sources SourceReader, records DurableRecordReader, artifacts ArtifactReader) (*Resolver, error) {
	if vocabularies == nil || sources == nil || records == nil || artifacts == nil {
		return nil, newError(InvalidInput, "resolver_dependencies")
	}
	return &Resolver{vocabularies: vocabularies, sources: sources, records: records, artifacts: artifacts}, nil
}

type ResolvedSource struct {
	source          Source
	sourceBytes     []byte
	contentBytes    []byte
	eventDefinition EventDefinition
}

func (value ResolvedSource) Source() Source       { return value.source }
func (value ResolvedSource) SourceBytes() []byte  { return append([]byte(nil), value.sourceBytes...) }
func (value ResolvedSource) ContentBytes() []byte { return append([]byte(nil), value.contentBytes...) }
func (value ResolvedSource) EventDefinition() EventDefinition {
	result := value.eventDefinition
	result.ConsumerModules = append([]string(nil), result.ConsumerModules...)
	return result
}

type ResolvedSources struct {
	vocabulary      EventVocabulary
	vocabularyBytes []byte
	items           []ResolvedSource
}

func (value ResolvedSources) Vocabulary() EventVocabulary {
	result := value.vocabulary
	result.Definitions = append([]EventDefinition(nil), value.vocabulary.Definitions...)
	for index := range result.Definitions {
		result.Definitions[index].ConsumerModules = append([]string(nil), value.vocabulary.Definitions[index].ConsumerModules...)
	}
	return result
}
func (value ResolvedSources) VocabularyBytes() []byte {
	return append([]byte(nil), value.vocabularyBytes...)
}
func (value ResolvedSources) Items() []ResolvedSource {
	result := make([]ResolvedSource, len(value.items))
	for index, item := range value.items {
		result[index] = ResolvedSource{source: item.source, sourceBytes: append([]byte(nil), item.sourceBytes...),
			contentBytes: append([]byte(nil), item.contentBytes...), eventDefinition: item.EventDefinition()}
	}
	return result
}

func (resolver *Resolver) Resolve(ctx context.Context, request ResolveRequest) (ResolvedSources, error) {
	if resolver == nil || resolver.vocabularies == nil || resolver.sources == nil || resolver.records == nil || resolver.artifacts == nil {
		return ResolvedSources{}, newError(InvalidInput, "resolver_dependencies")
	}
	if err := contextError(ctx); err != nil {
		return ResolvedSources{}, err
	}
	if !validScope(request.Scope) || !validUUID7(request.RunID) || !validDigest(request.VocabularyDigest) ||
		len(request.Sources) == 0 || len(request.Sources) > MaximumItems {
		return ResolvedSources{}, newError(InvalidInput, "resolve_request")
	}
	for _, reference := range request.Sources {
		if !validUUID7(reference.SourceRecordID) || reference.RecordRevision == 0 ||
			reference.RecordRevision > MaximumRevision || !validDigest(reference.SourceDigest) {
			return ResolvedSources{}, newError(InvalidInput, "source_reference")
		}
	}

	vocabularyBytes, found, err := resolver.vocabularies.ReadVocabulary(ctx, request.VocabularyDigest)
	if err != nil {
		return ResolvedSources{}, mapResolutionError(ctx, "vocabulary_unavailable")
	}
	if !found {
		return ResolvedSources{}, newError(Denied, "vocabulary_missing")
	}
	validatedVocabulary, err := DecodeVocabulary(ctx, vocabularyBytes)
	if err != nil || validatedVocabulary.Digest() != request.VocabularyDigest {
		return ResolvedSources{}, newError(Denied, "vocabulary_tamper")
	}
	vocabulary := validatedVocabulary.Value()
	definitions := make(map[string]EventDefinition, len(vocabulary.Definitions))
	for _, definition := range vocabulary.Definitions {
		definitions[eventIdentity(definition.EventType, definition.EventVersion)] = definition
	}

	items := make([]ResolvedSource, 0, len(request.Sources))
	totalContentBytes := uint64(0)
	for _, reference := range request.Sources {
		if err := contextError(ctx); err != nil {
			return ResolvedSources{}, err
		}
		sourceBytes, sourceFound, readErr := resolver.sources.ReadSource(ctx, request.Scope, reference.SourceRecordID, reference.RecordRevision)
		if readErr != nil {
			return ResolvedSources{}, mapResolutionError(ctx, "source_unavailable")
		}
		if !sourceFound {
			return ResolvedSources{}, newError(Denied, "source_missing")
		}
		validatedSource, decodeErr := DecodeSource(ctx, sourceBytes)
		if decodeErr != nil {
			return ResolvedSources{}, newError(Denied, "source_tamper")
		}
		source := validatedSource.Value()
		if source.SourceRecordID != reference.SourceRecordID || source.RecordRevision != reference.RecordRevision ||
			validatedSource.Digest() != reference.SourceDigest {
			return ResolvedSources{}, newError(Denied, "source_stale")
		}
		if source.Scope != request.Scope || source.RunID != request.RunID {
			return ResolvedSources{}, newError(Denied, "source_scope")
		}
		definition, supported := definitions[eventIdentity(source.EventType, source.EventVersion)]
		if !supported || definition.EventClass != "model_surface" || definition.Persistence != "durable" ||
			definition.ProjectionRule != source.ProjectionRule {
			return ResolvedSources{}, newError(Unsupported, "source_event")
		}

		var content ContentSnapshot
		var contentFound bool
		var contentErr error
		switch source.Content.Kind {
		case "durable_record":
			content, contentFound, contentErr = resolver.records.ReadDurableRecord(ctx, request.Scope, request.RunID, source.Content)
		case "immutable_artifact":
			content, contentFound, contentErr = resolver.artifacts.ReadArtifact(ctx, request.Scope, request.RunID, source.Content)
		default:
			return ResolvedSources{}, newError(Unsupported, "content_kind")
		}
		if contentErr != nil {
			return ResolvedSources{}, mapResolutionError(ctx, "content_unavailable")
		}
		if !contentFound {
			return ResolvedSources{}, newError(Denied, "content_missing")
		}
		if err := verifyContentSnapshot(request, source.Content, content); err != nil {
			return ResolvedSources{}, err
		}
		totalContentBytes += uint64(len(content.Bytes))
		if totalContentBytes > MaximumSurfaceBytes {
			return ResolvedSources{}, newError(Denied, "content_total_size")
		}
		items = append(items, ResolvedSource{source: source, sourceBytes: validatedSource.CanonicalBytes(),
			contentBytes: append([]byte(nil), content.Bytes...), eventDefinition: definition})
	}
	return ResolvedSources{vocabulary: vocabulary, vocabularyBytes: validatedVocabulary.CanonicalBytes(), items: items}, nil
}

func verifyContentSnapshot(request ResolveRequest, binding ContentBinding, snapshot ContentSnapshot) error {
	if snapshot.Scope != request.Scope || snapshot.RunID != request.RunID {
		return newError(Denied, "content_scope")
	}
	if snapshot.Kind != binding.Kind || snapshot.ContentID != binding.ContentID || snapshot.Digest != binding.Digest ||
		snapshot.MediaType != binding.MediaType || snapshot.Classification != binding.Classification ||
		!snapshot.Immutable || !binding.Immutable || uint64(len(snapshot.Bytes)) != binding.Length ||
		uint64(len(snapshot.Bytes)) > MaximumInputBytes {
		return newError(Denied, "content_binding")
	}
	if rawDigest(snapshot.Bytes) != binding.Digest {
		return newError(Denied, "content_tamper")
	}
	if !utf8.Valid(snapshot.Bytes) {
		return newError(Denied, "content_encoding")
	}
	if binding.MediaType == "application/json" || binding.MediaType == "application/schema+json" {
		canonical, err := domaincontract.Canonicalize(snapshot.Bytes)
		if err != nil || !bytes.Equal(canonical, snapshot.Bytes) {
			return newError(Denied, "content_canonical")
		}
	}
	return nil
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func eventIdentity(eventType string, eventVersion uint64) string {
	return eventType + "\x00" + formatUint(eventVersion)
}
func mapResolutionError(ctx context.Context, reason string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return newError(Unavailable, reason)
}
