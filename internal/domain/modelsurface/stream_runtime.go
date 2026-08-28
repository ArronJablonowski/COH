package modelsurface

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sync"
	"unicode/utf8"
)

type ValidatedStreamEvent = ValidatedDocument[StreamEvent]

// StreamEventWriter durably appends one already-validated lineage event.
type StreamEventWriter interface {
	AppendStreamEvent(context.Context, ValidatedStreamEvent) error
}

// StreamSession serializes one provider attempt and emits durable lineage for
// every observable output and its explicit terminal state.
type StreamSession struct {
	mu        sync.Mutex
	writer    StreamEventWriter
	binding   InferenceBinding
	sources   []string
	assembled []byte
	sequence  uint64
	started   bool
	terminal  bool
	observed  string
}

func NewStreamSession(ctx context.Context, binding InferenceBinding, writer StreamEventWriter) (*StreamSession, error) {
	if writer == nil {
		return nil, newError(InvalidInput, "stream_writer")
	}
	sealed, err := SealBinding(ctx, binding)
	if err != nil {
		return nil, err
	}
	if sealed.BindingDigest != binding.BindingDigest {
		return nil, newError(Denied, "stream_binding")
	}
	sources := append([]string(nil), binding.OrderedSourceRecordIDs...)
	slices.Sort(sources)
	return &StreamSession{writer: writer, binding: cloneBinding(binding), sources: sources}, nil
}

func (session *StreamSession) Start(ctx context.Context, observedAt string) (ValidatedStreamEvent, error) {
	return session.record(ctx, "started", nil, session.sources, "pending", observedAt)
}

// Append records provider text or a completed typed item. Content is retained
// only long enough to derive the final assembled-output digest.
func (session *StreamSession) Append(ctx context.Context, kind string, content []byte, sourceRecordIDs []string, observedAt string) (ValidatedStreamEvent, error) {
	if !oneOf(kind, "chunk", "item") || len(content) == 0 || len(content) > MaximumInputBytes || !utf8.Valid(content) {
		return ValidatedStreamEvent{}, newError(InvalidInput, "stream_append")
	}
	return session.record(ctx, kind, content, sourceRecordIDs, "pending", observedAt)
}

func (session *StreamSession) Finish(ctx context.Context, outcome, observedAt string) (ValidatedStreamEvent, error) {
	if !oneOf(outcome, "succeeded", "empty", "interrupted", "canceled", "timeout", "failed", "uncertain") {
		return ValidatedStreamEvent{}, newError(InvalidInput, "stream_terminal")
	}
	return session.record(ctx, "terminal", nil, session.sources, outcome, observedAt)
}

func (session *StreamSession) record(ctx context.Context, kind string, content []byte, sourceRecordIDs []string, outcome, observedAt string) (ValidatedStreamEvent, error) {
	if session == nil {
		return ValidatedStreamEvent{}, newError(InvalidInput, "stream_session")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.terminal || kind == "started" && session.started || kind != "started" && !session.started {
		return ValidatedStreamEvent{}, newError(Denied, "stream_state")
	}
	if !validTimestamp(observedAt) || session.observed != "" && !timestampAtOrAfter(observedAt, session.observed) ||
		!validLineageSubset(sourceRecordIDs, session.sources) {
		return ValidatedStreamEvent{}, newError(Denied, "stream_lineage")
	}
	if kind == "started" && !slices.Equal(sourceRecordIDs, session.sources) || kind == "terminal" && !slices.Equal(sourceRecordIDs, session.sources) {
		return ValidatedStreamEvent{}, newError(Denied, "stream_lineage")
	}
	nextAssembled := append([]byte(nil), session.assembled...)
	chunkDigest, assembledDigest := "", ""
	if oneOf(kind, "chunk", "item") {
		if uint64(len(nextAssembled))+uint64(len(content)) > MaximumSurfaceBytes {
			return ValidatedStreamEvent{}, newError(Denied, "stream_size")
		}
		nextAssembled = append(nextAssembled, content...)
		chunkDigest = streamBytesDigest(streamChunkDigestDomain, content)
	}
	if kind == "terminal" {
		if outcome == "succeeded" && len(nextAssembled) == 0 || outcome == "empty" && len(nextAssembled) != 0 {
			return ValidatedStreamEvent{}, newError(Denied, "stream_outcome")
		}
		assembledDigest = streamBytesDigest(assembledDigestDomain, nextAssembled)
	}
	event := StreamEvent{SchemaVersion: StreamSchema, ContractVersion: ContractVersion,
		RequestID: session.binding.RequestID, AttemptID: session.binding.AttemptID, BindingDigest: session.binding.BindingDigest,
		ProjectionDigest: session.binding.ProjectionDigest, InputSurfaceDigest: session.binding.SurfaceDigest,
		Sequence: session.sequence + 1, Kind: kind, SourceRecordIDs: append([]string(nil), sourceRecordIDs...),
		ChunkDigest: chunkDigest, AssembledDigest: assembledDigest, Outcome: outcome, ObservedAt: observedAt}
	canonical, _, err := CanonicalStreamEvent(ctx, event)
	if err != nil {
		return ValidatedStreamEvent{}, err
	}
	validated, err := DecodeStreamEvent(ctx, canonical)
	if err != nil {
		return ValidatedStreamEvent{}, err
	}
	if err := session.writer.AppendStreamEvent(ctx, validated); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return ValidatedStreamEvent{}, contextErr
		}
		return ValidatedStreamEvent{}, newError(Unavailable, "stream_persistence")
	}
	session.sequence++
	session.assembled = nextAssembled
	session.started = true
	session.terminal = kind == "terminal"
	session.observed = observedAt
	return validated, nil
}

func validLineageSubset(values, allowed []string) bool {
	if len(values) == 0 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validUUID7(value) || index > 0 && values[index-1] == value || !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func streamBytesDigest(domain string, value []byte) string {
	input := make([]byte, 0, len(domain)+len(value))
	input = append(input, domain...)
	input = append(input, value...)
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ValidateFallbackLineage requires a new attempt and provider binding while
// retaining the exact request, projection, ordered sources, artifacts, and
// rendered input surface from the failed primary attempt.
func ValidateFallbackLineage(ctx context.Context, primaryTerminal ValidatedStreamEvent, primary, fallback InferenceBinding) error {
	primarySealed, primaryErr := SealBinding(ctx, primary)
	fallbackSealed, fallbackErr := SealBinding(ctx, fallback)
	event := primaryTerminal.Value()
	if primaryErr != nil {
		return primaryErr
	}
	if fallbackErr != nil {
		return fallbackErr
	}
	if primarySealed.BindingDigest != primary.BindingDigest || fallbackSealed.BindingDigest != fallback.BindingDigest {
		return newError(Denied, "fallback_binding")
	}
	if event.Kind != "terminal" || event.Outcome != "failed" || event.RequestID != primary.RequestID ||
		event.AttemptID != primary.AttemptID || event.BindingDigest != primary.BindingDigest || event.ProjectionDigest != primary.ProjectionDigest ||
		event.InputSurfaceDigest != primary.SurfaceDigest {
		return newError(Denied, "fallback_terminal")
	}
	if fallback.RequestID != primary.RequestID || fallback.AttemptID == primary.AttemptID || fallback.ProviderID == primary.ProviderID ||
		fallback.Scope != primary.Scope || fallback.RunID != primary.RunID || fallback.ActorID != primary.ActorID ||
		fallback.ProjectionID != primary.ProjectionID || fallback.ProjectionVersion != primary.ProjectionVersion ||
		fallback.ProjectionDigest != primary.ProjectionDigest || !slices.Equal(fallback.OrderedSourceRecordIDs, primary.OrderedSourceRecordIDs) ||
		!slices.Equal(fallback.ArtifactDigests, primary.ArtifactDigests) || fallback.VocabularyDigest != primary.VocabularyDigest ||
		fallback.CompositionDigest != primary.CompositionDigest || fallback.SurfaceDigest != primary.SurfaceDigest {
		return newError(Denied, "fallback_lineage")
	}
	return nil
}
