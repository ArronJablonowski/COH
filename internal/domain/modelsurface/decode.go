package modelsurface

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

// ValidatedDocument owns canonical bytes and never returns aliases to them.
// Value decodes a fresh copy so slices in returned records cannot mutate the
// validated instance.
type ValidatedDocument[T any] struct {
	canonical []byte
	digest    string
}

func (value ValidatedDocument[T]) CanonicalBytes() []byte {
	return append([]byte(nil), value.canonical...)
}
func (value ValidatedDocument[T]) Digest() string { return value.digest }
func (value ValidatedDocument[T]) Value() T {
	var result T
	_ = json.Unmarshal(value.canonical, &result)
	return result
}

func DecodeVocabulary(ctx context.Context, input []byte) (ValidatedDocument[EventVocabulary], error) {
	return decodeValidated(ctx, input, SealVocabulary, func(value EventVocabulary) string { return value.VocabularyDigest })
}
func DecodeSource(ctx context.Context, input []byte) (ValidatedDocument[Source], error) {
	return decodeValidated(ctx, input, SealSource, func(value Source) string { return value.SourceDigest })
}
func DecodeProjection(ctx context.Context, input []byte) (ValidatedDocument[Projection], error) {
	return decodeValidated(ctx, input, SealProjection, func(value Projection) string { return value.ProjectionDigest })
}
func DecodeBinding(ctx context.Context, input []byte) (ValidatedDocument[InferenceBinding], error) {
	return decodeValidated(ctx, input, SealBinding, func(value InferenceBinding) string { return value.BindingDigest })
}
func DecodeStreamEvent(ctx context.Context, input []byte) (ValidatedDocument[StreamEvent], error) {
	return decodeValidated(ctx, input, SealStreamEvent, func(value StreamEvent) string { return value.EventDigest })
}
func DecodeCompaction(ctx context.Context, input []byte) (ValidatedDocument[CompactionReplacement], error) {
	if err := contextError(ctx); err != nil {
		return ValidatedDocument[CompactionReplacement]{}, err
	}
	canonical, value, err := decodeCanonical[CompactionReplacement](input)
	if err != nil {
		return ValidatedDocument[CompactionReplacement]{}, err
	}
	wantCoverage, wantReplacement := value.CoverageDigest, value.ReplacementDigest
	sealed, err := SealCompaction(ctx, value)
	if err != nil {
		return ValidatedDocument[CompactionReplacement]{}, err
	}
	if wantCoverage == "" || wantReplacement == "" || sealed.CoverageDigest != wantCoverage || sealed.ReplacementDigest != wantReplacement {
		return ValidatedDocument[CompactionReplacement]{}, newError(Denied, "record_digest_mismatch")
	}
	return ValidatedDocument[CompactionReplacement]{canonical: append([]byte(nil), canonical...), digest: wantReplacement}, nil
}
func DecodeTransition(ctx context.Context, input []byte) (ValidatedDocument[Transition], error) {
	return decodeValidated(ctx, input, SealTransition, func(value Transition) string { return value.TransitionDigest })
}

func decodeValidated[T any](ctx context.Context, input []byte, seal func(context.Context, T) (T, error), digest func(T) string) (ValidatedDocument[T], error) {
	if err := contextError(ctx); err != nil {
		return ValidatedDocument[T]{}, err
	}
	canonical, value, err := decodeCanonical[T](input)
	if err != nil {
		return ValidatedDocument[T]{}, err
	}
	want := digest(value)
	sealed, err := seal(ctx, value)
	if err != nil {
		return ValidatedDocument[T]{}, err
	}
	if want == "" || digest(sealed) != want {
		return ValidatedDocument[T]{}, newError(Denied, "record_digest_mismatch")
	}
	return ValidatedDocument[T]{canonical: append([]byte(nil), canonical...), digest: want}, nil
}

func decodeCanonical[T any](input []byte) ([]byte, T, error) {
	var zero T
	if len(input) == 0 || len(input) > MaximumInputBytes || !utf8.Valid(input) {
		return nil, zero, newError(InvalidInput, "document_size_or_encoding")
	}
	if err := checkDepth(input); err != nil {
		return nil, zero, err
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, zero, newError(InvalidInput, "document_decoding")
	}
	if !bytes.Equal(input, canonical) {
		return nil, zero, newError(InvalidInput, "document_canonical")
	}
	var value T
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, zero, newError(InvalidInput, "document_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, zero, newError(InvalidInput, "document_decoding")
	}
	reencoded, err := canonicalRecord(value)
	if err != nil || !bytes.Equal(canonical, reencoded) {
		return nil, zero, newError(InvalidInput, "document_shape")
	}
	return canonical, value, nil
}

func checkDepth(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return newError(InvalidInput, "document_decoding")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
				if depth > MaximumDepth {
					return newError(InvalidInput, "document_depth")
				}
			case '}', ']':
				depth--
			}
		}
	}
}
