package modelsurface

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func SealVocabulary(ctx context.Context, value EventVocabulary) (EventVocabulary, error) {
	value.VocabularyDigest = ""
	if err := validateVocabulary(value); err != nil {
		return EventVocabulary{}, err
	}
	digest, err := sealRecord(ctx, vocabularyDigestDomain, value, "vocabulary_digest")
	if err != nil {
		return EventVocabulary{}, err
	}
	value.VocabularyDigest = digest
	return value, nil
}

func SealSource(ctx context.Context, value Source) (Source, error) {
	value.SourceDigest = ""
	if err := validateSource(value); err != nil {
		return Source{}, err
	}
	digest, err := sealRecord(ctx, sourceDigestDomain, value, "source_digest")
	if err != nil {
		return Source{}, err
	}
	value.SourceDigest = digest
	return value, nil
}

func SealProjection(ctx context.Context, value Projection) (Projection, error) {
	value.ProjectionDigest = ""
	if err := validateProjection(value); err != nil {
		return Projection{}, err
	}
	digest, err := sealRecord(ctx, projectionDigestDomain, value, "projection_digest")
	if err != nil {
		return Projection{}, err
	}
	value.ProjectionDigest = digest
	return value, nil
}

func SealBinding(ctx context.Context, value InferenceBinding) (InferenceBinding, error) {
	value.BindingDigest = ""
	if err := validateBinding(value); err != nil {
		return InferenceBinding{}, err
	}
	digest, err := sealRecord(ctx, bindingDigestDomain, value, "binding_digest")
	if err != nil {
		return InferenceBinding{}, err
	}
	value.BindingDigest = digest
	return value, nil
}

func SealStreamEvent(ctx context.Context, value StreamEvent) (StreamEvent, error) {
	value.EventDigest = ""
	if err := validateStream(value); err != nil {
		return StreamEvent{}, err
	}
	digest, err := sealRecord(ctx, streamDigestDomain, value, "event_digest")
	if err != nil {
		return StreamEvent{}, err
	}
	value.EventDigest = digest
	return value, nil
}

func SealCompaction(ctx context.Context, value CompactionReplacement) (CompactionReplacement, error) {
	value.CoverageDigest = ""
	value.ReplacementDigest = ""
	if err := validateCompaction(value); err != nil {
		return CompactionReplacement{}, err
	}
	coverage, err := canonicalDigest(ctx, coverageDigestDomain, value.CoveredSources)
	if err != nil {
		return CompactionReplacement{}, err
	}
	value.CoverageDigest = coverage
	replacement, err := sealRecord(ctx, replacementDigestDomain, value, "replacement_digest")
	if err != nil {
		return CompactionReplacement{}, err
	}
	value.ReplacementDigest = replacement
	return value, nil
}

func SealTransition(ctx context.Context, value Transition) (Transition, error) {
	value.TransitionDigest = ""
	if err := validateTransition(value); err != nil {
		return Transition{}, err
	}
	digest, err := sealRecord(ctx, transitionDigestDomain, value, "transition_digest")
	if err != nil {
		return Transition{}, err
	}
	value.TransitionDigest = digest
	return value, nil
}

func CanonicalVocabulary(ctx context.Context, value EventVocabulary) ([]byte, string, error) {
	sealed, err := SealVocabulary(ctx, value)
	return canonicalSealed(sealed, sealed.VocabularyDigest, err)
}
func CanonicalSource(ctx context.Context, value Source) ([]byte, string, error) {
	sealed, err := SealSource(ctx, value)
	return canonicalSealed(sealed, sealed.SourceDigest, err)
}
func CanonicalProjection(ctx context.Context, value Projection) ([]byte, string, error) {
	sealed, err := SealProjection(ctx, value)
	return canonicalSealed(sealed, sealed.ProjectionDigest, err)
}
func CanonicalBinding(ctx context.Context, value InferenceBinding) ([]byte, string, error) {
	sealed, err := SealBinding(ctx, value)
	return canonicalSealed(sealed, sealed.BindingDigest, err)
}
func CanonicalStreamEvent(ctx context.Context, value StreamEvent) ([]byte, string, error) {
	sealed, err := SealStreamEvent(ctx, value)
	return canonicalSealed(sealed, sealed.EventDigest, err)
}
func CanonicalCompaction(ctx context.Context, value CompactionReplacement) ([]byte, string, error) {
	sealed, err := SealCompaction(ctx, value)
	return canonicalSealed(sealed, sealed.ReplacementDigest, err)
}
func CanonicalTransition(ctx context.Context, value Transition) ([]byte, string, error) {
	sealed, err := SealTransition(ctx, value)
	return canonicalSealed(sealed, sealed.TransitionDigest, err)
}

func canonicalSealed(value any, digest string, sealErr error) ([]byte, string, error) {
	if sealErr != nil {
		return nil, "", sealErr
	}
	canonical, err := canonicalRecord(value)
	if err != nil {
		return nil, "", err
	}
	return canonical, digest, nil
}

func sealRecord(ctx context.Context, domain string, value any, digestField string) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(InvalidInput, "record_encoding")
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		return "", newError(InvalidInput, "record_encoding")
	}
	delete(object, digestField)
	return canonicalDigest(ctx, domain, object)
}

func canonicalDigest(ctx context.Context, domain string, value any) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	canonical, err := canonicalRecord(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalRecord(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(InvalidInput, "record_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InvalidInput, "record_encoding")
	}
	return canonical, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_missing")
	}
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return newError(Timeout, "deadline_exceeded")
		}
		return newError(Canceled, "context_canceled")
	default:
		return nil
	}
}
