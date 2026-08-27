package investigationprojection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func CanonicalFact(ctx context.Context, value Fact) ([]byte, string, error) {
	if err := validateFact(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalProjection(ctx context.Context, value Projection) ([]byte, string, error) {
	if err := validateProjection(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalCheckpoint(ctx context.Context, value Checkpoint) ([]byte, string, error) {
	if err := validateCheckpoint(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalWatermark(ctx context.Context, value WatermarkRecord) ([]byte, string, error) {
	if err := validateWatermarkRecord(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalQuery(ctx context.Context, value Query) ([]byte, string, error) {
	if err := validateQuery(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func CanonicalCacheEntry(ctx context.Context, value CacheEntry) ([]byte, string, error) {
	if err := validateCacheEntry(ctx, value); err != nil {
		return nil, "", err
	}
	return canonicalValue(value)
}

func DecodeFact(ctx context.Context, input []byte) (Fact, []byte, string, error) {
	var value Fact
	canonical, err := decodeCanonical(ctx, input, &value)
	if err != nil {
		return Fact{}, nil, "", err
	}
	if err := validateFact(ctx, value); err != nil {
		return Fact{}, nil, "", err
	}
	return value, canonical, digestBytes(canonical), nil
}

func canonicalValue(value any) ([]byte, string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, "", newError(InvalidInputError, InvalidInput, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, "", newError(InvalidInputError, InvalidInput, err)
	}
	return canonical, digestBytes(canonical), nil
}

func decodeCanonical(ctx context.Context, input []byte, output any) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if len(input) == 0 || len(input) > MaximumBytes {
		return nil, newError(InvalidInputError, InvalidInput, nil)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, newError(InvalidInputError, InvalidInput, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return nil, newError(InvalidInputError, InvalidInput, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, newError(InvalidInputError, InvalidInput, err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return canonical, nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	if err := ctx.Err(); errors.Is(err, context.Canceled) {
		return newError(CanceledError, ContextCanceled, err)
	} else if errors.Is(err, context.DeadlineExceeded) {
		return newError(TimeoutError, ContextDeadline, err)
	}
	return nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
