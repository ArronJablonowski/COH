package entityresolution

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

const MaximumInputBytes = 1 << 20

func CanonicalObservation(ctx context.Context, observation Observation) ([]byte, string, error) {
	if err := validateObservation(ctx, observation); err != nil {
		return nil, "", err
	}
	return canonicalValue(observation)
}

func DecodeObservation(ctx context.Context, input []byte) (Observation, []byte, string, error) {
	var observation Observation
	canonical, err := decodeCanonical(ctx, input, &observation)
	if err != nil {
		return Observation{}, nil, "", err
	}
	if err := validateObservation(ctx, observation); err != nil {
		return Observation{}, nil, "", err
	}
	return observation, canonical, digestBytes(canonical), nil
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
	if len(input) == 0 || len(input) > MaximumInputBytes {
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
