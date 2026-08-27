package normalizedevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

func Decode(ctx context.Context, input []byte) (ValidatedEnvelope, error) {
	if err := checkContext(ctx); err != nil {
		return ValidatedEnvelope{}, err
	}
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return ValidatedEnvelope{}, newError(InvalidInput, "input_size", nil)
	}
	canonical, err := canonicalize(input)
	if err != nil {
		return ValidatedEnvelope{}, newError(InvalidInput, "canonical_json", err)
	}
	if err := checkContext(ctx); err != nil {
		return ValidatedEnvelope{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return ValidatedEnvelope{}, newError(InvalidInput, "envelope_shape", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return ValidatedEnvelope{}, err
	}
	if err := validate(ctx, envelope); err != nil {
		return ValidatedEnvelope{}, err
	}
	return ValidatedEnvelope{digest: digestBytes(canonical), value: envelope, bytes: canonical}, nil
}

func ensureEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return newError(InvalidInput, "trailing_data", errors.New("unexpected trailing token"))
		}
		return newError(InvalidInput, "trailing_data", err)
	}
	return nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "nil_context", nil)
	}
	if err := ctx.Err(); errors.Is(err, context.Canceled) {
		return newError(Canceled, "context_canceled", err)
	} else if errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, "context_deadline", err)
	}
	return nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
