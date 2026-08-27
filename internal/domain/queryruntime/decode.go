package queryruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const MaximumDocumentBytes = 1 << 20

func DecodeSession(ctx context.Context, input []byte) (Session, []byte, error) {
	return decodeRecord(ctx, input, func(value Session) error { return VerifySession(value) })
}

func DecodeSlicePlan(ctx context.Context, input []byte) (SlicePlan, []byte, error) {
	return decodeRecord(ctx, input, func(value SlicePlan) error { return VerifySlicePlan(value) })
}

func DecodeRateReservation(ctx context.Context, input []byte) (RateReservation, []byte, error) {
	return decodeRecord(ctx, input, func(value RateReservation) error { return VerifyRateReservation(value) })
}

func decodeRecord[T any](ctx context.Context, input []byte, verify func(T) error) (T, []byte, error) {
	var zero T
	if err := contextError(ctx); err != nil {
		return zero, nil, err
	}
	if len(input) == 0 || len(input) > MaximumDocumentBytes {
		return zero, nil, newError(InvalidInput, "document_size", nil)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return zero, nil, newError(InvalidInput, "document_decoding", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&zero); err != nil {
		return zero, nil, newError(InvalidInput, "document_decoding", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return zero, nil, newError(InvalidInput, "document_decoding", err)
	}
	if err := verify(zero); err != nil {
		return zero, nil, err
	}
	if err := contextError(ctx); err != nil {
		return zero, nil, err
	}
	return zero, append([]byte(nil), canonical...), nil
}
