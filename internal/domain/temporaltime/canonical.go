package temporaltime

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

func CanonicalCommand(ctx context.Context, command Command) ([]byte, string, error) {
	if err := validateCommand(ctx, command); err != nil {
		return nil, "", err
	}
	return canonicalValue(command)
}

func DecodeCommand(ctx context.Context, input []byte) (Command, []byte, string, error) {
	var command Command
	canonical, err := decodeCanonical(ctx, input, &command)
	if err != nil {
		return Command{}, nil, "", err
	}
	if err := validateCommand(ctx, command); err != nil {
		return Command{}, nil, "", err
	}
	return command, canonical, digestBytes(canonical), nil
}

func CanonicalRecord(ctx context.Context, record Record) ([]byte, string, error) {
	if err := validateRecord(ctx, record); err != nil {
		return nil, "", err
	}
	return canonicalValue(record)
}

func CanonicalComparison(ctx context.Context, comparison Comparison) ([]byte, string, error) {
	if err := validateComparison(ctx, comparison); err != nil {
		return nil, "", err
	}
	return canonicalValue(comparison)
}

func CanonicalReceipt(ctx context.Context, receipt Receipt) ([]byte, string, error) {
	if err := validateReceipt(ctx, receipt); err != nil {
		return nil, "", err
	}
	return canonicalValue(receipt)
}

func canonicalValue(value any) ([]byte, string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, "", newError(InvalidInput, InvalidSourceText, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, "", newError(InvalidInput, InvalidSourceText, err)
	}
	return canonical, digestBytes(canonical), nil
}

func decodeCanonical(ctx context.Context, input []byte, output any) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, newError(InvalidInput, InvalidSourceText, nil)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, newError(InvalidInput, InvalidSourceText, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return nil, newError(InvalidInput, InvalidSourceText, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, newError(InvalidInput, InvalidSourceText, err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return canonical, nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, InvalidSourceText, nil)
	}
	if err := ctx.Err(); errors.Is(err, context.Canceled) {
		return newError(Canceled, ContextCanceled, err)
	} else if errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, ContextDeadline, err)
	}
	return nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
