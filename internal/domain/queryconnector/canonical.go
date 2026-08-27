package queryconnector

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

const (
	capabilityDigestDomain   = "COH-QUERY-CAPABILITY-V1\x00"
	queryDigestDomain        = "COH-QUERY-REQUEST-V1\x00"
	validationDigestDomain   = "COH-QUERY-VALIDATION-V1\x00"
	executionDigestDomain    = "COH-QUERY-EXECUTION-V1\x00"
	schemaDigestDomain       = "COH-QUERY-SCHEMA-PAGE-V1\x00"
	pollDigestDomain         = "COH-QUERY-POLL-V1\x00"
	pageDigestDomain         = "COH-QUERY-PAGE-V1\x00"
	cancellationDigestDomain = "COH-QUERY-CANCELLATION-V1\x00"
)

type validatedDocument[T any] struct {
	value  T
	bytes  []byte
	digest string
}

func (document validatedDocument[T]) Value() T { return clone(document.value) }
func (document validatedDocument[T]) CanonicalBytes() []byte {
	return append([]byte(nil), document.bytes...)
}
func (document validatedDocument[T]) Digest() string { return document.digest }

type ValidatedCapability struct {
	validatedDocument[CapabilitySnapshot]
}
type ValidatedQuery struct{ validatedDocument[Query] }
type ValidatedValidation struct {
	validatedDocument[ValidationResult]
}
type ValidatedExecution struct{ validatedDocument[Execution] }
type ValidatedSchemaPage struct{ validatedDocument[SchemaPage] }
type ValidatedPoll struct{ validatedDocument[PollResult] }
type ValidatedPage struct{ validatedDocument[ResultPage] }
type ValidatedCancellation struct {
	validatedDocument[Cancellation]
}

func DecodeCapability(ctx context.Context, input []byte) (ValidatedCapability, error) {
	value, err := decode(ctx, input, capabilityDigestDomain, validateCapability)
	return ValidatedCapability{value}, err
}

func DecodeQuery(ctx context.Context, input []byte) (ValidatedQuery, error) {
	value, err := decode(ctx, input, queryDigestDomain, validateQuery)
	return ValidatedQuery{value}, err
}

func DecodeValidation(ctx context.Context, input []byte) (ValidatedValidation, error) {
	value, err := decode(ctx, input, validationDigestDomain, validateValidation)
	return ValidatedValidation{value}, err
}

func DecodeExecution(ctx context.Context, input []byte) (ValidatedExecution, error) {
	value, err := decode(ctx, input, executionDigestDomain, validateExecution)
	return ValidatedExecution{value}, err
}

func DecodeSchemaPage(ctx context.Context, input []byte) (ValidatedSchemaPage, error) {
	value, err := decode(ctx, input, schemaDigestDomain, validateSchemaPage)
	return ValidatedSchemaPage{value}, err
}

func DecodePoll(ctx context.Context, input []byte) (ValidatedPoll, error) {
	value, err := decode(ctx, input, pollDigestDomain, validatePoll)
	return ValidatedPoll{value}, err
}

func DecodePage(ctx context.Context, input []byte) (ValidatedPage, error) {
	value, err := decode(ctx, input, pageDigestDomain, validatePage)
	return ValidatedPage{value}, err
}

func DecodeCancellation(ctx context.Context, input []byte) (ValidatedCancellation, error) {
	value, err := decode(ctx, input, cancellationDigestDomain, validateCancellation)
	return ValidatedCancellation{value}, err
}

func decode[T any](ctx context.Context, input []byte, domain string, validate func(T) error) (validatedDocument[T], error) {
	var zero T
	if err := contextError(ctx); err != nil {
		return validatedDocument[T]{}, err
	}
	if len(input) == 0 || len(input) > MaximumDocumentBytes {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_size", nil)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_decoding", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&zero); err != nil {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_decoding", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_decoding", err)
	}
	if err := validate(zero); err != nil {
		return validatedDocument[T]{}, err
	}
	if err := contextError(ctx); err != nil {
		return validatedDocument[T]{}, err
	}
	hashInput := append([]byte(domain), canonical...)
	sum := sha256.Sum256(hashInput)
	return validatedDocument[T]{value: clone(zero), bytes: append([]byte(nil), canonical...), digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return NewError(InvalidInput, "context_required", nil)
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return NewError(Timeout, "request_timeout", err)
		}
		return NewError(Canceled, "request_canceled", err)
	}
	return nil
}

func clone[T any](value T) T {
	encoded, _ := json.Marshal(value)
	var output T
	_ = json.Unmarshal(encoded, &output)
	return output
}
