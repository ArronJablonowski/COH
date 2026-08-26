package providercontract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	capabilityDigestDomain    = "COH-PROVIDER-CAPABILITY-V1\x00"
	requestDigestDomain       = "COH-PROVIDER-REQUEST-V1\x00"
	responseDigestDomain      = "COH-PROVIDER-RESPONSE-V1\x00"
	streamEventDigestDomain   = "COH-PROVIDER-STREAM-EVENT-V1\x00"
	qualificationDigestDomain = "COH-PROVIDER-QUALIFICATION-V1\x00"
)

type validatedDocument[T any] struct {
	digest string
	bytes  []byte
}

func (document validatedDocument[T]) Digest() string { return document.digest }
func (document validatedDocument[T]) CanonicalBytes() []byte {
	return append([]byte(nil), document.bytes...)
}
func (document validatedDocument[T]) value() T {
	var value T
	_ = json.Unmarshal(document.bytes, &value)
	return value
}

type ValidatedCapability struct {
	validatedDocument[CapabilitySnapshot]
}
type ValidatedRequest struct {
	validatedDocument[InferenceRequest]
}
type ValidatedResponse struct {
	validatedDocument[InferenceResponse]
}
type ValidatedStreamEvent struct{ validatedDocument[StreamEvent] }
type ValidatedQualification struct {
	validatedDocument[QualificationRecord]
}

func (value ValidatedCapability) Value() CapabilitySnapshot { return value.value() }
func (value ValidatedRequest) Value() InferenceRequest      { return value.value() }
func (value ValidatedResponse) Value() InferenceResponse    { return value.value() }
func (value ValidatedStreamEvent) Value() StreamEvent       { return value.value() }
func (value ValidatedQualification) Value() QualificationRecord {
	return value.value()
}

func DecodeCapability(ctx context.Context, input []byte) (ValidatedCapability, error) {
	document, err := decode(ctx, input, capabilityDigestDomain, validateCapabilityShape, ValidateCapability)
	return ValidatedCapability{document}, err
}

func DecodeRequest(ctx context.Context, input []byte) (ValidatedRequest, error) {
	document, err := decode(ctx, input, requestDigestDomain, validateRequestShape, ValidateRequest)
	return ValidatedRequest{document}, err
}

func DecodeResponse(ctx context.Context, input []byte) (ValidatedResponse, error) {
	document, err := decode(ctx, input, responseDigestDomain, validateResponseShape, ValidateResponse)
	return ValidatedResponse{document}, err
}

func DecodeStreamEvent(ctx context.Context, input []byte) (ValidatedStreamEvent, error) {
	document, err := decode(ctx, input, streamEventDigestDomain, validateStreamShape, ValidateStreamEvent)
	return ValidatedStreamEvent{document}, err
}

func DecodeQualification(ctx context.Context, input []byte) (ValidatedQualification, error) {
	document, err := decode(ctx, input, qualificationDigestDomain, validateQualificationShape, ValidateQualification)
	return ValidatedQualification{document}, err
}

func decode[T any](ctx context.Context, input []byte, domain string, shape func([]byte) error,
	validate func(T) error) (validatedDocument[T], error) {
	if err := contextError(ctx); err != nil {
		return validatedDocument[T]{}, err
	}
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_decoding")
	}
	if err := shape(canonical); err != nil {
		return validatedDocument[T]{}, err
	}
	var value T
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return validatedDocument[T]{}, NewError(InvalidInput, "document_decoding")
	}
	if err := validate(value); err != nil {
		return validatedDocument[T]{}, err
	}
	if err := contextError(ctx); err != nil {
		return validatedDocument[T]{}, err
	}
	digestInput := make([]byte, 0, len(domain)+len(canonical))
	digestInput = append(digestInput, domain...)
	digestInput = append(digestInput, canonical...)
	sum := sha256.Sum256(digestInput)
	return validatedDocument[T]{digest: "sha256:" + hex.EncodeToString(sum[:]), bytes: append([]byte(nil), canonical...)}, nil
}
