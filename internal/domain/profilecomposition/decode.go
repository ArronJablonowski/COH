package profilecomposition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type ValidatedEnvelope struct {
	envelopeBytes []byte
	layerBytes    []byte
	layerDigest   string
}

func (value ValidatedEnvelope) CanonicalEnvelopeBytes() []byte {
	return append([]byte(nil), value.envelopeBytes...)
}
func (value ValidatedEnvelope) CanonicalLayerBytes() []byte {
	return append([]byte(nil), value.layerBytes...)
}
func (value ValidatedEnvelope) LayerDigest() string { return value.layerDigest }
func (value ValidatedEnvelope) Value() Envelope {
	var envelope Envelope
	_ = json.Unmarshal(value.envelopeBytes, &envelope)
	return envelope
}

func Decode(ctx context.Context, input []byte) (ValidatedEnvelope, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedEnvelope{}, err
	}
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return ValidatedEnvelope{}, newError(InvalidInput, "document_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return ValidatedEnvelope{}, newError(InvalidInput, "document_decoding")
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return ValidatedEnvelope{}, newError(InvalidInput, "document_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ValidatedEnvelope{}, newError(InvalidInput, "document_decoding")
	}
	reencoded, err := json.Marshal(envelope)
	if err != nil {
		return ValidatedEnvelope{}, newError(InvalidInput, "document_decoding")
	}
	complete, err := domaincontract.Canonicalize(reencoded)
	if err != nil || !bytes.Equal(canonical, complete) {
		return ValidatedEnvelope{}, newError(InvalidInput, "document_shape")
	}
	if err := validateEnvelope(envelope); err != nil {
		return ValidatedEnvelope{}, err
	}
	layerEncoded, err := json.Marshal(envelope.Layer)
	if err != nil {
		return ValidatedEnvelope{}, newError(InvalidInput, "layer_decoding")
	}
	layerCanonical, err := domaincontract.Canonicalize(layerEncoded)
	if err != nil {
		return ValidatedEnvelope{}, newError(InvalidInput, "layer_decoding")
	}
	want := digestBytes(layerDigestDomain, layerCanonical)
	if envelope.LayerDigest != want {
		return ValidatedEnvelope{}, newError(Denied, "layer_digest_mismatch")
	}
	if err := contextError(ctx); err != nil {
		return ValidatedEnvelope{}, err
	}
	return ValidatedEnvelope{envelopeBytes: append([]byte(nil), canonical...),
		layerBytes: append([]byte(nil), layerCanonical...), layerDigest: want}, nil
}

func digestBytes(domain string, canonical []byte) string {
	message := make([]byte, 0, len(domain)+len(canonical))
	message = append(message, domain...)
	message = append(message, canonical...)
	sum := sha256.Sum256(message)
	return "sha256:" + hex.EncodeToString(sum[:])
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
