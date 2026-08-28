package profileactivation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func CanonicalTransition(ctx context.Context, value Transition) ([]byte, string, error) {
	if err := contextError(ctx); err != nil {
		return nil, "", err
	}
	if err := validateTransition(value, false); err != nil {
		return nil, "", err
	}
	value.TransitionDigest = ""
	canonical, err := canonicalValue(value)
	if err != nil {
		return nil, "", newError(InvalidInput, "transition_encoding")
	}
	digest := digestValue(transitionDigestDomain, canonical)
	value.TransitionDigest = digest
	canonical, err = canonicalValue(value)
	if err != nil {
		return nil, "", newError(InvalidInput, "transition_encoding")
	}
	return canonical, digest, nil
}

func DecodeTransition(ctx context.Context, input []byte) (Transition, error) {
	var value Transition
	if err := decodeStrict(ctx, input, &value); err != nil {
		return Transition{}, err
	}
	if err := validateTransition(value, true); err != nil {
		return Transition{}, err
	}
	want := value.TransitionDigest
	value.TransitionDigest = ""
	canonical, _ := canonicalValue(value)
	if want != digestValue(transitionDigestDomain, canonical) {
		return Transition{}, newError(Denied, "transition_digest")
	}
	value.TransitionDigest = want
	return value, nil
}

func CanonicalActive(ctx context.Context, value ActiveProfile) ([]byte, string, error) {
	if err := contextError(ctx); err != nil {
		return nil, "", err
	}
	if err := validateActive(value, false); err != nil {
		return nil, "", err
	}
	value.ActiveDigest = ""
	canonical, err := canonicalValue(value)
	if err != nil {
		return nil, "", newError(InvalidInput, "active_encoding")
	}
	digest := digestValue(activeDigestDomain, canonical)
	value.ActiveDigest = digest
	canonical, err = canonicalValue(value)
	if err != nil {
		return nil, "", newError(InvalidInput, "active_encoding")
	}
	return canonical, digest, nil
}

func DecodeActive(ctx context.Context, input []byte) (ActiveProfile, error) {
	var value ActiveProfile
	if err := decodeStrict(ctx, input, &value); err != nil {
		return ActiveProfile{}, err
	}
	if err := validateActive(value, true); err != nil {
		return ActiveProfile{}, err
	}
	want := value.ActiveDigest
	value.ActiveDigest = ""
	canonical, _ := canonicalValue(value)
	if want != digestValue(activeDigestDomain, canonical) {
		return ActiveProfile{}, newError(Denied, "active_digest")
	}
	value.ActiveDigest = want
	return value, nil
}

func intentDigest(request Request) (string, error) {
	material := struct {
		TransitionID              string    `json:"transition_id"`
		Mode                      Mode      `json:"mode"`
		MaxDrainDurationMS        uint64    `json:"max_drain_duration_ms"`
		Candidate                 Candidate `json:"candidate"`
		ExpectedActiveRevision    uint64    `json:"expected_active_revision"`
		ExpectedCompositionDigest string    `json:"expected_composition_digest"`
	}{request.TransitionID, request.Mode, request.MaxDrainDurationMS, request.Candidate,
		request.ExpectedActiveRevision, request.ExpectedCompositionDigest}
	canonical, err := canonicalValue(material)
	if err != nil {
		return "", err
	}
	return digestValue(intentDigestDomain, canonical), nil
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return domaincontract.Canonicalize(encoded)
}

func decodeStrict(ctx context.Context, input []byte, output any) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if len(input) == 0 || len(input) > 4<<20 {
		return newError(InvalidInput, "document_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return newError(InvalidInput, "document_decoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(InvalidInput, "document_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(InvalidInput, "document_decoding")
	}
	reencoded, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, reencoded) {
		return newError(InvalidInput, "document_shape")
	}
	return nil
}

func digestValue(domain string, canonical []byte) string {
	message := append([]byte(domain), canonical...)
	sum := sha256.Sum256(message)
	return "sha256:" + hex.EncodeToString(sum[:])
}
