package mappingregistry

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

const signatureDomain = "COH-MAPPING-MANIFEST-V1\x00"

func CanonicalManifest(ctx context.Context, manifest Manifest) ([]byte, string, error) {
	if err := validateManifest(ctx, manifest); err != nil {
		return nil, "", err
	}
	return canonicalValue(manifest)
}

func CanonicalSignedMapping(ctx context.Context, signed SignedMapping) ([]byte, string, error) {
	if err := validateSignedMapping(ctx, signed); err != nil {
		return nil, "", err
	}
	return canonicalValue(signed)
}

func DecodeSignedMapping(ctx context.Context, input []byte) (SignedMapping, []byte, string, error) {
	var signed SignedMapping
	canonical, err := decodeCanonical(ctx, input, &signed)
	if err != nil {
		return SignedMapping{}, nil, "", err
	}
	if err := validateSignedMapping(ctx, signed); err != nil {
		return SignedMapping{}, nil, "", err
	}
	return signed, canonical, digestBytes(canonical), nil
}

func SignaturePreimage(manifestDigest string) ([]byte, error) {
	if !digestPattern.MatchString(manifestDigest) {
		return nil, newError(InvalidInput, ManifestDigestMismatch, nil)
	}
	raw, err := hex.DecodeString(manifestDigest[len("sha256:"):])
	if err != nil || len(raw) != sha256.Size {
		return nil, newError(InvalidInput, ManifestDigestMismatch, err)
	}
	return append([]byte(signatureDomain), raw...), nil
}

func canonicalValue(value any) ([]byte, string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, "", newError(InvalidInput, ManifestInvalid, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, "", newError(InvalidInput, ManifestInvalid, err)
	}
	return canonical, digestBytes(canonical), nil
}

func decodeCanonical(ctx context.Context, input []byte, output any) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, newError(InvalidInput, ManifestInvalid, nil)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, newError(InvalidInput, ManifestInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return nil, newError(InvalidInput, ManifestInvalid, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, newError(InvalidInput, ManifestInvalid, err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return canonical, nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, ManifestInvalid, nil)
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
