package oidcauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
	"github.com/ArronJablonowski/COH/internal/domain/oidcidentity"
)

const maximumCompactTokenBytes = 16 * 1024

type joseHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

func (service Service) verifyToken(ctx context.Context, compact []byte, now time.Time) (oidcidentity.Claims, KeyRecord, error) {
	var emptyClaims oidcidentity.Claims
	if len(compact) == 0 || len(compact) > maximumCompactTokenBytes {
		return emptyClaims, KeyRecord{}, authError(localidentity.Denied, "token_invalid")
	}
	parts := bytes.Split(compact, []byte{'.'})
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[2]) == 0 {
		return emptyClaims, KeyRecord{}, authError(localidentity.Denied, "token_invalid")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil || len(headerBytes) > 1024 {
		zero(headerBytes)
		return emptyClaims, KeyRecord{}, authError(localidentity.Denied, "token_invalid")
	}
	defer zero(headerBytes)
	header, err := decodeHeader(headerBytes)
	if err != nil || !slices.Contains(service.Config.AllowedAlgorithms, header.Algorithm) {
		return emptyClaims, KeyRecord{}, authError(localidentity.Denied, "token_invalid")
	}
	key, err := service.Keys.LookupKey(ctx, service.Config.Issuer, service.Config.JWKSReference, header.KeyID)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "key_source_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "token_invalid")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return emptyClaims, KeyRecord{}, resultErr
	}
	if !validKeyRecord(key) || key.Issuer != service.Config.Issuer || key.SourceReference != service.Config.JWKSReference ||
		key.ID != header.KeyID || key.Algorithm != header.Algorithm {
		return emptyClaims, KeyRecord{}, authError(localidentity.Denied, "token_invalid")
	}
	if !key.Active {
		return emptyClaims, key, authError(localidentity.Denied, "signing_key_revoked")
	}
	if now.Before(key.NotBefore) || !now.Before(key.ExpiresAt) {
		return emptyClaims, key, authError(localidentity.Denied, "signing_key_stale")
	}
	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil || len(signature) > 512 {
		zero(signature)
		return emptyClaims, key, authError(localidentity.Denied, "token_invalid")
	}
	defer zero(signature)
	signed := make([]byte, 0, len(parts[0])+1+len(parts[1]))
	signed = append(signed, parts[0]...)
	signed = append(signed, '.')
	signed = append(signed, parts[1]...)
	defer zero(signed)
	if !verifySignature(key, signed, signature) {
		return emptyClaims, key, authError(localidentity.Denied, "token_invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil || len(payload) > maximumCompactTokenBytes {
		zero(payload)
		return emptyClaims, key, authError(localidentity.Denied, "token_invalid")
	}
	defer zero(payload)
	claims, err := oidcidentity.DecodeClaims(payload)
	if err != nil {
		return emptyClaims, key, authError(localidentity.Denied, "token_invalid")
	}
	return claims, key, nil
}

func decodeHeader(input []byte) (joseHeader, error) {
	var header joseHeader
	if rejectDuplicateKeys(input) != nil {
		return header, authError(localidentity.Denied, "token_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil {
		return joseHeader{}, authError(localidentity.Denied, "token_invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || header.Type != "JWT" || !validOpaque(header.KeyID, 1, 128) {
		return joseHeader{}, authError(localidentity.Denied, "token_invalid")
	}
	return header, nil
}

func verifySignature(record KeyRecord, signed, signature []byte) bool {
	digest := sha256.Sum256(signed)
	switch key := record.PublicKey.(type) {
	case ed25519.PublicKey:
		return record.Algorithm == "EdDSA" && ed25519.Verify(key, signed, signature)
	case *ecdsa.PublicKey:
		if record.Algorithm != "ES256" || len(signature) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(key, digest[:], r, s)
	case *rsa.PublicKey:
		return record.Algorithm == "RS256" && rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
	default:
		return false
	}
}

func validKeyRecord(record KeyRecord) bool {
	if !validIssuer(record.Issuer) || !validOpaque(record.SourceReference, 1, 128) || !validOpaque(record.ID, 1, 128) ||
		record.Revision == 0 || record.NotBefore.IsZero() || !record.ExpiresAt.After(record.NotBefore) {
		return false
	}
	switch key := record.PublicKey.(type) {
	case ed25519.PublicKey:
		return record.Algorithm == "EdDSA" && len(key) == ed25519.PublicKeySize
	case *ecdsa.PublicKey:
		if record.Algorithm != "ES256" || key == nil || key.Curve != elliptic.P256() {
			return false
		}
		_, err := key.Bytes()
		return err == nil
	case *rsa.PublicKey:
		return record.Algorithm == "RS256" && key != nil && key.N != nil && key.N.BitLen() >= 2048 && key.E >= 65537 && key.E%2 == 1
	default:
		return false
	}
}

func rejectDuplicateKeys(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, keyOK := keyToken.(string)
				if keyErr != nil || !keyOK || seen[key] {
					return authError(localidentity.Denied, "token_invalid")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return authError(localidentity.Denied, "token_invalid")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return authError(localidentity.Denied, "token_invalid")
	}
	return nil
}

func validIssuer(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.ToValidUTF8(value, "") == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
}
