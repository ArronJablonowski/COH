package profilecomposition

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"time"
)

type Clock interface{ Now() time.Time }

type VerifiedLayer struct {
	validated          ValidatedEnvelope
	trustRevision      uint64
	revocationRevision uint64
}

func (value VerifiedLayer) Layer() Layer                { return value.validated.Value().Layer }
func (value VerifiedLayer) LayerDigest() string         { return value.validated.LayerDigest() }
func (value VerifiedLayer) CanonicalLayerBytes() []byte { return value.validated.CanonicalLayerBytes() }
func (value VerifiedLayer) CanonicalEnvelopeBytes() []byte {
	return value.validated.CanonicalEnvelopeBytes()
}
func (value VerifiedLayer) TrustRevision() uint64      { return value.trustRevision }
func (value VerifiedLayer) RevocationRevision() uint64 { return value.revocationRevision }

func Verify(ctx context.Context, input []byte, snapshot TrustSnapshot, clock Clock) (VerifiedLayer, error) {
	if clock == nil {
		return VerifiedLayer{}, newError(InvalidInput, "clock_missing")
	}
	validated, err := Decode(ctx, input)
	if err != nil {
		return VerifiedLayer{}, err
	}
	now := clock.Now().UTC()
	if err := contextError(ctx); err != nil {
		return VerifiedLayer{}, err
	}
	if err := validateTrustSnapshot(snapshot, now); err != nil {
		return VerifiedLayer{}, err
	}
	envelope := validated.Value()
	layerIssued, _ := parseTimestamp(envelope.Layer.IssuedAt)
	layerNotBefore, _ := parseTimestamp(envelope.Layer.NotBefore)
	layerExpires, _ := parseTimestamp(envelope.Layer.ExpiresAt)
	if now.Before(layerNotBefore) {
		return VerifiedLayer{}, newError(Denied, "layer_not_yet_valid")
	}
	if !now.Before(layerExpires) {
		return VerifiedLayer{}, newError(Denied, "layer_expired")
	}
	digestBytes, err := hex.DecodeString(validated.LayerDigest()[len("sha256:"):])
	if err != nil || len(digestBytes) != 32 {
		return VerifiedLayer{}, newError(InvalidInput, "layer_digest")
	}
	message := append([]byte(signatureDomain), digestBytes...)
	maximumRevocation := uint64(0)
	for _, signature := range envelope.Signatures {
		authority, found := authorityFor(snapshot.Records, signature)
		if !found {
			return VerifiedLayer{}, newError(Denied, "signer_untrusted")
		}
		if !authority.Active || authority.Revoked {
			return VerifiedLayer{}, newError(Denied, "signer_revoked")
		}
		signedAt, _ := parseTimestamp(signature.SignedAt)
		if signedAt.Before(layerIssued) || !signedAt.Before(layerExpires) || signedAt.After(now) ||
			signedAt.Before(authority.ValidFrom) || !signedAt.Before(authority.ValidUntil) ||
			now.Before(authority.ValidFrom) || !now.Before(authority.ValidUntil) {
			return VerifiedLayer{}, newError(Denied, "signer_validity")
		}
		decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(signature.Signature)
		if decodeErr != nil || len(decoded) != ed25519.SignatureSize || !ed25519.Verify(authority.PublicKey, message, decoded) {
			return VerifiedLayer{}, newError(Denied, "signature_invalid")
		}
		maximumRevocation = max(maximumRevocation, authority.RevocationRevision)
	}
	if err := contextError(ctx); err != nil {
		return VerifiedLayer{}, err
	}
	return VerifiedLayer{validated: validated, trustRevision: snapshot.TrustRevision,
		revocationRevision: maximumRevocation}, nil
}

func validateTrustSnapshot(snapshot TrustSnapshot, now time.Time) error {
	if !validUUID7(snapshot.ScopeOrganizationID) ||
		!oneOf(snapshot.Environment, "compose", "native_server", "native_workstation", "test") ||
		snapshot.TrustRevision == 0 || snapshot.TrustRevision > MaximumRevision ||
		len(snapshot.Records) == 0 || len(snapshot.Records) > 256 ||
		snapshot.CreatedAt.Location() != time.UTC || snapshot.ExpiresAt.Location() != time.UTC ||
		snapshot.CreatedAt.After(now) || !now.Before(snapshot.ExpiresAt) ||
		snapshot.ExpiresAt.Sub(snapshot.CreatedAt) > MaximumTrustAge {
		return newError(Denied, "trust_snapshot")
	}
	identities := make([]string, len(snapshot.Records))
	for index, authority := range snapshot.Records {
		if !oneOf(authority.Role, "publisher", "reviewer") || !validUUID7(authority.SignerID) ||
			!validToken(authority.KeyID) || authority.KeyRevision == 0 || authority.KeyRevision > MaximumRevision ||
			authority.TrustRevision != snapshot.TrustRevision || authority.ValidFrom.Location() != time.UTC ||
			authority.ValidUntil.Location() != time.UTC || !authority.ValidUntil.After(authority.ValidFrom) ||
			len(authority.PublicKey) != ed25519.PublicKeySize ||
			authority.RevocationRevision > MaximumRevision || authority.Revoked && authority.RevocationRevision == 0 {
			return newError(Denied, "trust_record")
		}
		identities[index] = authority.Role + "\x00" + authority.SignerID + "\x00" + authority.KeyID
	}
	if !slices.IsSorted(identities) || !sortedUnique(identities) {
		return newError(Denied, "trust_order")
	}
	return nil
}

func authorityFor(records []SigningAuthority, signature Signature) (SigningAuthority, bool) {
	want := signatureIdentity(signature)
	index, found := slices.BinarySearchFunc(records, want, func(record SigningAuthority, identity string) int {
		got := record.Role + "\x00" + record.SignerID + "\x00" + record.KeyID
		if got < identity {
			return -1
		}
		if got > identity {
			return 1
		}
		return 0
	})
	if !found {
		return SigningAuthority{}, false
	}
	authority := records[index]
	if authority.KeyRevision != signature.KeyRevision {
		return SigningAuthority{}, false
	}
	authority.PublicKey = append(ed25519.PublicKey(nil), authority.PublicKey...)
	return authority, true
}
