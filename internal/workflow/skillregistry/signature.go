package skillregistry

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
)

func verifyEnvelope(ctx context.Context, input []byte, publisher SigningAuthority,
	reviewers []SigningAuthority, review ReviewAuthority) (verifiedEnvelope, error) {
	verified, err := decodeEnvelope(ctx, input)
	if err != nil {
		return verifiedEnvelope{}, err
	}
	manifest := verified.envelope.Manifest
	if !validateSigningAuthority(publisher) || publisher.ActorID != manifest.PublisherActorID {
		return verifiedEnvelope{}, newError(Denied, "publisher_authority_invalid", false, nil)
	}
	if err := validateReview(manifest, review, reviewers); err != nil {
		return verifiedEnvelope{}, err
	}
	if err := verifyDetached(verified.envelope.PublisherSignature, publisher, ManifestDomain, verified.manifestBytes); err != nil {
		return verifiedEnvelope{}, err
	}
	if len(verified.envelope.ReviewSignatures) != len(reviewers) {
		return verifiedEnvelope{}, newError(Denied, "review_signature_count_invalid", false, nil)
	}
	for index, authority := range reviewers {
		signature := verified.envelope.ReviewSignatures[index]
		if index > 0 && verified.envelope.ReviewSignatures[index-1].ActorID >= signature.ActorID {
			return verifiedEnvelope{}, newError(Denied, "review_signatures_not_canonical", false, nil)
		}
		if err := verifyDetached(signature, authority, ReviewDomain, verified.manifestBytes); err != nil {
			return verifiedEnvelope{}, err
		}
	}
	if err := contextError(ctx); err != nil {
		return verifiedEnvelope{}, err
	}
	return verified, nil
}

func verifyChange(ctx context.Context, input []byte, authority SigningAuthority) (verifiedChange, error) {
	verified, err := decodeChange(ctx, input)
	if err != nil {
		return verifiedChange{}, err
	}
	if !validateSigningAuthority(authority) || authority.ActorID != verified.value.Command.ActorID {
		return verifiedChange{}, newError(Denied, "change_authority_invalid", false, nil)
	}
	if err := verifyDetached(verified.value.Signature, authority, CommandDomain, verified.command); err != nil {
		return verifiedChange{}, err
	}
	return verified, nil
}

func verifyDetached(signature DetachedSignature, authority SigningAuthority, domain string, payload []byte) error {
	if signature.SignatureAlgorithm != SignatureAlgorithm || signature.ActorID != authority.ActorID ||
		signature.KeyID != authority.KeyID || signature.KeyRevision != authority.KeyRevision ||
		signature.ApprovalRevision != authority.ApprovalRevision {
		return newError(Denied, "signature_authority_mismatch", false, nil)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature.Signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return newError(InvalidInput, "signature_value_invalid", false, err)
	}
	message := make([]byte, 0, len(domain)+len(payload))
	message = append(message, domain...)
	message = append(message, payload...)
	if !ed25519.Verify(authority.PublicKey, message, decoded) {
		return newError(Denied, "signature_invalid", false, nil)
	}
	return nil
}

func constantDigest(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
