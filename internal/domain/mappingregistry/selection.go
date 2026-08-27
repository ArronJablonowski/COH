package mappingregistry

import (
	"context"
	"errors"
	"time"
)

const mappingSignaturePurpose = "normalization_mapping"

type verifiedMapping struct {
	Signed           SignedMapping
	ManifestDigest   string
	RegistryRevision uint64
}

func resolveVerifiedMapping(ctx context.Context, dependencies Dependencies, command Command) (verifiedMapping, error) {
	if err := checkContext(ctx); err != nil {
		return verifiedMapping{}, err
	}
	if dependencies.Signatures == nil || dependencies.SourceSchemas == nil || dependencies.Store == nil || dependencies.Clock == nil {
		return verifiedMapping{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	if command.Operation != Apply || !validSource(command.Source) || !digestPattern.MatchString(command.MappingDigest) {
		return verifiedMapping{}, newError(InvalidInput, ManifestInvalid, nil)
	}
	if err := dependencies.SourceSchemas.VerifySourceSchema(ctx, command.Case, command.Source); err != nil {
		return verifiedMapping{}, normalizeDependencyError(err)
	}
	if err := checkContext(ctx); err != nil {
		return verifiedMapping{}, err
	}
	snapshots, err := dependencies.Store.LoadSnapshots(ctx, command.Case, command.Source)
	if err != nil {
		return verifiedMapping{}, normalizeDependencyError(err)
	}
	snapshot, err := selectSnapshot(command, snapshots)
	if err != nil {
		return verifiedMapping{}, err
	}
	signed, found, err := dependencies.Store.LoadSignedMapping(ctx, snapshot.CurrentManifestDigest)
	if err != nil {
		return verifiedMapping{}, normalizeDependencyError(err)
	}
	if !found {
		return verifiedMapping{}, newError(DeniedError, MappingNotFound, nil)
	}
	if err := verifySelectedMapping(ctx, dependencies.Signatures, dependencies.Clock.Now(), command.Source, snapshot, signed); err != nil {
		return verifiedMapping{}, err
	}
	return verifiedMapping{Signed: signed, ManifestDigest: signed.ManifestDigest, RegistryRevision: snapshot.Revision}, nil
}

func selectSnapshot(command Command, snapshots []RegistrySnapshot) (RegistrySnapshot, error) {
	if len(snapshots) == 0 {
		return RegistrySnapshot{}, newError(DeniedError, MappingNotFound, nil)
	}
	if len(snapshots) != 1 {
		return RegistrySnapshot{}, newError(ConflictError, MappingAmbiguous, nil)
	}
	snapshot := snapshots[0]
	if !sameSource(snapshot.Source, command.Source) {
		return RegistrySnapshot{}, newError(DeniedError, SourceMismatch, nil)
	}
	if snapshot.Revision == 0 || !digestPattern.MatchString(snapshot.CurrentManifestDigest) ||
		!validRevocation(snapshot.Revocation) || snapshot.PredecessorManifestDigest != "" && !digestPattern.MatchString(snapshot.PredecessorManifestDigest) {
		return RegistrySnapshot{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	if snapshot.CurrentRevoked {
		return RegistrySnapshot{}, newError(DeniedError, ManifestRevoked, nil)
	}
	if command.ExpectedRegistryRevision != 0 && command.ExpectedRegistryRevision != snapshot.Revision {
		if command.ExpectedRegistryRevision < snapshot.Revision {
			return RegistrySnapshot{}, newError(DeniedError, MappingDowngrade, nil)
		}
		return RegistrySnapshot{}, newError(DeniedError, MappingNotFound, nil)
	}
	if command.MappingDigest != snapshot.CurrentManifestDigest {
		if command.MappingDigest == snapshot.PredecessorManifestDigest {
			return RegistrySnapshot{}, newError(DeniedError, MappingDowngrade, nil)
		}
		return RegistrySnapshot{}, newError(DeniedError, ManifestDigestMismatch, nil)
	}
	return snapshot, nil
}

func verifySelectedMapping(ctx context.Context, verifier SignatureVerifier, now time.Time, source SourceMatcher, snapshot RegistrySnapshot, signed SignedMapping) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if signed.ManifestDigest != snapshot.CurrentManifestDigest {
		return newError(DeniedError, ManifestDigestMismatch, nil)
	}
	if !validCompatibility(signed.Manifest.Compatibility) {
		return newError(DeniedError, TargetIncompatible, nil)
	}
	if err := validateSignedMapping(ctx, signed); err != nil {
		return err
	}
	if !sameSource(signed.Manifest.Source, source) {
		return newError(DeniedError, SourceMismatch, nil)
	}
	if !validPredecessor(snapshot, signed.Manifest) {
		return newError(DeniedError, MappingDowngrade, nil)
	}
	decision, err := verifySignedAuthority(ctx, verifier, now, signed)
	if err != nil {
		return err
	}
	if decision.Revocation != snapshot.Revocation {
		return newError(DeniedError, RevocationStale, nil)
	}
	return nil
}

func verifySignedAuthority(ctx context.Context, verifier SignatureVerifier, now time.Time, signed SignedMapping) (SignatureDecision, error) {
	notBefore, beforeOK := parseTimestamp(signed.Manifest.NotBefore)
	notAfter, afterOK := parseTimestamp(signed.Manifest.NotAfter)
	if !beforeOK || !afterOK {
		return SignatureDecision{}, newError(InvalidInput, ManifestInvalid, nil)
	}
	if now.IsZero() {
		return SignatureDecision{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	now = now.UTC()
	if now.Before(notBefore) {
		return SignatureDecision{}, newError(DeniedError, ManifestNotYetValid, nil)
	}
	if !now.Before(notAfter) {
		return SignatureDecision{}, newError(DeniedError, ManifestExpired, nil)
	}
	decision, err := verifier.VerifySignature(ctx, SignatureRequest{
		ManifestDigest: signed.ManifestDigest, PublisherID: signed.PublisherID,
		KeyID: signed.PublisherKeyID, KeyRevision: signed.PublisherKeyRevision,
		Algorithm: signed.SignatureAlgorithm, Signature: signed.Signature, Domain: signatureDomain,
		Purpose: mappingSignaturePurpose, NotBefore: signed.Manifest.NotBefore, NotAfter: signed.Manifest.NotAfter,
		Revocation: signed.Manifest.Revocation,
	})
	if err != nil {
		return SignatureDecision{}, normalizeDependencyError(err)
	}
	if err := checkContext(ctx); err != nil {
		return SignatureDecision{}, err
	}
	if !decision.Verified {
		return SignatureDecision{}, newError(DeniedError, SignatureInvalid, nil)
	}
	if decision.TrustRevision != signed.PublisherKeyRevision {
		return SignatureDecision{}, newError(DeniedError, PublisherUntrusted, nil)
	}
	if decision.Revoked {
		return SignatureDecision{}, newError(DeniedError, ManifestRevoked, nil)
	}
	if !validRevocation(decision.Revocation) || decision.Revocation.ListID != signed.Manifest.Revocation.ListID ||
		decision.Revocation.ListDigest != signed.Manifest.Revocation.ListDigest ||
		decision.Revocation.MinimumRevision < signed.Manifest.Revocation.MinimumRevision {
		return SignatureDecision{}, newError(DeniedError, RevocationStale, nil)
	}
	return decision, nil
}

func validPredecessor(snapshot RegistrySnapshot, manifest Manifest) bool {
	if manifest.Revision == 1 {
		return manifest.PredecessorDigest == nil && snapshot.PredecessorManifestDigest == ""
	}
	return manifest.PredecessorDigest != nil && *manifest.PredecessorDigest == snapshot.PredecessorManifestDigest
}

func sameSource(left, right SourceMatcher) bool {
	if left.SourceKind != right.SourceKind || left.Product != right.Product || left.ProductDigest != right.ProductDigest ||
		left.SourceSchema != right.SourceSchema || left.SourceSchemaVersion != right.SourceSchemaVersion ||
		left.SourceSchemaDigest != right.SourceSchemaDigest || left.CollectionMethod != right.CollectionMethod ||
		left.CollectionMethodVersion != right.CollectionMethodVersion {
		return false
	}
	if left.SourceIdentityDigest == nil || right.SourceIdentityDigest == nil {
		return left.SourceIdentityDigest == nil && right.SourceIdentityDigest == nil
	}
	return *left.SourceIdentityDigest == *right.SourceIdentityDigest
}

func normalizeDependencyError(err error) error {
	if Code(err) != "" {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return newError(CanceledError, ContextCanceled, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(TimeoutError, ContextDeadline, err)
	}
	return newError(UnavailableError, DependencyUnavailableReason, err)
}
