package mappingregistry

import (
	"bytes"
	"context"
	"math"
)

type registryMutation struct {
	Status        Status
	Reason        Reason
	Revision      uint64
	SignedMapping *SignedMapping
	Snapshot      *RegistrySnapshot
}

func executeRegistryMutation(ctx context.Context, dependencies Dependencies, command Command) (registryMutation, error) {
	if err := dependencies.SourceSchemas.VerifySourceSchema(ctx, command.Case, command.Source); err != nil {
		return registryMutation{}, normalizeDependencyError(err)
	}
	if err := checkContext(ctx); err != nil {
		return registryMutation{}, err
	}
	switch command.Operation {
	case Register:
		return registerMapping(ctx, dependencies, command)
	case Promote:
		return promoteMapping(ctx, dependencies, command)
	case Rollback:
		return rollbackMapping(ctx, dependencies, command)
	case Revoke:
		return revokeMapping(ctx, dependencies, command)
	default:
		return registryMutation{}, newError(InvalidInput, ManifestInvalid, nil)
	}
}

func registerMapping(ctx context.Context, dependencies Dependencies, command Command) (registryMutation, error) {
	signed := *command.SignedMapping
	if !validCompatibility(signed.Manifest.Compatibility) {
		return registryMutation{}, newError(DeniedError, TargetIncompatible, nil)
	}
	decision, err := verifySignedAuthority(ctx, dependencies.Signatures, dependencies.Clock.Now(), signed)
	if err != nil {
		return registryMutation{}, err
	}
	if decision.Revocation != signed.Manifest.Revocation {
		return registryMutation{}, newError(DeniedError, RevocationStale, nil)
	}
	existing, found, err := dependencies.Store.LoadSignedMapping(ctx, command.MappingDigest)
	if err != nil {
		return registryMutation{}, normalizeDependencyError(err)
	}
	if found {
		left, _, leftErr := CanonicalSignedMapping(ctx, existing)
		right, _, rightErr := CanonicalSignedMapping(ctx, signed)
		if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
			return registryMutation{}, newError(ConflictError, ManifestDigestMismatch, nil)
		}
		return registryMutation{Status: Registered, Reason: RegisteredReason}, nil
	}
	owned := cloneSignedMapping(signed)
	return registryMutation{Status: Registered, Reason: RegisteredReason, SignedMapping: &owned}, nil
}

func promoteMapping(ctx context.Context, dependencies Dependencies, command Command) (registryMutation, error) {
	candidate, decision, err := loadMutationCandidate(ctx, dependencies, command)
	if err != nil {
		return registryMutation{}, err
	}
	snapshots, err := dependencies.Store.LoadSnapshots(ctx, command.Case, command.Source)
	if err != nil {
		return registryMutation{}, normalizeDependencyError(err)
	}
	if len(snapshots) > 1 {
		return registryMutation{}, newError(ConflictError, MappingAmbiguous, nil)
	}
	if len(snapshots) == 0 {
		if command.ExpectedRegistryRevision != 0 || candidate.Manifest.Revision != 1 || candidate.Manifest.PredecessorDigest != nil {
			return registryMutation{}, newError(DeniedError, MappingDowngrade, nil)
		}
		snapshot := RegistrySnapshot{Source: command.Source, Revision: 1, CurrentManifestDigest: candidate.ManifestDigest,
			Revocation: decision.Revocation}
		return registryMutation{Status: Promoted, Reason: PromotedReason, Revision: 1, Snapshot: &snapshot}, nil
	}
	current := snapshots[0]
	if err := validateMutationSnapshot(command, current); err != nil {
		return registryMutation{}, err
	}
	if current.Revision >= math.MaxInt64 {
		return registryMutation{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	if command.MappingDigest == current.CurrentManifestDigest || candidate.Manifest.PredecessorDigest == nil ||
		*candidate.Manifest.PredecessorDigest != current.CurrentManifestDigest {
		return registryMutation{}, newError(DeniedError, MappingDowngrade, nil)
	}
	currentMapping, found, err := dependencies.Store.LoadSignedMapping(ctx, current.CurrentManifestDigest)
	if err != nil {
		return registryMutation{}, normalizeDependencyError(err)
	}
	if !found || validateSignedMapping(ctx, currentMapping) != nil {
		return registryMutation{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	if currentMapping.Manifest.Revision >= math.MaxInt64 {
		return registryMutation{}, newError(DeniedError, MappingDowngrade, nil)
	}
	if candidate.Manifest.Revision != currentMapping.Manifest.Revision+1 {
		return registryMutation{}, newError(DeniedError, MappingDowngrade, nil)
	}
	snapshot := RegistrySnapshot{Source: command.Source, Revision: current.Revision + 1,
		CurrentManifestDigest: candidate.ManifestDigest, PredecessorManifestDigest: current.CurrentManifestDigest,
		Revocation: decision.Revocation}
	return registryMutation{Status: Promoted, Reason: PromotedReason, Revision: snapshot.Revision, Snapshot: &snapshot}, nil
}

func rollbackMapping(ctx context.Context, dependencies Dependencies, command Command) (registryMutation, error) {
	snapshot, err := loadCurrentMutationSnapshot(ctx, dependencies, command)
	if err != nil {
		return registryMutation{}, err
	}
	if snapshot.PredecessorManifestDigest == "" || command.MappingDigest != snapshot.PredecessorManifestDigest {
		return registryMutation{}, newError(DeniedError, MappingDowngrade, nil)
	}
	if snapshot.Revision >= math.MaxInt64 {
		return registryMutation{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	target, decision, err := loadMutationCandidate(ctx, dependencies, command)
	if err != nil {
		return registryMutation{}, err
	}
	predecessor := ""
	if target.Manifest.PredecessorDigest != nil {
		predecessor = *target.Manifest.PredecessorDigest
	}
	next := RegistrySnapshot{Source: command.Source, Revision: snapshot.Revision + 1,
		CurrentManifestDigest: target.ManifestDigest, PredecessorManifestDigest: predecessor, Revocation: decision.Revocation}
	return registryMutation{Status: RolledBack, Reason: RolledBackReason, Revision: next.Revision, Snapshot: &next}, nil
}

func revokeMapping(ctx context.Context, dependencies Dependencies, command Command) (registryMutation, error) {
	snapshot, err := loadCurrentMutationSnapshot(ctx, dependencies, command)
	if err != nil {
		return registryMutation{}, err
	}
	if command.MappingDigest != snapshot.CurrentManifestDigest {
		return registryMutation{}, newError(DeniedError, ManifestDigestMismatch, nil)
	}
	if snapshot.CurrentRevoked {
		return registryMutation{Status: Revoked, Reason: RevokedReason, Revision: snapshot.Revision}, nil
	}
	if snapshot.Revision >= math.MaxInt64 {
		return registryMutation{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	snapshot.Revision++
	snapshot.CurrentRevoked = true
	return registryMutation{Status: Revoked, Reason: RevokedReason, Revision: snapshot.Revision, Snapshot: &snapshot}, nil
}

func loadMutationCandidate(ctx context.Context, dependencies Dependencies, command Command) (SignedMapping, SignatureDecision, error) {
	signed, found, err := dependencies.Store.LoadSignedMapping(ctx, command.MappingDigest)
	if err != nil {
		return SignedMapping{}, SignatureDecision{}, normalizeDependencyError(err)
	}
	if !found {
		return SignedMapping{}, SignatureDecision{}, newError(DeniedError, MappingNotFound, nil)
	}
	if signed.ManifestDigest != command.MappingDigest {
		return SignedMapping{}, SignatureDecision{}, newError(DeniedError, ManifestDigestMismatch, nil)
	}
	if !sameSource(signed.Manifest.Source, command.Source) {
		return SignedMapping{}, SignatureDecision{}, newError(DeniedError, SourceMismatch, nil)
	}
	if !validCompatibility(signed.Manifest.Compatibility) {
		return SignedMapping{}, SignatureDecision{}, newError(DeniedError, TargetIncompatible, nil)
	}
	if err := validateSignedMapping(ctx, signed); err != nil {
		return SignedMapping{}, SignatureDecision{}, err
	}
	decision, err := verifySignedAuthority(ctx, dependencies.Signatures, dependencies.Clock.Now(), signed)
	return signed, decision, err
}

func loadCurrentMutationSnapshot(ctx context.Context, dependencies Dependencies, command Command) (RegistrySnapshot, error) {
	snapshots, err := dependencies.Store.LoadSnapshots(ctx, command.Case, command.Source)
	if err != nil {
		return RegistrySnapshot{}, normalizeDependencyError(err)
	}
	if len(snapshots) == 0 {
		return RegistrySnapshot{}, newError(DeniedError, MappingNotFound, nil)
	}
	if len(snapshots) != 1 {
		return RegistrySnapshot{}, newError(ConflictError, MappingAmbiguous, nil)
	}
	if err := validateMutationSnapshot(command, snapshots[0]); err != nil {
		return RegistrySnapshot{}, err
	}
	return snapshots[0], nil
}

func validateMutationSnapshot(command Command, snapshot RegistrySnapshot) error {
	if !sameSource(snapshot.Source, command.Source) || snapshot.Revision == 0 || snapshot.Revision > math.MaxInt64 || !digestPattern.MatchString(snapshot.CurrentManifestDigest) ||
		snapshot.PredecessorManifestDigest != "" && !digestPattern.MatchString(snapshot.PredecessorManifestDigest) || !validRevocation(snapshot.Revocation) {
		return newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	if command.ExpectedRegistryRevision != snapshot.Revision {
		if command.ExpectedRegistryRevision < snapshot.Revision {
			return newError(DeniedError, MappingDowngrade, nil)
		}
		return newError(ConflictError, MappingNotFound, nil)
	}
	return nil
}

func cloneSignedMapping(value SignedMapping) SignedMapping {
	encoded, _, _ := canonicalValue(value)
	var clone SignedMapping
	_, _ = decodeCanonical(context.Background(), encoded, &clone)
	return clone
}
