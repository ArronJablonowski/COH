package toolregistry

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"
)

type registryEntry struct {
	verified                  VerifiedEnvelope
	publisherApprovalRevision uint64
}

type Registry struct {
	mu          sync.RWMutex
	clock       Clock
	entries     map[string]registryEntry
	manifestIDs map[string]string
}

func NewRegistry(clock Clock) (*Registry, error) {
	if clock == nil {
		return nil, NewError(InvalidInput, "registry_dependencies")
	}
	return &Registry{clock: clock, entries: make(map[string]registryEntry), manifestIDs: make(map[string]string)}, nil
}

func (registry *Registry) Admit(ctx context.Context, input []byte, authority PublisherAuthority) (Admission, error) {
	if registry == nil || registry.clock == nil {
		return Admission{}, NewError(Unavailable, "registry_unavailable")
	}
	if err := contextError(ctx); err != nil {
		return Admission{}, err
	}
	verified, err := Verify(ctx, input, authority)
	if err != nil {
		return Admission{}, err
	}
	now := registry.clock.Now().UTC()
	if now.IsZero() {
		return Admission{}, NewError(Unavailable, "clock_unavailable")
	}
	if err := validateCurrent(verified.manifest, now); err != nil {
		return Admission{}, err
	}
	key := registryKey(verified.manifest.ToolName, verified.manifest.ToolVersion)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if existing, found := registry.entries[key]; found {
		if bytes.Equal(existing.verified.envelopeBytes, verified.envelopeBytes) {
			if authority.ApprovalRevision < existing.publisherApprovalRevision {
				return Admission{}, NewError(Denied, "publisher_authority_stale")
			}
			if authority.ApprovalRevision > existing.publisherApprovalRevision {
				existing.publisherApprovalRevision = authority.ApprovalRevision
				registry.entries[key] = existing
			}
			return admissionFor(existing.verified, authority.ApprovalRevision, true), nil
		}
		return Admission{}, NewError(Conflict, "tool_identity_collision")
	}
	if existingKey, found := registry.manifestIDs[verified.manifest.ManifestID]; found && existingKey != key {
		return Admission{}, NewError(Conflict, "manifest_identity_collision")
	}
	if err := contextError(ctx); err != nil {
		return Admission{}, err
	}
	registry.entries[key] = registryEntry{verified: cloneVerified(verified), publisherApprovalRevision: authority.ApprovalRevision}
	registry.manifestIDs[verified.manifest.ManifestID] = key
	return admissionFor(verified, authority.ApprovalRevision, false), nil
}

func (registry *Registry) Resolve(ctx context.Context, reference ToolReference,
	authority PublisherAuthority) (VerifiedEnvelope, error) {
	if registry == nil || registry.clock == nil {
		return VerifiedEnvelope{}, NewError(Unavailable, "registry_unavailable")
	}
	if err := contextError(ctx); err != nil {
		return VerifiedEnvelope{}, err
	}
	if !tokenPattern.MatchString(reference.Name) || !versionPattern.MatchString(reference.Version) ||
		!digestPattern.MatchString(reference.ArtifactDigest) {
		return VerifiedEnvelope{}, NewError(InvalidInput, "tool_reference")
	}
	registry.mu.RLock()
	entry, found := registry.entries[registryKey(reference.Name, reference.Version)]
	registry.mu.RUnlock()
	if !found {
		return VerifiedEnvelope{}, NewError(NotFound, "tool_not_registered")
	}
	if authority.ApprovalRevision < entry.publisherApprovalRevision {
		return VerifiedEnvelope{}, NewError(Denied, "publisher_authority_stale")
	}
	verified, err := Verify(ctx, entry.verified.CanonicalEnvelopeBytes(), authority)
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	if verified.manifest.ArtifactDigest != reference.ArtifactDigest {
		return VerifiedEnvelope{}, NewError(Denied, "tool_digest_mismatch")
	}
	now := registry.clock.Now().UTC()
	if now.IsZero() {
		return VerifiedEnvelope{}, NewError(Unavailable, "clock_unavailable")
	}
	if err := validateCurrent(verified.manifest, now); err != nil {
		return VerifiedEnvelope{}, err
	}
	return cloneVerified(verified), nil
}

func (registry *Registry) ResolveOperation(ctx context.Context, reference ToolReference, operationName,
	requiredTier, runtimeCeiling string, authority PublisherAuthority) (Capability, error) {
	verified, err := registry.Resolve(ctx, reference, authority)
	if err != nil {
		return Capability{}, err
	}
	if !tokenPattern.MatchString(operationName) || !validTier(requiredTier) || !validTier(runtimeCeiling) {
		return Capability{}, NewError(InvalidInput, "operation_request")
	}
	manifest := verified.manifest
	index, found := slices.BinarySearchFunc(manifest.Operations, operationName,
		func(operation Operation, name string) int {
			if operation.Name < name {
				return -1
			}
			if operation.Name > name {
				return 1
			}
			return 0
		})
	if !found {
		return Capability{}, NewError(Denied, "operation_not_registered")
	}
	operation := manifest.Operations[index]
	if tierValue(runtimeCeiling) > tierValue(manifest.MaximumActionTier) ||
		tierValue(runtimeCeiling) > tierValue(operation.MaximumActionTier) {
		return Capability{}, NewError(Denied, "policy_ceiling_elevation")
	}
	if tierValue(requiredTier) < tierValue(operation.BaselineActionTier) {
		return Capability{}, NewError(Denied, "tier_below_baseline")
	}
	effective := minimumTier(manifest.MaximumActionTier, operation.MaximumActionTier, runtimeCeiling)
	if tierValue(requiredTier) > tierValue(effective) {
		return Capability{}, NewError(Denied, "tier_exceeds_effective_ceiling")
	}
	if err := contextError(ctx); err != nil {
		return Capability{}, err
	}
	return Capability{ManifestDigest: verified.ManifestDigest, ManifestID: manifest.ManifestID,
		Tool: reference, Operation: cloneOperation(operation), RequiredTier: requiredTier,
		RuntimeCeiling: runtimeCeiling, EffectiveCeiling: effective}, nil
}

func validateCurrent(manifest Manifest, now time.Time) error {
	validFrom, fromErr := time.Parse(timestampLayout, manifest.ValidFrom)
	validUntil, untilErr := time.Parse(timestampLayout, manifest.ValidUntil)
	if fromErr != nil || untilErr != nil || now.Before(validFrom) || !now.Before(validUntil) {
		return NewError(Denied, "manifest_not_current")
	}
	return nil
}

func registryKey(name, version string) string { return name + "@" + version }

func admissionFor(verified VerifiedEnvelope, approvalRevision uint64, replayed bool) Admission {
	manifest := verified.manifest
	return Admission{ManifestDigest: verified.ManifestDigest, ManifestID: manifest.ManifestID,
		Tool:        ToolReference{Name: manifest.ToolName, Version: manifest.ToolVersion, ArtifactDigest: manifest.ArtifactDigest},
		PublisherID: verified.PublisherID, PublisherKeyID: verified.PublisherKeyID,
		PublisherKeyRevision: verified.PublisherKeyRevision, PublisherApprovalRevision: approvalRevision,
		ReviewID: manifest.ReviewID, ReviewRevision: manifest.ReviewRevision, Replayed: replayed}
}

func cloneVerified(verified VerifiedEnvelope) VerifiedEnvelope {
	cloned := verified
	cloned.manifest = cloneManifest(verified.manifest)
	cloned.manifestBytes = append([]byte(nil), verified.manifestBytes...)
	cloned.envelopeBytes = append([]byte(nil), verified.envelopeBytes...)
	return cloned
}

func cloneOperation(operation Operation) Operation {
	manifest := cloneManifest(Manifest{Operations: []Operation{operation}})
	return manifest.Operations[0]
}

func minimumTier(values ...string) string {
	minimum := values[0]
	for _, value := range values[1:] {
		if tierValue(value) < tierValue(minimum) {
			minimum = value
		}
	}
	return minimum
}
