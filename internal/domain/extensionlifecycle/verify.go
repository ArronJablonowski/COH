package extensionlifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"time"
)

type Clock interface{ Now() time.Time }

type ValidatedAdmission struct {
	envelope           ValidatedEnvelope
	intent             ValidatedIntent
	authorityRevision  uint64
	revocationRevision uint64
}

func (value ValidatedAdmission) Envelope() ValidatedEnvelope { return value.envelope }
func (value ValidatedAdmission) Intent() ValidatedIntent     { return value.intent }
func (value ValidatedAdmission) AuthorityRevision() uint64   { return value.authorityRevision }
func (value ValidatedAdmission) RevocationRevision() uint64  { return value.revocationRevision }

func VerifyAdmission(ctx context.Context, envelopeInput, intentInput []byte, snapshot AuthoritySnapshot, clock Clock) (ValidatedAdmission, error) {
	if clock == nil {
		return ValidatedAdmission{}, newError(InvalidInput, "clock_missing")
	}
	envelope, err := DecodeEnvelope(ctx, envelopeInput)
	if err != nil {
		return ValidatedAdmission{}, err
	}
	intent, err := DecodeIntent(ctx, intentInput)
	if err != nil {
		return ValidatedAdmission{}, err
	}
	now := clock.Now().UTC()
	if err := validateAuthoritySnapshot(snapshot, now); err != nil {
		return ValidatedAdmission{}, err
	}
	manifest := envelope.Value().Manifest
	command := intent.Value()
	if err := validateBindings(manifest, envelope.ManifestDigest(), command, snapshot, now); err != nil {
		return ValidatedAdmission{}, err
	}
	maximumRevocation := uint64(0)
	outer := envelope.Value()
	checks := []struct {
		role, domain string
		signature    Signature
	}{
		{"publisher", publisherSignatureDomain, outer.PublisherSignature},
		{"owner", ownerSignatureDomain, outer.OwnerSignature},
	}
	for _, signature := range outer.ReviewSignatures {
		checks = append(checks, struct {
			role, domain string
			signature    Signature
		}{"reviewer", reviewerSignatureDomain, signature})
	}
	for _, check := range checks {
		revocation, verifyErr := verifySignature(snapshot, check.role, check.domain, envelope.ManifestDigest(), check.signature, now)
		if verifyErr != nil {
			return ValidatedAdmission{}, verifyErr
		}
		maximumRevocation = max(maximumRevocation, revocation)
	}
	revocation, err := verifySignature(snapshot, "administrator", administratorSignatureDomain, intent.Digest(), command.AdministratorSignature, now)
	if err != nil {
		return ValidatedAdmission{}, err
	}
	maximumRevocation = max(maximumRevocation, revocation)
	if err := contextError(ctx); err != nil {
		return ValidatedAdmission{}, err
	}
	return ValidatedAdmission{envelope: envelope, intent: intent, authorityRevision: snapshot.AuthorityRevision, revocationRevision: maximumRevocation}, nil
}

func validateBindings(manifest Manifest, manifestDigest string, intent ActivationIntent, snapshot AuthoritySnapshot, now time.Time) error {
	validFrom, _ := parseTimestamp(manifest.ValidFrom)
	validUntil, _ := parseTimestamp(manifest.ValidUntil)
	issued, _ := parseTimestamp(intent.IssuedAt)
	deadline, _ := parseTimestamp(intent.DeadlineAt)
	if now.Before(validFrom) || !now.Before(validUntil) {
		return newError(Denied, "manifest_validity")
	}
	if issued.After(now) || !now.Before(deadline) {
		return newError(Denied, "intent_validity")
	}
	if intent.ExtensionID != manifest.ExtensionID || intent.ManifestDigest != manifestDigest || snapshot.ManifestDigest != manifestDigest {
		return newError(Denied, "manifest_binding")
	}
	if intent.OrganizationID != snapshot.Scope.OrganizationID || intent.TenantID != snapshot.Scope.TenantID {
		return newError(Denied, "scope_binding")
	}
	scopeDigest, _ := ScopeDigest(snapshot.Scope)
	permissionsDigest, permissionsErr := PermissionsDigest(snapshot.Permissions)
	if permissionsErr != nil || intent.RequestedScopeDigest != scopeDigest || intent.RequestedPermissionsDigest != permissionsDigest ||
		!isSubset(snapshot.Permissions, manifest.DeclaredPermissions) || !scopeAllowed(snapshot.Scope, manifest.DeclaredScopeTypes) {
		return newError(Denied, "scope_or_permission_widening")
	}
	if intent.ActiveProfileRevision != snapshot.ProfileRevision || intent.ProfileBindingDigest != snapshot.ProfileBindingDigest ||
		intent.CompositionDigest != snapshot.CompositionDigest || intent.CapabilityGraphDigest != snapshot.CapabilityGraphDigest {
		return newError(Denied, "profile_binding")
	}
	if intent.ExpectedRegistryRevision != snapshot.RegistryRevision || intent.PolicyDecisionDigest != snapshot.PolicyDecisionDigest ||
		intent.PromotionSnapshotDigest != snapshot.PromotionSnapshotDigest ||
		intent.QualificationSnapshotDigest != snapshot.QualificationSnapshotDigest ||
		intent.AuditAvailabilityDigest != snapshot.AuditAvailabilityDigest || intent.EStopState != snapshot.EStopState ||
		intent.EStopRevision != snapshot.EStopRevision {
		return newError(Denied, "authority_binding")
	}
	if snapshot.ReviewDigest != manifest.ReviewDigest || !snapshot.ReviewActive || !snapshot.PromotionActive ||
		!snapshot.QualificationActive || !snapshot.PolicyAllowed || !snapshot.AuditAvailable ||
		!snapshot.DependenciesQualified || snapshot.ArtifactRevoked || snapshot.EStopState != "armed" {
		return newError(Denied, "authority_inactive")
	}
	if intent.MaximumDrainDurationMS > manifest.MaximumDrainDurationMS {
		return newError(Denied, "drain_widening")
	}
	if intent.Mode == "upgrade" && intent.ExpectedPredecessorManifestDigest != manifest.PredecessorManifestDigest ||
		intent.Mode == "rollback" && (intent.RollbackAuthorizationDigest == "" || intent.ExpectedPredecessorManifestDigest == "") {
		return newError(Denied, "lineage_binding")
	}
	return nil
}

func validateAuthoritySnapshot(snapshot AuthoritySnapshot, now time.Time) error {
	if snapshot.CreatedAt.Location() != time.UTC || snapshot.ExpiresAt.Location() != time.UTC || snapshot.CreatedAt.After(now) ||
		!now.Before(snapshot.ExpiresAt) || snapshot.ExpiresAt.Sub(snapshot.CreatedAt) > MaximumAuthorityAge ||
		snapshot.AuthorityRevision == 0 || snapshot.AuthorityRevision > MaximumRevision || snapshot.RegistryRevision == 0 ||
		snapshot.RegistryRevision > MaximumRevision || !validDigest(snapshot.ManifestDigest) ||
		!validDigest(snapshot.ReviewDigest) ||
		!validDigest(snapshot.PromotionSnapshotDigest) || !validDigest(snapshot.QualificationSnapshotDigest) ||
		!validDigest(snapshot.PolicyDecisionDigest) || !validDigest(snapshot.AuditAvailabilityDigest) ||
		snapshot.ProfileRevision == 0 || snapshot.ProfileRevision > MaximumRevision || !validDigest(snapshot.ProfileBindingDigest) ||
		!validDigest(snapshot.CompositionDigest) || !validDigest(snapshot.CapabilityGraphDigest) ||
		snapshot.EStopState != "armed" || snapshot.EStopRevision == 0 || snapshot.EStopRevision > MaximumRevision ||
		!validScope(snapshot.Scope) || !validTokenSet(snapshot.Permissions, 128) || len(snapshot.Records) < 4 || len(snapshot.Records) > 256 {
		return newError(Denied, "authority_snapshot")
	}
	identities := make([]string, len(snapshot.Records))
	for index, record := range snapshot.Records {
		if !oneOf(record.Role, "administrator", "owner", "publisher", "reviewer") || !validUUID7(record.ActorID) ||
			!validToken(record.KeyID) || record.KeyRevision == 0 || record.KeyRevision > MaximumRevision ||
			record.ApprovalRevision == 0 || record.ApprovalRevision > MaximumRevision ||
			record.AuthorityRevision != snapshot.AuthorityRevision || record.RevocationRevision > MaximumRevision ||
			record.ValidFrom.Location() != time.UTC || record.ValidUntil.Location() != time.UTC ||
			!record.ValidUntil.After(record.ValidFrom) || len(record.PublicKey) != ed25519.PublicKeySize ||
			record.Revoked && record.RevocationRevision == 0 {
			return newError(Denied, "authority_record")
		}
		identities[index] = authorityIdentity(record.Role, record.ActorID, record.KeyID)
	}
	if !sortedUnique(identities) {
		return newError(Denied, "authority_order")
	}
	return nil
}

func verifySignature(snapshot AuthoritySnapshot, role, domain, digest string, signature Signature, now time.Time) (uint64, error) {
	want := authorityIdentity(role, signature.ActorID, signature.KeyID)
	index, found := slices.BinarySearchFunc(snapshot.Records, want, func(record SigningAuthority, identity string) int {
		return stringsCompare(authorityIdentity(record.Role, record.ActorID, record.KeyID), identity)
	})
	if !found {
		return 0, newError(Denied, "signer_untrusted")
	}
	authority := snapshot.Records[index]
	if authority.KeyRevision != signature.KeyRevision || authority.ApprovalRevision != signature.ApprovalRevision ||
		!authority.Active || authority.Revoked || now.Before(authority.ValidFrom) || !now.Before(authority.ValidUntil) {
		return 0, newError(Denied, "signer_revoked")
	}
	digestBytes, err := hex.DecodeString(digest[len("sha256:"):])
	if err != nil || len(digestBytes) != sha256Size {
		return 0, newError(InvalidInput, "signature_digest")
	}
	signatureBytes, err := base64.RawURLEncoding.Strict().DecodeString(signature.Value)
	message := append([]byte(domain), digestBytes...)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize || !ed25519.Verify(authority.PublicKey, message, signatureBytes) {
		return 0, newError(Denied, "signature_invalid")
	}
	return authority.RevocationRevision, nil
}

const sha256Size = 32

func authorityIdentity(role, actorID, keyID string) string {
	return role + "\x00" + actorID + "\x00" + keyID
}
func stringsCompare(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
func validScope(scope ExactScope) bool {
	return validUUID7(scope.OrganizationID) && validUUID7(scope.TenantID) &&
		(scope.CaseID == "" || validUUID7(scope.CaseID)) && (scope.TaskID == "" || validUUID7(scope.TaskID))
}
func scopeAllowed(scope ExactScope, declared []string) bool {
	if !slices.Contains(declared, "organization") || !slices.Contains(declared, "tenant") {
		return false
	}
	return (scope.CaseID == "" || slices.Contains(declared, "case")) && (scope.TaskID == "" || slices.Contains(declared, "task"))
}
