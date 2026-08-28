package extensionlifecycle

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuid7Pattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	timePattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
)

func validateEnvelope(value Envelope) error {
	if value.SchemaVersion != EnvelopeSchemaVersion || value.ContractVersion != ContractVersion ||
		value.Manifest.SchemaVersion != ManifestSchemaVersion || value.Manifest.ContractVersion != ContractVersion {
		return newError(Unsupported, "unsupported_contract")
	}
	if !validDigest(value.ManifestDigest) || len(value.ReviewSignatures) == 0 || len(value.ReviewSignatures) > 16 {
		return newError(InvalidInput, "envelope")
	}
	if err := validateManifest(value.Manifest); err != nil {
		return err
	}
	if err := validateSignature(value.PublisherSignature); err != nil {
		return err
	}
	if err := validateSignature(value.OwnerSignature); err != nil {
		return err
	}
	if value.OwnerSignature.ActorID != value.Manifest.OwnerActorID ||
		value.PublisherSignature.ActorID == value.Manifest.OwnerActorID {
		return newError(Denied, "signature_independence")
	}
	identities := make([]string, len(value.ReviewSignatures))
	reviewers := make([]string, len(value.ReviewSignatures))
	for index, signature := range value.ReviewSignatures {
		if err := validateSignature(signature); err != nil {
			return err
		}
		if signature.ActorID == value.Manifest.OwnerActorID || signature.ActorID == value.PublisherSignature.ActorID {
			return newError(Denied, "signature_independence")
		}
		identities[index] = signatureIdentity(signature)
		reviewers[index] = signature.ActorID
	}
	if !sortedUnique(identities) || !unique(reviewers) {
		return newError(Denied, "review_signature_order")
	}
	return nil
}

func validateManifest(value Manifest) error {
	validFrom, fromOK := parseTimestamp(value.ValidFrom)
	validUntil, untilOK := parseTimestamp(value.ValidUntil)
	if !validUUID7(value.ExtensionID) || !validToken(value.ExtensionName) || !semverPattern.MatchString(value.ExtensionVersion) ||
		!oneOf(value.ExtensionKind, "data_adapter", "model_provider", "query_provider", "skill_provider", "tool_provider") ||
		!validUUID7(value.OwnerActorID) || !validToken(value.OwnerModule) || !validDigest(value.ArtifactDigest) ||
		!validDigest(value.SBOMDigest) || !validDigest(value.ProvenanceDigest) || !validDigest(value.TestEvidenceDigest) ||
		!validDigest(value.ThreatModelDigest) || !validOptionalDigest(value.PredecessorManifestDigest) ||
		!validDigest(value.ReviewDigest) || !fromOK || !untilOK || !validUntil.After(validFrom) ||
		value.MaximumActiveWork == 0 || value.MaximumActiveWork > 100000 ||
		value.MaximumDrainDurationMS < 1000 || value.MaximumDrainDurationMS > 300000 ||
		!validTokenSet(value.DeclaredPermissions, 128) || !validScopeSet(value.DeclaredScopeTypes) {
		return newError(InvalidInput, "manifest")
	}
	if len(value.Dependencies) > 64 || len(value.Registrations) == 0 || len(value.Registrations) > 64 {
		return newError(InvalidInput, "manifest_bounds")
	}
	dependencies := make([]string, len(value.Dependencies))
	for index, dependency := range value.Dependencies {
		if !validCapability(dependency) || reservedCapability(dependency.CapabilityID) {
			return newError(InvalidInput, "dependency")
		}
		dependencies[index] = capabilityIdentity(dependency)
	}
	if !sortedUnique(dependencies) {
		return newError(InvalidInput, "dependency_order")
	}
	registrationIDs := make([]string, len(value.Registrations))
	for index, registration := range value.Registrations {
		if !validToken(registration.RegistrationID) || !oneOf(registration.Role, "consumer", "provider") ||
			!validCapability(registration.Capability) || !validToken(registration.ProviderID) ||
			!validTokenSet(registration.Permissions, 128) || !validScopeSet(registration.ScopeTypes) ||
			!validDigest(registration.ResourceLimitsDigest) || !isSubset(registration.Permissions, value.DeclaredPermissions) ||
			!isSubset(registration.ScopeTypes, value.DeclaredScopeTypes) {
			return newError(Denied, "registration_declaration")
		}
		if reservedCapability(registration.Capability.CapabilityID) || reservedProvider(registration.ProviderID) {
			return newError(Denied, "reserved_authority")
		}
		registrationIDs[index] = registration.RegistrationID
	}
	if !unique(registrationIDs) {
		return newError(Denied, "registration_identity")
	}
	return nil
}

func validateIntent(value ActivationIntent) error {
	issued, issuedOK := parseTimestamp(value.IssuedAt)
	deadline, deadlineOK := parseTimestamp(value.DeadlineAt)
	if value.SchemaVersion != IntentSchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "unsupported_contract")
	}
	if !validUUID7(value.RequestID) || !validUUID7(value.IdempotencyKey) || !validUUID7(value.ActorID) ||
		value.ActorKind != "administrator" || !validUUID7(value.OrganizationID) || !validUUID7(value.TenantID) ||
		!validUUID7(value.ExtensionID) || !validDigest(value.ManifestDigest) || !oneOf(value.Operation, "activate", "deactivate") ||
		!oneOf(value.Mode, "maintenance", "rollback", "startup", "upgrade") || !validDigest(value.RequestedScopeDigest) ||
		!validDigest(value.RequestedPermissionsDigest) || !validOptionalDigest(value.ExpectedPredecessorManifestDigest) ||
		!validOptionalDigest(value.RollbackAuthorizationDigest) || value.ActiveProfileRevision == 0 ||
		value.ActiveProfileRevision > MaximumRevision || !validDigest(value.ProfileBindingDigest) ||
		!validDigest(value.CompositionDigest) || !validDigest(value.CapabilityGraphDigest) ||
		value.ExpectedLifecycleRevision > MaximumRevision || value.ExpectedRegistryRevision == 0 ||
		value.ExpectedRegistryRevision > MaximumRevision || !validDigest(value.PolicyDecisionDigest) ||
		!validDigest(value.PromotionSnapshotDigest) || !validDigest(value.QualificationSnapshotDigest) ||
		!validDigest(value.AuditAvailabilityDigest) || value.EStopState != "armed" || value.EStopRevision == 0 ||
		value.EStopRevision > MaximumRevision || value.MaximumDrainDurationMS < 1000 || value.MaximumDrainDurationMS > 300000 ||
		!issuedOK || !deadlineOK || !deadline.After(issued) || !validDigest(value.IntentDigest) {
		return newError(InvalidInput, "intent")
	}
	if value.Mode == "rollback" && value.RollbackAuthorizationDigest == "" ||
		value.Mode != "rollback" && value.RollbackAuthorizationDigest != "" ||
		value.Mode == "startup" && value.Operation != "activate" {
		return newError(Denied, "intent_mode")
	}
	if value.AdministratorSignature.ActorID != value.ActorID {
		return newError(Denied, "administrator_identity")
	}
	return validateSignature(value.AdministratorSignature)
}

func validateSignature(value Signature) error {
	if !validUUID7(value.ActorID) || !validToken(value.KeyID) || value.KeyRevision == 0 ||
		value.KeyRevision > MaximumRevision || value.ApprovalRevision == 0 || value.ApprovalRevision > MaximumRevision ||
		value.Algorithm != SignatureAlgorithm || len(value.Value) != 86 {
		return newError(InvalidInput, "signature")
	}
	return nil
}

func validCapability(value CapabilityRef) bool {
	return validToken(value.CapabilityID) && semverPattern.MatchString(value.CapabilityVersion)
}
func reservedCapability(value string) bool { return strings.HasPrefix(value, "authority.") }
func reservedProvider(value string) bool {
	return slices.Contains([]string{"coh.approval", "coh.audit", "coh.broker", "coh.connector", "coh.credential", "coh.estop", "coh.evidence", "coh.policy", "coh.runner", "coh.validator"}, value)
}
func capabilityIdentity(value CapabilityRef) string {
	return value.CapabilityID + "\x00" + value.CapabilityVersion
}
func signatureIdentity(value Signature) string { return value.ActorID + "\x00" + value.KeyID }
func validScopeSet(values []string) bool {
	return validEnumSet(values, 4, "case", "organization", "task", "tenant")
}
func validEnumSet(values []string, maximum int, allowed ...string) bool {
	if len(values) == 0 || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !slices.Contains(allowed, value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}
func validTokenSet(values []string, maximum int) bool {
	if values == nil || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validToken(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}
func sortedUnique(values []string) bool {
	return values != nil && slices.IsSorted(values) && unique(values)
}
func unique(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
func isSubset(values, maximum []string) bool {
	for _, value := range values {
		if !slices.Contains(maximum, value) {
			return false
		}
	}
	return true
}
func validToken(value string) bool {
	return tokenPattern.MatchString(value) && strings.TrimSpace(value) == value
}
func validUUID7(value string) bool          { return uuid7Pattern.MatchString(value) }
func validDigest(value string) bool         { return digestPattern.MatchString(value) }
func validOptionalDigest(value string) bool { return value == "" || validDigest(value) }
func parseTimestamp(value string) (time.Time, bool) {
	if !timePattern.MatchString(value) {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	return parsed, err == nil
}
func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }
