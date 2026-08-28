package extensionlifecycle

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func SealTransition(ctx context.Context, value Transition) (Transition, error) {
	value.TransitionDigest = ""
	if err := validateTransition(value); err != nil {
		return Transition{}, err
	}
	digest, err := sealRecord(ctx, transitionDigestDomain, &value, "transition_digest")
	if err != nil {
		return Transition{}, err
	}
	value.TransitionDigest = digest
	return value, nil
}

func SealHandle(ctx context.Context, value RevocationHandle) (RevocationHandle, error) {
	value.HandleDigest = ""
	if err := validateHandle(value); err != nil {
		return RevocationHandle{}, err
	}
	digest, err := sealRecord(ctx, handleDigestDomain, &value, "handle_digest")
	if err != nil {
		return RevocationHandle{}, err
	}
	value.HandleDigest = digest
	return value, nil
}

func SealReceipt(ctx context.Context, value RegistrationReceipt) (RegistrationReceipt, error) {
	value.ReceiptDigest = ""
	if err := validateReceipt(value); err != nil {
		return RegistrationReceipt{}, err
	}
	digest, err := sealRecord(ctx, receiptDigestDomain, &value, "receipt_digest")
	if err != nil {
		return RegistrationReceipt{}, err
	}
	value.ReceiptDigest = digest
	return value, nil
}

func SealActive(ctx context.Context, value ActiveExtension) (ActiveExtension, error) {
	value.ActiveDigest = ""
	if err := validateActive(value); err != nil {
		return ActiveExtension{}, err
	}
	digest, err := sealRecord(ctx, activeDigestDomain, &value, "active_digest")
	if err != nil {
		return ActiveExtension{}, err
	}
	value.ActiveDigest = digest
	return value, nil
}

func sealRecord(ctx context.Context, domain string, value any, digestField string) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(InvalidInput, "record_encoding")
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		return "", newError(InvalidInput, "record_encoding")
	}
	delete(object, digestField)
	encoded, _ = json.Marshal(object)
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(InvalidInput, "record_encoding")
	}
	return digestBytes(domain, canonical), nil
}

func validateTransition(value Transition) error {
	if value.SchemaVersion != TransitionSchema || value.ContractVersion != ContractVersion ||
		!validUUID7(value.TransitionID) || !validDigest(value.IntentDigest) || !validUUID7(value.ExtensionID) ||
		!validDigest(value.ManifestDigest) || !validUUID7(value.OrganizationID) || !validUUID7(value.TenantID) ||
		!oneOf(string(value.Direction), string(ActivateDirection), string(DeactivateDirection)) ||
		!oneOf(string(value.Phase), string(PreparedPhase), string(ApplyingPhase), string(UnwindingPhase), string(ActivePhase), string(DrainingPhase), string(RevokingPhase), string(InactivePhase)) ||
		value.Sequence == 0 || value.Sequence > MaximumRevision || value.ExpectedLifecycleRevision > MaximumRevision ||
		value.RegistryRevision == 0 || value.RegistryRevision > MaximumRevision || value.NextApplyOrdinal > 64 ||
		value.NextRevokeOrdinal < -1 || value.NextRevokeOrdinal > 63 || len(value.RegistrationReceiptDigests) > 64 ||
		value.ActiveWorkCount > 100000 || !validOptionalDigest(value.TerminalWorkDigest) ||
		!validOptionalDigest(value.ActivationAuditDigest) || !validOptionalDigest(value.TerminalAuditDigest) ||
		(value.FailureCode != "" && !validToken(value.FailureCode)) || !validTimestampString(value.CreatedAt) || !validTimestampString(value.UpdatedAt) {
		return newError(InvalidInput, "transition")
	}
	if !digestSetInOrder(value.RegistrationReceiptDigests) || value.NextApplyOrdinal != uint64(len(value.RegistrationReceiptDigests)) {
		return newError(Denied, "transition_receipts")
	}
	if value.Phase == PreparedPhase && (value.NextApplyOrdinal != 0 || value.NextRevokeOrdinal != -1) ||
		value.Phase == ActivePhase && (value.ActivationAuditDigest == "" || value.NextApplyOrdinal == 0) ||
		value.Phase == UnwindingPhase && value.NextRevokeOrdinal >= int64(value.NextApplyOrdinal) {
		return newError(Denied, "transition_phase")
	}
	return nil
}

func validateHandle(value RevocationHandle) error {
	if value.SchemaVersion != HandleSchema || value.ContractVersion != ContractVersion || !validUUID7(value.HandleID) ||
		!validUUID7(value.ExtensionID) || !validDigest(value.ManifestDigest) || !validUUID7(value.TransitionID) ||
		!validToken(value.RegistrationID) || value.RegistrationOrdinal > 63 || !validUUID7(value.OrganizationID) ||
		!validUUID7(value.TenantID) || !validDigest(value.ScopeDigest) || value.RegistryRevision == 0 ||
		value.RegistryRevision > MaximumRevision || value.Generation == 0 || value.Generation > MaximumRevision ||
		!validTimestampString(value.IssuedAt) {
		return newError(InvalidInput, "revocation_handle")
	}
	return nil
}

func validateReceipt(value RegistrationReceipt) error {
	if value.SchemaVersion != ReceiptSchema || value.ContractVersion != ContractVersion || !validUUID7(value.ReceiptID) ||
		!validUUID7(value.IdempotencyKey) || !validUUID7(value.ExtensionID) || !validDigest(value.ManifestDigest) ||
		!validUUID7(value.TransitionID) || !validToken(value.RegistrationID) || value.RegistrationOrdinal > 63 ||
		!oneOf(value.Role, "consumer", "provider") || !validToken(value.CapabilityID) || !semverPattern.MatchString(value.CapabilityVersion) ||
		!validToken(value.ProviderID) || !validUUID7(value.OrganizationID) || !validUUID7(value.TenantID) ||
		!validDigest(value.ScopeDigest) || !validDigest(value.PermissionsDigest) || !validDigest(value.ResourceLimitsDigest) ||
		value.RegistryRevision == 0 || value.RegistryRevision > MaximumRevision || value.Generation == 0 ||
		!oneOf(value.State, "registered", "revoked") || !validTimestampString(value.RegisteredAt) ||
		!validOptionalTimestamp(value.RevokedAt) || !validDigest(value.EffectAuditDigest) {
		return newError(InvalidInput, "registration_receipt")
	}
	if err := validateHandle(value.RevocationHandle); err != nil {
		return err
	}
	handle := value.RevocationHandle
	if handle.ExtensionID != value.ExtensionID || handle.ManifestDigest != value.ManifestDigest || handle.TransitionID != value.TransitionID ||
		handle.RegistrationID != value.RegistrationID || handle.RegistrationOrdinal != value.RegistrationOrdinal ||
		handle.OrganizationID != value.OrganizationID || handle.TenantID != value.TenantID || handle.ScopeDigest != value.ScopeDigest ||
		handle.RegistryRevision != value.RegistryRevision || handle.Generation != value.Generation ||
		value.State == "registered" && value.RevokedAt != "" || value.State == "revoked" && value.RevokedAt == "" {
		return newError(Denied, "receipt_owner_binding")
	}
	return nil
}

func validateActive(value ActiveExtension) error {
	if value.SchemaVersion != ActiveExtensionSchema || value.ContractVersion != ContractVersion || !validUUID7(value.ExtensionID) ||
		!validToken(value.ExtensionName) || !semverPattern.MatchString(value.ExtensionVersion) || !validDigest(value.ManifestDigest) ||
		!validUUID7(value.TransitionID) || value.LifecycleRevision == 0 || value.LifecycleRevision > MaximumRevision ||
		value.RegistryRevision == 0 || value.RegistryRevision > MaximumRevision || !validUUID7(value.OrganizationID) ||
		!validUUID7(value.TenantID) || value.ActiveProfileRevision == 0 || !validDigest(value.ProfileBindingDigest) ||
		!validDigest(value.CompositionDigest) || !validDigest(value.CapabilityGraphDigest) ||
		len(value.RegistrationReceiptDigests) == 0 || len(value.RegistrationReceiptDigests) > 64 ||
		!digestSetInOrder(value.RegistrationReceiptDigests) || !validDigest(value.ActivationAuditDigest) ||
		!validTimestampString(value.ActivatedAt) {
		return newError(InvalidInput, "active_extension")
	}
	return nil
}

func digestSetInOrder(values []string) bool {
	for _, value := range values {
		if !validDigest(value) {
			return false
		}
	}
	return len(values) == 0 || !slices.Contains(values[1:], values[0]) && unique(values)
}
func validTimestampString(value string) bool   { _, ok := parseTimestamp(value); return ok }
func validOptionalTimestamp(value string) bool { return value == "" || validTimestampString(value) }
