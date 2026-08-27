package splunk

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const splunkTimestampLayout = "2006-01-02T15:04:05.000000000Z"

type Qualifier struct {
	config Config
	client Client
	clock  Clock
}

func NewQualifier(config Config, client Client, clock Clock) (*Qualifier, error) {
	if err := validateConfig(config); err != nil || nilPort(client) || nilPort(clock) {
		return nil, invalidInput("splunk_qualifier_configuration_invalid")
	}
	return &Qualifier{config: cloneConfig(config), client: client, clock: clock}, nil
}

func (qualifier *Qualifier) Qualify(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (ValidatedQualification, error) {
	if qualifier == nil {
		return ValidatedQualification{}, invalidInput("splunk_qualifier_required")
	}
	if err := contextError(ctx); err != nil {
		return ValidatedQualification{}, err
	}
	targets := append([]string(nil), scope.ResourceIDs...)
	identityBinding := CallBinding{Scope: scope, Authority: authority, Operation: "splunk.server_info", Targets: targets}
	if err := validateCallBinding(qualifier.config, identityBinding, identityBinding.Operation); err != nil {
		return ValidatedQualification{}, err
	}
	identity, identityReceipt, err := qualifier.client.ServerInfo(ctx, identityBinding)
	if err != nil {
		return ValidatedQualification{}, err
	}
	if err := validateQualificationReceipt(qualifier.config, identityReceipt); err != nil {
		return ValidatedQualification{}, err
	}
	if err := validateServerIdentity(qualifier.config, identity); err != nil {
		return ValidatedQualification{}, err
	}
	capabilityBinding := CallBinding{Scope: scope, Authority: authority, Operation: "splunk.current_context", Targets: targets}
	current, capabilityReceipt, err := qualifier.client.CurrentContext(ctx, capabilityBinding)
	if err != nil {
		return ValidatedQualification{}, err
	}
	if err := validateQualificationReceipt(qualifier.config, capabilityReceipt); err != nil {
		return ValidatedQualification{}, err
	}
	if err := validateCurrentCapabilities(qualifier.config, current.Capabilities); err != nil {
		return ValidatedQualification{}, err
	}
	now := qualifier.clock.Now().UTC()
	if now.IsZero() {
		return ValidatedQualification{}, deniedCall("splunk_qualification_time_invalid")
	}
	validUntil := now.Add(time.Duration(qualifier.config.QualificationLifetimeSeconds) * time.Second)
	value := Qualification{SchemaVersion: QualificationVersion, ContractVersion: ContractVersion,
		SourceID: qualifier.config.SourceID, AdapterVersion: qualifier.config.AdapterVersion,
		ObservedAt: now.Format(splunkTimestampLayout), ValidUntil: validUntil.Format(splunkTimestampLayout),
		ServerGUID: identity.GUID, ProductType: identity.ProductType, Version: identity.Version, Build: identity.Build,
		ServerRoles: append([]string(nil), identity.ServerRoles...), Capabilities: append([]string(nil), current.Capabilities...),
		ConfigDigest: hashValue("COH-SPLUNK-CONFIG-V1\x00", qualifier.config),
		ServerIdentityDigest: hashValue("COH-SPLUNK-SERVER-IDENTITY-V1\x00", struct {
			Identity ServerIdentity
			Receipt  CallReceipt
		}{identity, identityReceipt}),
		CapabilitiesDigest: hashValue("COH-SPLUNK-CAPABILITIES-V1\x00", struct {
			Capabilities []string
			Receipt      CallReceipt
		}{current.Capabilities, capabilityReceipt}),
		Receipts: []QualificationReceipt{
			qualificationReceipt("splunk.server_info", identityReceipt),
			qualificationReceipt("splunk.current_context", capabilityReceipt),
		}}
	value.Digest = qualificationDigest(value)
	return validateQualificationDocument(ctx, value)
}

func DecodeValidatedQualification(ctx context.Context, input []byte) (ValidatedQualification, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedQualification{}, err
	}
	value, err := DecodeQualification(input)
	if err != nil {
		return ValidatedQualification{}, err
	}
	if value.Digest != qualificationDigest(value) {
		return ValidatedQualification{}, deniedCall("splunk_qualification_digest_invalid")
	}
	return validateQualificationDocument(ctx, value)
}

func validateQualificationDocument(ctx context.Context, value Qualification) (ValidatedQualification, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedQualification{}, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ValidatedQualification{}, deniedCall("splunk_qualification_encoding_invalid")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return ValidatedQualification{}, deniedCall("splunk_qualification_encoding_invalid")
	}
	decoded, err := DecodeQualification(canonical)
	if err != nil || decoded.Digest != qualificationDigest(decoded) {
		return ValidatedQualification{}, deniedCall("splunk_qualification_digest_invalid")
	}
	return ValidatedQualification{value: decoded, bytes: canonical, digest: decoded.Digest}, nil
}

func validateServerIdentity(config Config, identity ServerIdentity) error {
	if identity.GUID != config.ExpectedServerGUID || identity.ProductType != config.ExpectedProductType ||
		!slices.Equal(identity.ServerRoles, config.ExpectedServerRoles) {
		return conflictCall("splunk_server_identity_mismatch")
	}
	parts := strings.Split(identity.Version, ".")
	if len(parts) != 3 || !versionPattern.MatchString(identity.Version) ||
		!slices.Contains(config.QualifiedMinorVersions, parts[0]+"."+parts[1]) {
		return queryconnector.NewError(queryconnector.Unsupported, "splunk_version_unqualified", nil)
	}
	return nil
}

func validateCurrentCapabilities(config Config, capabilities []string) error {
	if !validNames(capabilities, 1, 256) {
		return deniedCall("splunk_capabilities_invalid")
	}
	for _, required := range config.RequiredCapabilities {
		if !slices.Contains(capabilities, required) {
			return deniedCall("splunk_required_capability_missing")
		}
	}
	if intersects(capabilities, config.DeniedCapabilities) {
		return deniedCall("splunk_dangerous_capability_present")
	}
	return nil
}

func validateQualificationReceipt(config Config, receipt CallReceipt) error {
	if !validDigests(receipt.RequestDigest, receipt.ResponseDigest, receipt.LeaseDecisionDigest) ||
		receipt.TransportDigest != config.TransportIdentityDigest {
		return deniedCall("splunk_qualification_receipt_invalid")
	}
	return nil
}

func qualificationReceipt(operation string, receipt CallReceipt) QualificationReceipt {
	return QualificationReceipt{Operation: operation, RequestDigest: receipt.RequestDigest,
		ResponseDigest: receipt.ResponseDigest, LeaseDecisionDigest: receipt.LeaseDecisionDigest,
		TransportDigest: receipt.TransportDigest}
}

func qualificationDigest(value Qualification) string {
	value.Digest = ""
	return hashValue("COH-SPLUNK-QUALIFICATION-V1\x00", value)
}

func cloneQualification(value Qualification) Qualification {
	value.ServerRoles = append([]string(nil), value.ServerRoles...)
	value.Capabilities = append([]string(nil), value.Capabilities...)
	value.Receipts = append([]QualificationReceipt(nil), value.Receipts...)
	return value
}
