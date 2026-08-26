package toolregistry

import (
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[1-9][0-9]{0,8}([.][0-9]{1,9}){0,2}$`)
)

func Validate(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchemaVersion || manifest.ContractVersion != ContractVersion {
		return NewError(Denied, "unsupported_contract")
	}
	if !uuidPattern.MatchString(manifest.ManifestID) || !uuidPattern.MatchString(manifest.PublisherID) ||
		!uuidPattern.MatchString(manifest.ReviewID) || !tokenPattern.MatchString(manifest.ToolName) ||
		!versionPattern.MatchString(manifest.ToolVersion) || !digestPattern.MatchString(manifest.ArtifactDigest) ||
		!digestPattern.MatchString(manifest.ThreatModelDigest) || manifest.ReviewRevision == 0 {
		return NewError(InvalidInput, "manifest_identity")
	}
	if manifest.ReviewDecision != "approved" || !validTier(manifest.MaximumActionTier) {
		return NewError(Denied, "manifest_review")
	}
	if !validUUIDSet(manifest.ReviewerActorIDs, 1, 16) {
		return NewError(InvalidInput, "manifest_reviewers")
	}
	reviewedAt, reviewErr := time.Parse(timestampLayout, manifest.ReviewedAt)
	validFrom, fromErr := time.Parse(timestampLayout, manifest.ValidFrom)
	validUntil, untilErr := time.Parse(timestampLayout, manifest.ValidUntil)
	if reviewErr != nil || fromErr != nil || untilErr != nil || reviewedAt.After(validFrom) ||
		!validUntil.After(validFrom) || validUntil.Sub(validFrom) > MaximumValidity {
		return NewError(InvalidInput, "manifest_validity")
	}
	if len(manifest.Operations) == 0 || len(manifest.Operations) > 128 {
		return NewError(InvalidInput, "manifest_operations")
	}
	for index, operation := range manifest.Operations {
		if index > 0 && manifest.Operations[index-1].Name >= operation.Name {
			return NewError(InvalidInput, "manifest_operations")
		}
		if err := validateOperation(operation, manifest.MaximumActionTier); err != nil {
			return err
		}
	}
	return nil
}

func validateOperation(operation Operation, manifestCeiling string) error {
	if !tokenPattern.MatchString(operation.Name) || operation.InputSchemaVersion != "coh.tool-input/v1" ||
		!validTier(operation.BaselineActionTier) || !validTier(operation.MaximumActionTier) ||
		tierValue(operation.BaselineActionTier) > tierValue(operation.MaximumActionTier) ||
		tierValue(operation.MaximumActionTier) > tierValue(manifestCeiling) {
		return NewError(InvalidInput, "operation_tier")
	}
	if !validIsolation(operation.IsolationClass, operation.MaximumActionTier) ||
		!validTokenSet(operation.CredentialClasses, 1, 16) || !validCancellation(operation.CancellationMode, operation.MaximumActionTier) ||
		!validRetry(operation.RetryMode, operation.MaximumActionTier) {
		return NewError(Denied, "operation_controls")
	}
	if len(operation.InputFields) > 128 {
		return NewError(InvalidInput, "operation_inputs")
	}
	for index, field := range operation.InputFields {
		if index > 0 && operation.InputFields[index-1].Name >= field.Name || validateInputField(field) != nil {
			return NewError(InvalidInput, "operation_inputs")
		}
	}
	if !validResources(operation.ResourceLimits) || !validNetwork(operation.NetworkPolicy) ||
		operation.MaximumActionTier == "T4" && operation.NetworkPolicy.Mode == "none" {
		return NewError(Denied, "operation_sandbox")
	}
	return nil
}

func validateInputField(field InputField) error {
	if !tokenPattern.MatchString(field.Name) || field.Enum == nil || len(field.Enum) > 64 || !slices.IsSorted(field.Enum) || duplicate(field.Enum) {
		return NewError(InvalidInput, "input_field")
	}
	for _, value := range field.Enum {
		if !utf8.ValidString(value) || len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value {
			return NewError(InvalidInput, "input_field")
		}
	}
	switch field.Type {
	case "boolean":
		if field.Minimum != nil || field.Maximum != nil || field.MaximumBytes != 0 || field.MaximumItems != 0 || len(field.Enum) != 0 {
			return NewError(InvalidInput, "input_field")
		}
	case "integer", "duration_ms":
		if field.Minimum == nil || field.Maximum == nil || *field.Minimum > *field.Maximum || field.MaximumBytes != 0 ||
			field.MaximumItems != 0 || len(field.Enum) != 0 || field.Type == "duration_ms" && *field.Minimum < 1 {
			return NewError(InvalidInput, "input_field")
		}
	case "string", "uuid", "digest", "timestamp":
		if field.Minimum != nil || field.Maximum != nil || field.MaximumBytes == 0 || field.MaximumBytes > 65536 || field.MaximumItems != 0 {
			return NewError(InvalidInput, "input_field")
		}
	case "string_list", "digest_list":
		if field.Minimum != nil || field.Maximum != nil || field.MaximumBytes == 0 || field.MaximumBytes > 65536 ||
			field.MaximumItems == 0 || field.MaximumItems > 256 {
			return NewError(InvalidInput, "input_field")
		}
	default:
		return NewError(InvalidInput, "input_field")
	}
	for _, value := range field.Enum {
		if uint32(len(value)) > field.MaximumBytes || field.Type == "uuid" && !uuidPattern.MatchString(value) ||
			field.Type == "digest" && !digestPattern.MatchString(value) {
			return NewError(InvalidInput, "input_field")
		}
		if field.Type == "timestamp" {
			if _, err := time.Parse(timestampLayout, value); err != nil {
				return NewError(InvalidInput, "input_field")
			}
		}
	}
	return nil
}

func validResources(value ResourceLimits) bool {
	return value.WallTimeMilliseconds > 0 && value.WallTimeMilliseconds <= 86_400_000 &&
		value.CPUMilliseconds > 0 && value.CPUMilliseconds <= 86_400_000 &&
		value.MemoryBytes >= 16<<20 && value.MemoryBytes <= 64<<30 && value.OutputBytes > 0 && value.OutputBytes <= 1<<30 &&
		value.EphemeralStorageBytes > 0 && value.EphemeralStorageBytes <= 256<<30 &&
		value.ProcessCount > 0 && value.ProcessCount <= 1024 && value.OpenFileCount > 0 && value.OpenFileCount <= 65536
}

func validNetwork(value NetworkPolicy) bool {
	if value.PublicInternetAllowed || value.MetadataAllowed || !validProtocolSet(value.Protocols) {
		return false
	}
	switch value.Mode {
	case "none":
		return len(value.Protocols) == 0 && value.DNSMode == "none" && value.MaximumConnections == 0
	case "target_only", "target_and_control":
		return len(value.Protocols) > 0 && (value.DNSMode == "none" || value.DNSMode == "broker_resolved") &&
			value.MaximumConnections > 0 && value.MaximumConnections <= 65535
	default:
		return false
	}
}

func validIsolation(value, ceiling string) bool {
	switch value {
	case "native_restricted":
		return tierValue(ceiling) <= tierValue("T2")
	case "oci_sandbox":
		return tierValue(ceiling) <= tierValue("T3")
	case "remote_isolated":
		return tierValue(ceiling) <= tierValue("T3")
	case "t4_dedicated":
		return true
	default:
		return false
	}
}

func validRetry(value, ceiling string) bool {
	if ceiling == "T4" {
		return value == "never"
	}
	return value == "safe" || value == "reconcile" || value == "never"
}

func validCancellation(value, ceiling string) bool {
	if ceiling == "T4" {
		return value == "cooperative"
	}
	if tierValue(ceiling) >= tierValue("T2") {
		return value == "cooperative" || value == "broker_only"
	}
	return value == "cooperative" || value == "broker_only" || value == "unsupported"
}

func validTier(value string) bool { return tierValue(value) >= 0 }

func tierValue(value string) int {
	switch value {
	case "T0":
		return 0
	case "T1":
		return 1
	case "T2":
		return 2
	case "T3":
		return 3
	case "T4":
		return 4
	default:
		return -1
	}
}

func validUUIDSet(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) || duplicate(values) {
		return false
	}
	for _, value := range values {
		if !uuidPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validTokenSet(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) || duplicate(values) {
		return false
	}
	for _, value := range values {
		if !tokenPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validProtocolSet(values []string) bool {
	if !slices.IsSorted(values) || duplicate(values) {
		return false
	}
	for _, value := range values {
		if value != "tcp" && value != "udp" {
			return false
		}
	}
	return true
}

func duplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}
