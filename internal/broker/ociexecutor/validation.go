package ociexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

var (
	tokenPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern    = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	envPattern        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$`)
)

var allowedEnvironment = map[string]bool{"LANG": true, "LC_ALL": true, "TZ": true}

func validateRegistration(value Registration) error {
	if !tokenPattern.MatchString(value.Tool.Name) || !versionPattern.MatchString(value.Tool.Version) ||
		!digestPattern.MatchString(value.Tool.ArtifactDigest) || !tokenPattern.MatchString(value.Operation) ||
		!repositoryPattern.MatchString(value.ImageRepository) || value.ImageDigest != value.Tool.ArtifactDigest ||
		!validContainerPath(value.Entrypoint) || value.RunAsUser == 0 || value.RunAsGroup == 0 {
		return NewError(InvalidInput, "registration_identity")
	}
	if shellEntrypoint(value.Entrypoint) {
		return NewError(InvalidInput, "registration_entrypoint")
	}
	if err := validateArguments(value.FixedArguments, false); err != nil {
		return err
	}
	if err := validateArguments(value.HealthArguments, true); err != nil {
		return err
	}
	seenEnvironment := make(map[string]struct{}, len(value.FixedEnvironment))
	for _, entry := range value.FixedEnvironment {
		if !allowedEnvironment[entry.Name] || !envPattern.MatchString(entry.Name) ||
			len(entry.Value) > MaximumArgumentBytes || strings.IndexByte(entry.Value, 0) >= 0 ||
			!utf8.ValidString(entry.Value) || sensitiveEnvironment(entry.Name) {
			return NewError(InvalidInput, "registration_environment")
		}
		if _, exists := seenEnvironment[entry.Name]; exists {
			return NewError(InvalidInput, "registration_environment")
		}
		seenEnvironment[entry.Name] = struct{}{}
	}
	if err := validateMounts(value.WritableMounts); err != nil {
		return err
	}
	return nil
}

func validateArguments(values []string, required bool) error {
	if len(values) > MaximumArguments || required && len(values) == 0 {
		return NewError(InvalidInput, "registration_arguments")
	}
	for _, argument := range values {
		if argument == "" || len(argument) > MaximumArgumentBytes || strings.IndexByte(argument, 0) >= 0 || !utf8.ValidString(argument) {
			return NewError(InvalidInput, "registration_arguments")
		}
	}
	return nil
}

func validateMounts(values []WritableMount) error {
	if len(values) == 0 || len(values) > MaximumMounts {
		return NewError(InvalidInput, "registration_mounts")
	}
	cloned := slices.Clone(values)
	slices.SortFunc(cloned, func(left, right WritableMount) int { return strings.Compare(left.Destination, right.Destination) })
	hasWork := false
	for index, mount := range cloned {
		if mount.Bytes == 0 || !validWritablePath(mount.Destination) {
			return NewError(InvalidInput, "registration_mounts")
		}
		if mount.Destination == "/work" {
			hasWork = true
		}
		if index > 0 && (mount.Destination == cloned[index-1].Destination ||
			strings.HasPrefix(mount.Destination, cloned[index-1].Destination+"/")) {
			return NewError(InvalidInput, "registration_mounts")
		}
	}
	if !hasWork {
		return NewError(InvalidInput, "registration_mounts")
	}
	return nil
}

func validWritablePath(value string) bool {
	return validContainerPath(value) && (value == "/work" || strings.HasPrefix(value, "/work/") ||
		value == "/tmp" || strings.HasPrefix(value, "/tmp/"))
}

func validContainerPath(value string) bool {
	return len(value) > 1 && len(value) <= MaximumArgumentBytes && strings.HasPrefix(value, "/") &&
		path.Clean(value) == value && strings.IndexByte(value, 0) < 0 && utf8.ValidString(value)
}

func sensitiveEnvironment(name string) bool {
	for _, fragment := range []string{"SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE", "API_KEY", "ACCESS_KEY"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

func shellEntrypoint(value string) bool {
	switch path.Base(value) {
	case "sh", "bash", "dash", "zsh", "csh", "ksh", "pwsh", "powershell", "cmd", "cmd.exe":
		return true
	default:
		return false
	}
}

func validHealthOutcome(value string) bool {
	return value == "" || value == "healthy" || value == "unhealthy" || value == "canceled"
}

func validateRequest(ctx context.Context, value Request) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !uuidPattern.MatchString(value.AttemptID) || !tokenPattern.MatchString(value.Tool.Name) ||
		!uuidPattern.MatchString(value.OrganizationID) || !uuidPattern.MatchString(value.TenantID) ||
		!uuidPattern.MatchString(value.CaseID) || !uuidPattern.MatchString(value.ActorID) ||
		!versionPattern.MatchString(value.Tool.Version) || !digestPattern.MatchString(value.Tool.ArtifactDigest) ||
		!tokenPattern.MatchString(value.Operation) || !ociTier(value.RequiredTier) || len(value.Inputs) > 128 {
		return NewError(InvalidInput, "execution_request")
	}
	return nil
}

func validateCapability(request Request, runtimeCeiling string, capability toolregistry.Capability) error {
	operation := capability.Operation
	if capability.Tool != request.Tool || capability.RequiredTier != request.RequiredTier ||
		capability.RuntimeCeiling != runtimeCeiling || !digestPattern.MatchString(capability.ManifestDigest) ||
		!uuidPattern.MatchString(capability.ManifestID) || operation.Name != request.Operation ||
		operation.IsolationClass != "oci_sandbox" || !ociTier(capability.RequiredTier) ||
		!ociTier(capability.EffectiveCeiling) || !validLimits(operation.ResourceLimits) ||
		!validNetworkPolicy(operation.NetworkPolicy) || len(operation.CredentialClasses) != 1 ||
		operation.CredentialClasses[0] != "none" {
		return NewError(Denied, "oci_capability_binding")
	}
	return nil
}

func validLimits(value toolregistry.ResourceLimits) bool {
	return value.WallTimeMilliseconds > 0 && value.CPUMilliseconds > 0 && value.MemoryBytes >= 16<<20 &&
		value.OutputBytes > 0 && value.EphemeralStorageBytes > 0 && value.ProcessCount > 0 && value.OpenFileCount > 2
}

func validNetworkPolicy(value toolregistry.NetworkPolicy) bool {
	if value.PublicInternetAllowed || value.MetadataAllowed || !slices.IsSorted(value.Protocols) {
		return false
	}
	for index, protocol := range value.Protocols {
		if protocol != "tcp" && protocol != "udp" || index > 0 && value.Protocols[index-1] == protocol {
			return false
		}
	}
	switch value.Mode {
	case "none":
		return len(value.Protocols) == 0 && value.DNSMode == "none" && value.MaximumConnections == 0
	case "target_only", "target_and_control":
		return len(value.Protocols) > 0 && (value.DNSMode == "none" || value.DNSMode == "broker_resolved") &&
			value.MaximumConnections > 0
	default:
		return false
	}
}

func validateMountBudget(mounts []WritableMount, limit uint64) error {
	var total uint64
	for _, mount := range mounts {
		if mount.Bytes > limit-total {
			return NewError(Denied, "mount_storage_limit")
		}
		total += mount.Bytes
	}
	return nil
}

func validateDispatchAuthority(authority DispatchAuthority, expected AuthorizationRequest, now time.Time) error {
	authorizedAt, authorizedErr := time.Parse(time.RFC3339Nano, authority.AuthorizedAt)
	validUntil, validErr := time.Parse(time.RFC3339Nano, authority.ValidUntil)
	if authority.Request != expected || !uuidPattern.MatchString(authority.AuthorizationID) ||
		!digestPattern.MatchString(authority.DecisionDigest) || !ociTier(authority.RuntimeCeiling) ||
		authorizedErr != nil || validErr != nil || authority.AuthorizedAt != formatTime(authorizedAt) ||
		authority.ValidUntil != formatTime(validUntil) || authorizedAt.After(now) || !now.Before(validUntil) ||
		!validUntil.After(authorizedAt) || validUntil.Sub(authorizedAt) > 5*time.Minute {
		return NewError(Denied, "dispatch_authority")
	}
	return nil
}

func validateNetworkLease(lease NetworkLease, expected NetworkRequest, authority DispatchAuthority, now time.Time) error {
	authorizedAt, authorizedErr := time.Parse(time.RFC3339Nano, lease.AuthorizedAt)
	validUntil, validErr := time.Parse(time.RFC3339Nano, lease.ValidUntil)
	authorityAt, authorityAtErr := time.Parse(time.RFC3339Nano, authority.AuthorizedAt)
	authorityUntil, authorityErr := time.Parse(time.RFC3339Nano, authority.ValidUntil)
	validEngineNetwork := tokenPattern.MatchString(lease.EngineNetwork)
	if expected.Policy.Mode == "none" {
		validEngineNetwork = lease.EngineNetwork == "none"
	}
	if !reflect.DeepEqual(lease.Request, expected) || !uuidPattern.MatchString(lease.LeaseID) ||
		!digestPattern.MatchString(lease.EnforcementDigest) || !validEngineNetwork || lease.Cleanup == nil ||
		authorizedErr != nil || validErr != nil || authorityAtErr != nil || authorityErr != nil ||
		lease.AuthorizedAt != formatTime(authorizedAt) || authorizedAt.Before(authorityAt) ||
		lease.ValidUntil != formatTime(validUntil) || authorizedAt.After(now) || !now.Before(validUntil) ||
		!validUntil.After(authorizedAt) || validUntil.After(authorityUntil) || validUntil.Sub(authorizedAt) > 5*time.Minute {
		return NewError(Denied, "network_lease")
	}
	return nil
}

func encodeInputs(fields []toolregistry.InputField, values map[string]InputValue) ([]byte, error) {
	if len(values) > len(fields) {
		return nil, NewError(InvalidInput, "operation_inputs")
	}
	encoded := make(map[string]any, len(values))
	for _, field := range fields {
		value, present := values[field.Name]
		if !present {
			if field.Required {
				return nil, NewError(InvalidInput, "operation_inputs")
			}
			continue
		}
		converted, err := validateInput(field, value)
		if err != nil {
			return nil, err
		}
		encoded[field.Name] = converted
	}
	for name := range values {
		if _, found := encoded[name]; !found {
			return nil, NewError(InvalidInput, "operation_inputs")
		}
	}
	data, err := json.Marshal(encoded)
	if err != nil || len(data) > MaximumInputBytes {
		return nil, NewError(InvalidInput, "operation_inputs")
	}
	return data, nil
}

func validateInput(field toolregistry.InputField, value InputValue) (any, error) {
	if value.Kind != field.Type {
		return nil, NewError(InvalidInput, "operation_input_type")
	}
	switch field.Type {
	case "boolean":
		return value.Boolean, nil
	case "integer", "duration_ms":
		if field.Minimum == nil || field.Maximum == nil || value.Integer < *field.Minimum || value.Integer > *field.Maximum {
			return nil, NewError(InvalidInput, "operation_input_bounds")
		}
		return value.Integer, nil
	case "string", "uuid", "digest", "timestamp":
		if !validStringInput(field, value.String) {
			return nil, NewError(InvalidInput, "operation_input_bounds")
		}
		return value.String, nil
	case "string_list", "digest_list":
		if len(value.Strings) == 0 || len(value.Strings) > int(field.MaximumItems) || !slices.IsSorted(value.Strings) {
			return nil, NewError(InvalidInput, "operation_input_bounds")
		}
		for index, item := range value.Strings {
			if index > 0 && value.Strings[index-1] == item || len(item) > int(field.MaximumBytes) ||
				!utf8.ValidString(item) || field.Type == "digest_list" && !digestPattern.MatchString(item) {
				return nil, NewError(InvalidInput, "operation_input_bounds")
			}
		}
		return slices.Clone(value.Strings), nil
	default:
		return nil, NewError(InvalidInput, "operation_input_type")
	}
}

func validStringInput(field toolregistry.InputField, value string) bool {
	if value == "" || !utf8.ValidString(value) || len(value) > int(field.MaximumBytes) {
		return false
	}
	if len(field.Enum) > 0 && !slices.Contains(field.Enum, value) {
		return false
	}
	switch field.Type {
	case "uuid":
		return uuidPattern.MatchString(value)
	case "digest":
		return digestPattern.MatchString(value)
	case "timestamp":
		parsed, err := time.Parse(time.RFC3339Nano, value)
		return err == nil && parsed.Format(time.RFC3339Nano) == value && strings.HasSuffix(value, "Z")
	default:
		return true
	}
}

func cleanEnvironment(values []EnvironmentVariable) []string {
	cloned := slices.Clone(values)
	slices.SortFunc(cloned, func(left, right EnvironmentVariable) int { return strings.Compare(left.Name, right.Name) })
	result := make([]string, len(cloned))
	for index, value := range cloned {
		result[index] = value.Name + "=" + value.Value
	}
	return result
}

func canonicalBytes(value any) []byte {
	data, _ := json.Marshal(value)
	return bytes.Clone(data)
}

func inputRequestDigest(values map[string]InputValue) (string, error) {
	data, err := json.Marshal(values)
	if err != nil || len(data) > MaximumInputBytes {
		return "", NewError(InvalidInput, "operation_inputs")
	}
	return digestBytes(data), nil
}

func ociTier(value string) bool {
	return value == "T0" || value == "T1" || value == "T2" || value == "T3"
}
