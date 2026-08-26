package nativeexecutor

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

var (
	tokenPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	envPattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

var allowedEnvironment = map[string]bool{"LANG": true, "LC_ALL": true, "TZ": true}

func validateRegistration(value Registration) error {
	if !tokenPattern.MatchString(value.Tool.Name) || !versionPattern.MatchString(value.Tool.Version) ||
		!digestPattern.MatchString(value.Tool.ArtifactDigest) || !tokenPattern.MatchString(value.Operation) {
		return NewError(InvalidInput, "registration_identity")
	}
	if !filepath.IsAbs(value.ExecutablePath) || filepath.Clean(value.ExecutablePath) != value.ExecutablePath {
		return NewError(InvalidInput, "registration_executable")
	}
	if len(value.FixedArguments) > MaximumArguments {
		return NewError(InvalidInput, "registration_arguments")
	}
	for _, argument := range value.FixedArguments {
		if argument == "" || len(argument) > MaximumArgumentBytes || strings.IndexByte(argument, 0) >= 0 || !utf8.ValidString(argument) {
			return NewError(InvalidInput, "registration_arguments")
		}
	}
	seen := make(map[string]struct{}, len(value.FixedEnvironment))
	for _, entry := range value.FixedEnvironment {
		if !allowedEnvironment[entry.Name] || !envPattern.MatchString(entry.Name) || len(entry.Value) > MaximumArgumentBytes ||
			strings.IndexByte(entry.Value, 0) >= 0 || !utf8.ValidString(entry.Value) || sensitiveEnvironment(entry.Name) {
			return NewError(InvalidInput, "registration_environment")
		}
		if _, exists := seen[entry.Name]; exists {
			return NewError(InvalidInput, "registration_environment")
		}
		seen[entry.Name] = struct{}{}
	}
	return nil
}

func sensitiveEnvironment(name string) bool {
	for _, fragment := range []string{"SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE", "API_KEY", "ACCESS_KEY"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
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

func validateCapability(request Request, runtimeCeiling string, capability toolregistry.Capability) error {
	operation := capability.Operation
	if capability.Tool != request.Tool || capability.RequiredTier != request.RequiredTier ||
		capability.RuntimeCeiling != runtimeCeiling || !digestPattern.MatchString(capability.ManifestDigest) ||
		!uuidPattern.MatchString(capability.ManifestID) || operation.Name != request.Operation ||
		operation.IsolationClass != "native_restricted" || !lowRiskTier(capability.RequiredTier) ||
		!lowRiskTier(capability.EffectiveCeiling) || !validLimits(operation.ResourceLimits) ||
		operation.NetworkPolicy.Mode != "none" || operation.NetworkPolicy.DNSMode != "none" ||
		len(operation.NetworkPolicy.Protocols) != 0 || operation.NetworkPolicy.MaximumConnections != 0 ||
		operation.NetworkPolicy.PublicInternetAllowed || operation.NetworkPolicy.MetadataAllowed {
		return NewError(Denied, "native_capability_binding")
	}
	return nil
}

func validLimits(value toolregistry.ResourceLimits) bool {
	return value.WallTimeMilliseconds > 0 && value.CPUMilliseconds > 0 && value.MemoryBytes > 0 &&
		value.OutputBytes > 0 && value.EphemeralStorageBytes > 0 && value.ProcessCount > 0 && value.OpenFileCount > 2
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

func canonicalStrings(values []string) []byte {
	data, _ := json.Marshal(values)
	return bytes.Clone(data)
}

func inputRequestDigest(values map[string]InputValue) (string, error) {
	data, err := json.Marshal(values)
	if err != nil || len(data) > MaximumInputBytes {
		return "", NewError(InvalidInput, "operation_inputs")
	}
	return digestBytes(data), nil
}

func validateDispatchAuthority(authority DispatchAuthority, expected AuthorizationRequest, now time.Time) error {
	authorizedAt, authorizedErr := time.Parse(time.RFC3339Nano, authority.AuthorizedAt)
	validUntil, validErr := time.Parse(time.RFC3339Nano, authority.ValidUntil)
	if authority.Request != expected || !uuidPattern.MatchString(authority.AuthorizationID) ||
		!digestPattern.MatchString(authority.DecisionDigest) || !lowRiskTier(authority.RuntimeCeiling) ||
		authorizedErr != nil || validErr != nil || authority.AuthorizedAt != formatTime(authorizedAt) ||
		authority.ValidUntil != formatTime(validUntil) || authorizedAt.After(now) || !now.Before(validUntil) ||
		!validUntil.After(authorizedAt) || validUntil.Sub(authorizedAt) > 5*time.Minute {
		return NewError(Denied, "dispatch_authority")
	}
	return nil
}
