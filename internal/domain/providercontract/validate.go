package providercontract

import (
	"encoding/json"
	"reflect"
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
	tokenPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+:-]{0,127}$`)
	reasonPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[0-9]+([.][0-9]+){1,3}([+-][A-Za-z0-9.-]+)?$`)
)

func ValidateCapability(value CapabilitySnapshot) error {
	if value.SchemaVersion != CapabilitySchemaVersion || value.ContractVersion != ContractVersion {
		return NewError(Unsupported, "unsupported_contract")
	}
	observed, observedErr := parseTimestamp(value.ObservedAt)
	validUntil, untilErr := parseTimestamp(value.ValidUntil)
	if !uuidPattern.MatchString(value.SnapshotID) || observedErr != nil || untilErr != nil ||
		!validUntil.After(observed) || validUntil.Sub(observed) > 24*time.Hour {
		return NewError(InvalidInput, "capability_identity")
	}
	if err := validateProvider(value.Provider); err != nil {
		return err
	}
	if !validSet(value.Features.MessageRoles, []string{"assistant", "developer", "system", "tool", "user"}, 2) ||
		!contains(value.Features.MessageRoles, "assistant") || !contains(value.Features.MessageRoles, "user") ||
		!validSet(value.Features.ContentKinds, []string{"input_json", "output_json", "reasoning_ref", "text", "tool_call", "tool_result"}, 1) ||
		!contains(value.Features.ContentKinds, "text") ||
		!validSet(value.Features.StateModes, []string{"client_managed", "provider_managed", "stateless"}, 1) ||
		!contains(value.Features.StateModes, value.Provider.StateMode) {
		return NewError(InvalidInput, "capability_features")
	}
	limits := value.Limits
	if limits.MaximumInputTokens == 0 || limits.MaximumInputTokens > 16777216 ||
		limits.MaximumOutputTokens == 0 || limits.MaximumOutputTokens > 1048576 ||
		limits.MaximumMessages == 0 || limits.MaximumMessages > 16384 || limits.MaximumTools > 1024 ||
		limits.MaximumParallelToolCalls > 256 || limits.MaximumStreamSeconds == 0 || limits.MaximumStreamSeconds > 86400 ||
		value.Provider.ContextLimit < limits.MaximumInputTokens+limits.MaximumOutputTokens ||
		value.Features.ToolCalls != (limits.MaximumTools > 0 && limits.MaximumParallelToolCalls > 0) {
		return NewError(Denied, "capability_limits")
	}
	return nil
}

func ValidateQualification(value QualificationRecord) error {
	if value.SchemaVersion != QualificationSchemaVersion || value.ContractVersion != ContractVersion {
		return NewError(Unsupported, "unsupported_contract")
	}
	issued, issuedErr := parseTimestamp(value.IssuedAt)
	expires, expiresErr := parseTimestamp(value.ExpiresAt)
	if !uuidPattern.MatchString(value.QualificationID) || issuedErr != nil || expiresErr != nil ||
		!expires.After(issued) || expires.Sub(issued) > 31*24*time.Hour {
		return NewError(InvalidInput, "qualification_identity")
	}
	if err := validateProvider(value.Provider); err != nil {
		return err
	}
	if !digestPattern.MatchString(value.CapabilityDigest) || !digestPattern.MatchString(value.SuiteDigest) ||
		!digestPattern.MatchString(value.QualifierIdentityDigest) || !validReleaseMatrix(value.ReleaseMatrix) {
		return NewError(InvalidInput, "qualification_binding")
	}
	wantKinds := []string{"cancellation", "capability", "identity_provenance", "policy_route", "structured_output", "tool_call"}
	if len(value.Cases) != len(wantKinds) {
		return NewError(Unsupported, "qualification_cases")
	}
	failed := false
	for index, testCase := range value.Cases {
		if testCase.Kind != wantKinds[index] || !digestPattern.MatchString(testCase.FixtureDigest) ||
			!digestPattern.MatchString(testCase.TraceDigest) || testCase.DurationMilliseconds > 3600000 ||
			testCase.Outcome != "passed" && testCase.Outcome != "failed" {
			return NewError(InvalidInput, "qualification_cases")
		}
		failed = failed || testCase.Outcome == "failed"
	}
	if value.AggregateOutcome != "passed" && value.AggregateOutcome != "failed" ||
		value.AggregateOutcome == "passed" && failed || value.AggregateOutcome == "failed" && !failed {
		return NewError(Denied, "qualification_outcome")
	}
	return nil
}

// AdmitQualification accepts only a current passing record for the exact
// immutable capability and provider tuple. Runtime policy may still narrow it.
func AdmitQualification(capability ValidatedCapability, qualification ValidatedQualification, now time.Time) error {
	capabilityValue := capability.Value()
	qualificationValue := qualification.Value()
	if capability.Digest() == "" || qualification.Digest() == "" || now.IsZero() {
		return NewError(InvalidInput, "qualification_admission")
	}
	observed, _ := parseTimestamp(capabilityValue.ObservedAt)
	capabilityUntil, _ := parseTimestamp(capabilityValue.ValidUntil)
	issued, _ := parseTimestamp(qualificationValue.IssuedAt)
	expires, _ := parseTimestamp(qualificationValue.ExpiresAt)
	if now.Before(observed) || !now.Before(capabilityUntil) || now.Before(issued) || !now.Before(expires) {
		return NewError(Unsupported, "qualification_expired")
	}
	if qualificationValue.AggregateOutcome != "passed" || qualificationValue.CapabilityDigest != capability.Digest() {
		return NewError(Unsupported, "qualification_not_passed")
	}
	if !reflect.DeepEqual(capabilityValue.Provider, qualificationValue.Provider) {
		return NewError(Unsupported, "provider_identity_drift")
	}
	features := capabilityValue.Features
	if !features.ToolCalls || !features.StructuredOutput || !features.Streaming || !features.Cancellation || !features.Usage {
		return NewError(Unsupported, "capability_unqualified")
	}
	return nil
}

func validateProvider(value ProviderIdentity) error {
	if !oneOf(value.ProviderKind, "ollama", "llama_cpp", "vllm", "openai_responses", "codex_runtime") ||
		!versionPattern.MatchString(value.AdapterVersion) || !digestPattern.MatchString(value.EndpointIdentityDigest) ||
		!oneOf(value.DataRoute, "local", "approved_external", "air_gapped") || !boundedText(value.RequestedModel, 256) ||
		!boundedText(value.ActualModel, 256) || !digestPattern.MatchString(value.ModelRevision) ||
		!tokenPattern.MatchString(value.RuntimeName) || !versionPattern.MatchString(value.RuntimeVersion) ||
		!digestPattern.MatchString(value.RuntimeDigest) || !tokenPattern.MatchString(value.TokenizerName) ||
		!versionPattern.MatchString(value.TokenizerVersion) || !digestPattern.MatchString(value.TokenizerDigest) ||
		!digestPattern.MatchString(value.ChatTemplateDigest) || !digestPattern.MatchString(value.ToolParserDigest) ||
		!digestPattern.MatchString(value.ReasoningParserDigest) || value.ContextLimit == 0 || value.ContextLimit > 16777216 ||
		!digestPattern.MatchString(value.SamplingProfileDigest) || !digestPattern.MatchString(value.HardwareProfileDigest) ||
		!oneOf(value.StateMode, "stateless", "client_managed", "provider_managed") || value.PolicyRevision == 0 {
		return NewError(InvalidInput, "provider_identity")
	}
	return nil
}

func validReleaseMatrix(value ReleaseMatrix) bool {
	return boundedText(value.Profile, 128) && oneOf(value.OS, "darwin", "linux") &&
		oneOf(value.Architecture, "arm64", "amd64") && oneOf(value.DeploymentMode, "native", "compose", "dedicated") &&
		oneOf(value.NetworkMode, "connected", "restricted_connected", "air_gapped")
}

func validJSONObject(input json.RawMessage) bool {
	if len(input) == 0 {
		return false
	}
	var value map[string]any
	return json.Unmarshal(input, &value) == nil && value != nil
}

func validSet(values, allowed []string, minimum int) bool {
	if len(values) < minimum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !contains(allowed, value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool { return slices.Contains(values, wanted) }

func boundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value
}

func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }

func parseTimestamp(value string) (time.Time, error) { return time.Parse(timestampLayout, value) }
