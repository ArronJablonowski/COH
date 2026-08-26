package providercontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const toolResultDigestDomain = "COH-PROVIDER-TOOL-RESULT-V1\x00"

func ValidateRequest(value InferenceRequest) error {
	if value.SchemaVersion != RequestSchemaVersion || value.ContractVersion != ContractVersion {
		return NewError(Unsupported, "unsupported_contract")
	}
	for _, identifier := range []string{value.RequestID, value.AttemptID, value.OrganizationID, value.TenantID,
		value.CaseID, value.TaskID, value.ActorID, value.QualificationID} {
		if !uuidPattern.MatchString(identifier) {
			return NewError(InvalidInput, "request_identity")
		}
	}
	if err := validateProvider(value.Provider); err != nil {
		return err
	}
	if !digestPattern.MatchString(value.CapabilityDigest) || len(value.Messages) == 0 || len(value.Messages) > 16384 ||
		len(value.Tools) > 1024 || value.MaximumOutputTokens == 0 || value.MaximumOutputTokens > 1048576 {
		return NewError(InvalidInput, "request_bounds")
	}
	for _, message := range value.Messages {
		if err := validateMessage(message); err != nil {
			return err
		}
	}
	for index, tool := range value.Tools {
		if index > 0 && value.Tools[index-1].Name >= tool.Name || !tokenPattern.MatchString(tool.Name) ||
			!boundedText(tool.Description, 4096) || !digestPattern.MatchString(tool.InputSchemaDigest) ||
			!digestPattern.MatchString(tool.OutputSchemaDigest) {
			return NewError(InvalidInput, "request_tools")
		}
	}
	if err := validateOutputConstraint(value.OutputConstraint); err != nil {
		return err
	}
	if value.Sampling.TemperatureMilli > 2000 || value.Sampling.TopPMillionths == 0 ||
		value.Sampling.TopPMillionths > 1000000 || value.Sampling.Seed > 2147483647 {
		return NewError(InvalidInput, "request_sampling")
	}
	if err := validateState(value.State); err != nil {
		return err
	}
	if value.State.Mode != value.Provider.StateMode || value.MaximumOutputTokens > value.Provider.ContextLimit {
		return NewError(Denied, "request_provider_binding")
	}
	if _, err := parseTimestamp(value.Deadline); err != nil {
		return NewError(InvalidInput, "request_deadline")
	}
	for _, digest := range []string{value.AuthorizationDigest, value.PolicyDecisionDigest,
		value.ApprovalDecisionDigest, value.AuditReservationDigest} {
		if !digestPattern.MatchString(digest) {
			return NewError(Denied, "request_authority")
		}
	}
	return nil
}

func ValidateResponse(value InferenceResponse) error {
	if value.SchemaVersion != ResponseSchemaVersion || value.ContractVersion != ContractVersion {
		return NewError(Unsupported, "unsupported_contract")
	}
	for _, identifier := range []string{value.ResponseID, value.RequestID, value.AttemptID, value.QualificationID} {
		if !uuidPattern.MatchString(identifier) {
			return NewError(InvalidInput, "response_identity")
		}
	}
	if err := validateProvider(value.Provider); err != nil {
		return err
	}
	if !digestPattern.MatchString(value.CapabilityDigest) || !digestPattern.MatchString(value.ProvenanceDigest) ||
		len(value.Items) > 16384 || !oneOf(value.Outcome, "succeeded", "denied", "canceled", "timeout", "failed", "uncertain") {
		return NewError(InvalidInput, "response_binding")
	}
	for _, item := range value.Items {
		if err := validateContent(item); err != nil {
			return err
		}
	}
	if value.Usage.TotalTokens != value.Usage.InputTokens+value.Usage.OutputTokens ||
		value.Usage.CachedInputTokens > value.Usage.InputTokens || value.Usage.ReasoningTokens > value.Usage.OutputTokens {
		return NewError(InvalidInput, "response_usage")
	}
	if err := validateState(value.State); err != nil {
		return err
	}
	if value.State.Mode != value.Provider.StateMode {
		return NewError(Denied, "response_provider_binding")
	}
	started, startErr := parseTimestamp(value.StartedAt)
	completed, completeErr := parseTimestamp(value.CompletedAt)
	if startErr != nil || completeErr != nil || completed.Before(started) {
		return NewError(InvalidInput, "response_timing")
	}
	if value.Outcome == "succeeded" {
		if value.Error != nil {
			return NewError(InvalidInput, "response_error")
		}
	} else if value.Error == nil || validateTerminalError(*value.Error) != nil {
		return NewError(InvalidInput, "response_error")
	}
	return nil
}

func ValidateStreamEvent(value StreamEvent) error {
	if value.SchemaVersion != StreamEventSchemaVersion || value.ContractVersion != ContractVersion {
		return NewError(Unsupported, "unsupported_contract")
	}
	if !uuidPattern.MatchString(value.RequestID) || !uuidPattern.MatchString(value.AttemptID) {
		return NewError(InvalidInput, "stream_identity")
	}
	if _, err := parseTimestamp(value.ObservedAt); err != nil {
		return NewError(InvalidInput, "stream_timing")
	}
	present := 0
	if value.TextDelta != "" {
		present++
	}
	if value.Item != nil {
		present++
	}
	if value.UsageDelta != nil {
		present++
	}
	if value.Response != nil {
		present++
	}
	if value.Error != nil {
		present++
	}
	if present != 1 {
		return NewError(InvalidInput, "stream_payload")
	}
	switch value.Kind {
	case "text_delta":
		if value.TextDelta == "" || len(value.TextDelta) > 1048576 {
			return NewError(InvalidInput, "stream_payload")
		}
	case "item":
		if value.Item == nil || validateContent(*value.Item) != nil {
			return NewError(InvalidInput, "stream_payload")
		}
	case "usage_delta":
		if value.UsageDelta == nil {
			return NewError(InvalidInput, "stream_payload")
		}
	case "completed":
		if value.Response == nil || ValidateResponse(*value.Response) != nil || value.Response.RequestID != value.RequestID ||
			value.Response.AttemptID != value.AttemptID {
			return NewError(InvalidInput, "stream_terminal")
		}
	case "error":
		if value.Error == nil || validateTerminalError(*value.Error) != nil {
			return NewError(InvalidInput, "stream_terminal")
		}
	default:
		return NewError(InvalidInput, "stream_kind")
	}
	return nil
}

func validateMessage(value Message) error {
	if !uuidPattern.MatchString(value.MessageID) || !oneOf(value.Role, "system", "developer", "user", "assistant", "tool") ||
		len(value.Items) == 0 || len(value.Items) > 4096 {
		return NewError(InvalidInput, "message_identity")
	}
	for _, item := range value.Items {
		if err := validateContent(item); err != nil {
			return err
		}
		if !roleAllows(value.Role, item.Kind) {
			return NewError(Denied, "message_content")
		}
	}
	return nil
}

func validateContent(value ContentItem) error {
	switch value.Kind {
	case "text":
		if len(value.Text) > 1048576 || hasNonTextFields(value) {
			return NewError(InvalidInput, "content_text")
		}
	case "input_json", "output_json":
		if !validJSONObject(value.Value) || !digestPattern.MatchString(value.SchemaDigest) || hasOutsideJSONFields(value) {
			return NewError(InvalidInput, "content_json")
		}
	case "tool_call":
		if !boundedText(value.CallID, 128) || !tokenPattern.MatchString(value.ToolName) || !validJSONObject(value.Arguments) ||
			!digestPattern.MatchString(value.InputSchemaDigest) || hasOutsideToolCallFields(value) {
			return NewError(InvalidInput, "content_tool_call")
		}
	case "tool_result":
		if !boundedText(value.CallID, 128) || !oneOf(value.Outcome, "succeeded", "denied", "canceled", "timeout", "failed", "uncertain") ||
			!validJSONObject(value.Value) || !digestPattern.MatchString(value.OutputSchemaDigest) ||
			value.ResultDigest != toolResultDigest(value.Value) || hasOutsideToolResultFields(value) {
			return NewError(InvalidInput, "content_tool_result")
		}
	case "reasoning_ref":
		if !boundedText(value.ReferenceID, 256) || !digestPattern.MatchString(value.Digest) || hasOutsideReasoningFields(value) {
			return NewError(InvalidInput, "content_reasoning")
		}
	default:
		return NewError(Unsupported, "content_kind")
	}
	return nil
}

func validateOutputConstraint(value OutputConstraint) error {
	switch value.Kind {
	case "text":
		if value.Name != "" || value.SchemaDigest != "" || value.Strict != nil {
			return NewError(InvalidInput, "output_constraint")
		}
	case "json_schema":
		if !tokenPattern.MatchString(value.Name) || !digestPattern.MatchString(value.SchemaDigest) || value.Strict == nil || !*value.Strict {
			return NewError(Denied, "output_constraint")
		}
	default:
		return NewError(Unsupported, "output_constraint")
	}
	return nil
}

func validateState(value State) error {
	switch value.Mode {
	case "stateless":
		if value.ReferenceID != "" || value.StateDigest != "" {
			return NewError(InvalidInput, "state_binding")
		}
	case "client_managed", "provider_managed":
		if !boundedText(value.ReferenceID, 256) || !digestPattern.MatchString(value.StateDigest) {
			return NewError(InvalidInput, "state_binding")
		}
	default:
		return NewError(Unsupported, "state_mode")
	}
	return nil
}

func validateTerminalError(value TerminalError) error {
	if !oneOf(value.Code, "invalid_input", "denied", "unsupported", "canceled", "timeout", "unavailable", "conflict", "internal") ||
		!reasonPattern.MatchString(value.Reason) || len(value.Message) > 512 || !safeErrorMessage(value.Message) {
		return NewError(InvalidInput, "terminal_error")
	}
	return nil
}

func roleAllows(role, kind string) bool {
	switch role {
	case "system", "developer", "user":
		return oneOf(kind, "text", "input_json")
	case "assistant":
		return oneOf(kind, "text", "output_json", "tool_call", "reasoning_ref")
	case "tool":
		return kind == "tool_result"
	default:
		return false
	}
}

func safeErrorMessage(value string) bool {
	lower := strings.ToLower(value)
	return !slices.ContainsFunc([]string{"bearer ", "api_key", "private_key", "credential", "authorization:"}, func(token string) bool {
		return strings.Contains(lower, token)
	})
}

func rawEmpty(value []byte) bool { return len(bytes.TrimSpace(value)) == 0 }

func toolResultDigest(value []byte) string {
	canonical, err := domaincontract.Canonicalize(value)
	if err != nil {
		return ""
	}
	input := make([]byte, 0, len(toolResultDigestDomain)+len(canonical))
	input = append(input, toolResultDigestDomain...)
	input = append(input, canonical...)
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestToolResult returns the contract digest for one typed JSON tool result.
func DigestToolResult(value json.RawMessage) (string, error) {
	digest := toolResultDigest(value)
	if digest == "" || !validJSONObject(value) {
		return "", NewError(InvalidInput, "tool_result_value")
	}
	return digest, nil
}

func hasNonTextFields(value ContentItem) bool {
	return !rawEmpty(value.Value) || value.SchemaDigest != "" || value.CallID != "" || value.ToolName != "" ||
		!rawEmpty(value.Arguments) || value.InputSchemaDigest != "" || value.Outcome != "" || value.OutputSchemaDigest != "" || value.ResultDigest != "" ||
		value.ReferenceID != "" || value.Digest != ""
}

func hasOutsideJSONFields(value ContentItem) bool {
	return value.Text != "" || value.CallID != "" || value.ToolName != "" || !rawEmpty(value.Arguments) ||
		value.InputSchemaDigest != "" || value.Outcome != "" || value.OutputSchemaDigest != "" || value.ResultDigest != "" || value.ReferenceID != "" || value.Digest != ""
}

func hasOutsideToolCallFields(value ContentItem) bool {
	return value.Text != "" || !rawEmpty(value.Value) || value.SchemaDigest != "" || value.Outcome != "" ||
		value.OutputSchemaDigest != "" || value.ResultDigest != "" || value.ReferenceID != "" || value.Digest != ""
}

func hasOutsideToolResultFields(value ContentItem) bool {
	return value.Text != "" || value.SchemaDigest != "" || value.ToolName != "" ||
		!rawEmpty(value.Arguments) || value.InputSchemaDigest != "" || value.ReferenceID != "" || value.Digest != ""
}

func hasOutsideReasoningFields(value ContentItem) bool {
	return value.Text != "" || !rawEmpty(value.Value) || value.SchemaDigest != "" || value.CallID != "" ||
		value.ToolName != "" || !rawEmpty(value.Arguments) || value.InputSchemaDigest != "" || value.Outcome != "" ||
		value.OutputSchemaDigest != "" || value.ResultDigest != ""
}
