package providercontract

import (
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var providerFields = []string{
	"provider_kind", "adapter_version", "endpoint_identity_digest", "data_route", "requested_model", "actual_model",
	"model_revision", "runtime_name", "runtime_version", "runtime_digest", "tokenizer_name", "tokenizer_version",
	"tokenizer_digest", "chat_template_digest", "tool_parser_digest", "reasoning_parser_digest", "context_limit",
	"sampling_profile_digest", "hardware_profile_digest", "state_mode", "policy_revision",
}

func validateCapabilityShape(input []byte) error {
	root, err := exactObject(input, []string{"schema_version", "contract_version", "snapshot_id", "observed_at", "valid_until", "provider", "features", "limits"})
	if err != nil || exactMap(root["provider"], providerFields, nil) != nil ||
		exactMap(root["features"], []string{"message_roles", "content_kinds", "tool_calls", "structured_output", "streaming", "cancellation", "usage", "state_modes"}, nil) != nil ||
		exactMap(root["limits"], []string{"maximum_input_tokens", "maximum_output_tokens", "maximum_messages", "maximum_tools", "maximum_parallel_tool_calls", "maximum_stream_seconds"}, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	return nil
}

func validateQualificationShape(input []byte) error {
	root, err := exactObject(input, []string{"schema_version", "contract_version", "qualification_id", "issued_at", "expires_at", "provider", "capability_digest", "release_matrix", "cases", "aggregate_outcome", "suite_digest", "qualifier_identity_digest"})
	if err != nil || exactMap(root["provider"], providerFields, nil) != nil ||
		exactMap(root["release_matrix"], []string{"profile", "os", "architecture", "deployment_mode", "network_mode"}, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	cases, ok := root["cases"].([]any)
	if !ok {
		return NewError(InvalidInput, "document_decoding")
	}
	for _, item := range cases {
		if exactMap(item, []string{"kind", "fixture_digest", "outcome", "trace_digest", "duration_milliseconds"}, nil) != nil {
			return NewError(InvalidInput, "document_decoding")
		}
	}
	return nil
}

func validateRequestShape(input []byte) error {
	root, err := exactObject(input, []string{"schema_version", "contract_version", "request_id", "attempt_id", "organization_id", "tenant_id", "case_id", "task_id", "actor_id", "provider", "capability_digest", "qualification_id", "messages", "tools", "output_constraint", "sampling", "maximum_output_tokens", "state", "deadline", "authorization_digest", "policy_decision_digest", "approval_decision_digest", "audit_reservation_digest"})
	if err != nil || exactMap(root["provider"], providerFields, nil) != nil ||
		exactMap(root["sampling"], []string{"temperature_milli", "top_p_millionths", "seed"}, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	if err := validateOutputShape(root["output_constraint"]); err != nil {
		return err
	}
	if err := validateStateShape(root["state"]); err != nil {
		return err
	}
	messages, ok := root["messages"].([]any)
	if !ok {
		return NewError(InvalidInput, "document_decoding")
	}
	for _, rawMessage := range messages {
		message, err := mapWithFields(rawMessage, []string{"message_id", "role", "items"}, nil)
		if err != nil {
			return err
		}
		items, ok := message["items"].([]any)
		if !ok {
			return NewError(InvalidInput, "document_decoding")
		}
		for _, item := range items {
			if err := validateContentShape(item); err != nil {
				return err
			}
		}
	}
	tools, ok := root["tools"].([]any)
	if !ok {
		return NewError(InvalidInput, "document_decoding")
	}
	for _, tool := range tools {
		if exactMap(tool, []string{"name", "description", "input_schema_digest", "output_schema_digest"}, nil) != nil {
			return NewError(InvalidInput, "document_decoding")
		}
	}
	return nil
}

func validateResponseShape(input []byte) error {
	value, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	return validateResponseMap(value)
}

func validateResponseMap(value any) error {
	root, err := mapWithFields(value, []string{"schema_version", "contract_version", "response_id", "request_id", "attempt_id", "provider", "capability_digest", "qualification_id", "outcome", "items", "usage", "state", "started_at", "completed_at", "provenance_digest"}, []string{"error"})
	if err != nil || exactMap(root["provider"], providerFields, nil) != nil ||
		exactMap(root["usage"], []string{"input_tokens", "output_tokens", "total_tokens", "cached_input_tokens", "reasoning_tokens"}, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	if err := validateStateShape(root["state"]); err != nil {
		return err
	}
	items, ok := root["items"].([]any)
	if !ok {
		return NewError(InvalidInput, "document_decoding")
	}
	for _, item := range items {
		if err := validateContentShape(item); err != nil {
			return err
		}
	}
	if rawError, exists := root["error"]; exists && exactMap(rawError, []string{"code", "reason", "message", "retryable"}, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	return nil
}

func validateStreamShape(input []byte) error {
	value, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	root, err := mapWithFields(value, []string{"schema_version", "contract_version", "request_id", "attempt_id", "sequence", "observed_at", "kind"}, []string{"text_delta", "item", "usage_delta", "response", "error"})
	if err != nil {
		return err
	}
	kind, _ := root["kind"].(string)
	var payload string
	switch kind {
	case "text_delta":
		payload = "text_delta"
	case "item":
		payload = "item"
	case "usage_delta":
		payload = "usage_delta"
	case "completed":
		payload = "response"
	case "error":
		payload = "error"
	default:
		return NewError(InvalidInput, "document_decoding")
	}
	if len(root) != 8 {
		return NewError(InvalidInput, "document_decoding")
	}
	if _, exists := root[payload]; !exists {
		return NewError(InvalidInput, "document_decoding")
	}
	switch payload {
	case "item":
		return validateContentShape(root[payload])
	case "usage_delta":
		if exactMap(root[payload], []string{"input_tokens", "output_tokens", "cached_input_tokens", "reasoning_tokens"}, nil) != nil {
			return NewError(InvalidInput, "document_decoding")
		}
	case "response":
		return validateResponseMap(root[payload])
	case "error":
		if exactMap(root[payload], []string{"code", "reason", "message", "retryable"}, nil) != nil {
			return NewError(InvalidInput, "document_decoding")
		}
	}
	return nil
}

func validateContentShape(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return NewError(InvalidInput, "document_decoding")
	}
	kind, _ := object["kind"].(string)
	var fields []string
	switch kind {
	case "text":
		fields = []string{"kind", "text"}
	case "input_json", "output_json":
		fields = []string{"kind", "value", "schema_digest"}
	case "tool_call":
		fields = []string{"kind", "call_id", "tool_name", "arguments", "input_schema_digest"}
	case "tool_result":
		fields = []string{"kind", "call_id", "outcome", "value", "output_schema_digest", "result_digest"}
	case "reasoning_ref":
		fields = []string{"kind", "reference_id", "digest"}
	default:
		return NewError(InvalidInput, "document_decoding")
	}
	if exactMap(object, fields, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	return nil
}

func validateOutputShape(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return NewError(InvalidInput, "document_decoding")
	}
	kind, _ := object["kind"].(string)
	fields := []string{"kind"}
	if kind == "json_schema" {
		fields = []string{"kind", "name", "schema_digest", "strict"}
	} else if kind != "text" {
		return NewError(InvalidInput, "document_decoding")
	}
	if exactMap(object, fields, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	return nil
}

func validateStateShape(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return NewError(InvalidInput, "document_decoding")
	}
	mode, _ := object["mode"].(string)
	fields := []string{"mode"}
	if mode == "client_managed" || mode == "provider_managed" {
		fields = []string{"mode", "reference_id", "state_digest"}
	} else if mode != "stateless" {
		return NewError(InvalidInput, "document_decoding")
	}
	if exactMap(object, fields, nil) != nil {
		return NewError(InvalidInput, "document_decoding")
	}
	return nil
}

func exactObject(input []byte, required []string) (map[string]any, error) {
	value, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return nil, NewError(InvalidInput, "document_decoding")
	}
	return mapWithFields(value, required, nil)
}

func exactMap(value any, required, optional []string) error {
	_, err := mapWithFields(value, required, optional)
	return err
}

func mapWithFields(value any, required, optional []string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) < len(required) || len(object) > len(required)+len(optional) {
		return nil, NewError(InvalidInput, "document_decoding")
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = struct{}{}
		if _, exists := object[name]; !exists {
			return nil, NewError(InvalidInput, "document_decoding")
		}
	}
	for _, name := range optional {
		allowed[name] = struct{}{}
	}
	for name := range object {
		if _, exists := allowed[name]; !exists {
			return nil, NewError(InvalidInput, "document_decoding")
		}
	}
	return object, nil
}
