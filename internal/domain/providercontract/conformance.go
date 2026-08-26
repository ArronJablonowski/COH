package providercontract

import (
	"context"
	"reflect"
	"slices"
)

var mandatoryConformanceCases = []string{
	"cancellation", "capability", "identity_provenance", "policy_route", "structured_output", "tool_call",
}

// ConformanceTrace is a provider-neutral recorded interaction. Adapter suites
// feed canonical documents here; no vendor request or response type crosses
// this boundary.
type ConformanceTrace struct {
	Kind       string
	Capability ValidatedCapability
	Request    ValidatedRequest
	Events     []ValidatedStreamEvent
}

func EvaluateConformanceSuite(ctx context.Context, traces []ConformanceTrace) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if len(traces) != len(mandatoryConformanceCases) {
		return NewError(Unsupported, "conformance_cases")
	}
	for index, trace := range traces {
		if trace.Kind != mandatoryConformanceCases[index] {
			return NewError(Unsupported, "conformance_cases")
		}
		if err := EvaluateConformanceTrace(ctx, trace); err != nil {
			return err
		}
	}
	return nil
}

func EvaluateConformanceTrace(ctx context.Context, trace ConformanceTrace) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !slices.Contains(mandatoryConformanceCases, trace.Kind) || trace.Capability.Digest() == "" {
		return NewError(InvalidInput, "conformance_trace")
	}
	capability := trace.Capability.Value()
	if trace.Kind == "capability" {
		if trace.Request.Digest() != "" || len(trace.Events) != 0 || !capability.Features.ToolCalls ||
			!capability.Features.StructuredOutput || !capability.Features.Streaming || !capability.Features.Cancellation ||
			!capability.Features.Usage {
			return NewError(Unsupported, "conformance_capability")
		}
		return nil
	}
	if trace.Request.Digest() == "" || len(trace.Events) == 0 {
		return NewError(InvalidInput, "conformance_trace")
	}
	request := trace.Request.Value()
	if request.CapabilityDigest != trace.Capability.Digest() || !reflect.DeepEqual(request.Provider, capability.Provider) ||
		request.State.Mode != capability.Provider.StateMode || uint64(len(request.Messages)) > uint64(capability.Limits.MaximumMessages) ||
		uint64(len(request.Tools)) > uint64(capability.Limits.MaximumTools) || request.MaximumOutputTokens > capability.Limits.MaximumOutputTokens {
		return NewError(Unsupported, "conformance_binding")
	}
	stream := &StreamValidator{}
	for _, event := range trace.Events {
		if err := contextError(ctx); err != nil {
			return err
		}
		value := event.Value()
		if value.RequestID != request.RequestID || value.AttemptID != request.AttemptID {
			return NewError(Conflict, "conformance_correlation")
		}
		if err := stream.Apply(event); err != nil {
			return err
		}
	}
	if !stream.Complete() {
		return NewError(Unsupported, "conformance_incomplete")
	}
	terminal := trace.Events[len(trace.Events)-1].Value()
	if trace.Kind == "cancellation" {
		if terminal.Kind != "error" || terminal.Error == nil || !oneOf(terminal.Error.Code, "canceled", "timeout") ||
			!capability.Features.Cancellation {
			return NewError(Unsupported, "conformance_cancellation")
		}
		return nil
	}
	if terminal.Kind != "completed" || terminal.Response == nil {
		return NewError(Unsupported, "conformance_terminal")
	}
	response := terminal.Response
	if response.RequestID != request.RequestID || response.AttemptID != request.AttemptID ||
		response.CapabilityDigest != trace.Capability.Digest() || response.QualificationID != request.QualificationID ||
		!reflect.DeepEqual(response.Provider, capability.Provider) || response.ProvenanceDigest == "" {
		return NewError(Unsupported, "conformance_provenance")
	}
	switch trace.Kind {
	case "identity_provenance":
		return nil
	case "policy_route":
		if !digestPattern.MatchString(request.AuthorizationDigest) || !digestPattern.MatchString(request.PolicyDecisionDigest) ||
			!digestPattern.MatchString(request.ApprovalDecisionDigest) || !digestPattern.MatchString(request.AuditReservationDigest) {
			return NewError(Denied, "conformance_policy_route")
		}
	case "structured_output":
		if request.OutputConstraint.Kind != "json_schema" || !containsOutputSchema(response.Items, request.OutputConstraint.SchemaDigest) {
			return NewError(Unsupported, "conformance_structured_output")
		}
	case "tool_call":
		if !containsQualifiedToolCall(request.Tools, response.Items) {
			return NewError(Unsupported, "conformance_tool_call")
		}
	}
	return nil
}

func containsOutputSchema(items []ContentItem, digest string) bool {
	return slices.ContainsFunc(items, func(item ContentItem) bool {
		return item.Kind == "output_json" && item.SchemaDigest == digest && validJSONObject(item.Value)
	})
}

func containsQualifiedToolCall(tools []Tool, items []ContentItem) bool {
	for _, item := range items {
		if item.Kind != "tool_call" {
			continue
		}
		if slices.ContainsFunc(tools, func(tool Tool) bool {
			return tool.Name == item.ToolName && tool.InputSchemaDigest == item.InputSchemaDigest
		}) {
			return true
		}
	}
	return false
}
