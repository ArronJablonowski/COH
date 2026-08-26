package providercontract

import (
	"context"
	"encoding/json"
	"testing"
)

func TestProviderNeutralConformanceSuite(t *testing.T) {
	capability := decodeCapabilityFixture(t)
	base := validRequest(capability.Value().Provider, capability.Digest())
	traces := make([]ConformanceTrace, 0, 6)
	traces = append(traces, cancellationTrace(t, capability, base, "canceled"))
	traces = append(traces, ConformanceTrace{Kind: "capability", Capability: capability})
	traces = append(traces, successfulTrace(t, "identity_provenance", capability, base, nil))
	traces = append(traces, successfulTrace(t, "policy_route", capability, base, nil))

	structured := base
	strict := true
	structured.OutputConstraint = OutputConstraint{Kind: "json_schema", Name: "answer", SchemaDigest: digest("f"), Strict: &strict}
	traces = append(traces, successfulTrace(t, "structured_output", capability, structured,
		[]ContentItem{{Kind: "output_json", Value: json.RawMessage(`{"answer":"ok"}`), SchemaDigest: digest("f")}}))

	toolRequest := base
	toolRequest.Tools = []Tool{{Name: "collect", Description: "Collect typed evidence", InputSchemaDigest: digest("1"), OutputSchemaDigest: digest("2")}}
	traces = append(traces, successfulTrace(t, "tool_call", capability, toolRequest,
		[]ContentItem{{Kind: "tool_call", CallID: "call-1", ToolName: "collect", Arguments: json.RawMessage(`{"target":"case"}`), InputSchemaDigest: digest("1")}}))

	if err := EvaluateConformanceSuite(context.Background(), traces); err != nil {
		t.Fatal(err)
	}
	traces[5].Events[0], traces[5].Events[1] = traces[5].Events[1], traces[5].Events[0]
	if err := EvaluateConformanceSuite(context.Background(), traces); err == nil {
		t.Fatal("sequence tamper accepted")
	}
}

func TestConformanceCancellationAcceptsTimeoutAndPreservesRecovery(t *testing.T) {
	capability := decodeCapabilityFixture(t)
	request := validRequest(capability.Value().Provider, capability.Digest())
	if err := EvaluateConformanceTrace(context.Background(), cancellationTrace(t, capability, request, "timeout")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := EvaluateConformanceTrace(ctx, cancellationTrace(t, capability, request, "canceled")); Code(err) != Canceled {
		t.Fatalf("canceled err=%v", err)
	}
	if err := EvaluateConformanceTrace(context.Background(), cancellationTrace(t, capability, request, "canceled")); err != nil {
		t.Fatalf("recovery err=%v", err)
	}
}

func successfulTrace(t *testing.T, kind string, capability ValidatedCapability, request InferenceRequest,
	items []ContentItem) ConformanceTrace {
	t.Helper()
	if items == nil {
		items = []ContentItem{{Kind: "text", Text: "ok"}}
	}
	response := validResponse(capability.Value().Provider, capability.Digest(), request)
	response.Items = items
	events := []ValidatedStreamEvent{
		decodeEvent(t, StreamEvent{SchemaVersion: StreamEventSchemaVersion, ContractVersion: ContractVersion,
			RequestID: request.RequestID, AttemptID: request.AttemptID, Sequence: 0,
			ObservedAt: "2026-08-26T06:00:00.000000000Z", Kind: "text_delta", TextDelta: "chunk"}),
		decodeEvent(t, StreamEvent{SchemaVersion: StreamEventSchemaVersion, ContractVersion: ContractVersion,
			RequestID: request.RequestID, AttemptID: request.AttemptID, Sequence: 1,
			ObservedAt: "2026-08-26T06:00:01.000000000Z", Kind: "completed", Response: &response}),
	}
	return ConformanceTrace{Kind: kind, Capability: capability, Request: decodeRequest(t, request), Events: events}
}

func cancellationTrace(t *testing.T, capability ValidatedCapability, request InferenceRequest, code string) ConformanceTrace {
	t.Helper()
	event := StreamEvent{SchemaVersion: StreamEventSchemaVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, AttemptID: request.AttemptID, Sequence: 0,
		ObservedAt: "2026-08-26T06:00:00.000000000Z", Kind: "error",
		Error: &TerminalError{Code: code, Reason: "provider_" + code, Message: "request stopped", Retryable: code == "timeout"}}
	return ConformanceTrace{Kind: "cancellation", Capability: capability, Request: decodeRequest(t, request),
		Events: []ValidatedStreamEvent{decodeEvent(t, event)}}
}
