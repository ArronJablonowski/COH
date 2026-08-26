package openairesponses

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestPublishedCapabilityMatchesDiscovery(t *testing.T) {
	rig := newTestRig(t, "completed-response.json")
	fixture, err := os.ReadFile("../../../contracts/provider/openai-responses/v1/capability.json")
	if err != nil {
		t.Fatal(err)
	}
	published, err := providercontract.DecodeCapability(context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	discovered := rig.adapter.Capability()
	if published.Digest() != discovered.Digest() || !bytes.Equal(published.CanonicalBytes(), discovered.CanonicalBytes()) {
		t.Fatalf("published=%s discovered=%s", published.Digest(), discovered.Digest())
	}
}

func TestAdapterPassesProviderNeutralConformanceSuite(t *testing.T) {
	toolRig := newTestRig(t, "completed-response.json")
	toolRig.http.body = readFixture(t, "completed-stream.sse")
	toolRig.http.contentType = "text/event-stream"
	toolEvents := collectStream(t, toolRig.adapter, context.Background(), toolRig.request)

	structuredRig := newTestRig(t, "structured-response.json")
	structuredRequest := structuredRig.request.Value()
	strict := true
	structuredRequest.OutputConstraint = providercontract.OutputConstraint{Kind: "json_schema", Name: "verdict",
		SchemaDigest: testDigest("c"), Strict: &strict}
	validatedStructured := decodeRequest(t, structuredRequest)
	structuredResponse, err := structuredRig.adapter.Invoke(context.Background(), validatedStructured)
	if err != nil {
		t.Fatal(err)
	}
	structuredEvents := []providercontract.ValidatedStreamEvent{terminalEvent(t, validatedStructured, structuredResponse,
		structuredRig.clock)}

	cancelRig := newTestRig(t, "completed-response.json")
	cancelRig.adapter.config.HTTP = blockingHTTP{}
	cancelContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	cancelEvents := collectStream(t, cancelRig.adapter, cancelContext, cancelRig.request)

	capability := toolRig.adapter.Capability()
	traces := []providercontract.ConformanceTrace{
		{Kind: "cancellation", Capability: capability, Request: cancelRig.request, Events: cancelEvents},
		{Kind: "capability", Capability: capability},
		{Kind: "identity_provenance", Capability: capability, Request: toolRig.request, Events: toolEvents},
		{Kind: "policy_route", Capability: capability, Request: toolRig.request, Events: toolEvents},
		{Kind: "structured_output", Capability: capability, Request: validatedStructured, Events: structuredEvents},
		{Kind: "tool_call", Capability: capability, Request: toolRig.request, Events: toolEvents},
	}
	if err := providercontract.EvaluateConformanceSuite(context.Background(), traces); err != nil {
		t.Fatal(err)
	}
}

func collectStream(t *testing.T, adapter *Adapter, ctx context.Context,
	request providercontract.ValidatedRequest) []providercontract.ValidatedStreamEvent {
	t.Helper()
	events := make([]providercontract.ValidatedStreamEvent, 0, 8)
	if err := adapter.Stream(ctx, request, func(event providercontract.ValidatedStreamEvent) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return events
}

func terminalEvent(t *testing.T, request providercontract.ValidatedRequest, response providercontract.ValidatedResponse,
	observed time.Time) providercontract.ValidatedStreamEvent {
	t.Helper()
	requestValue, responseValue := request.Value(), response.Value()
	event := providercontract.StreamEvent{SchemaVersion: providercontract.StreamEventSchemaVersion,
		ContractVersion: providercontract.ContractVersion, RequestID: requestValue.RequestID, AttemptID: requestValue.AttemptID,
		ObservedAt: formatTimestamp(observed), Kind: "completed", Response: &responseValue}
	encoded, _ := json.Marshal(event)
	validated, err := providercontract.DecodeStreamEvent(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}
