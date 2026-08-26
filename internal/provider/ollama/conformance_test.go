package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestPublishedCapabilityMatchesDiscovery(t *testing.T) {
	rig := newTestRig(t)
	fixture, err := os.ReadFile("../../../contracts/provider/ollama/v1/capability.json")
	if err != nil {
		t.Fatal(err)
	}
	published, err := providercontract.DecodeCapability(context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	discovered := rig.adapter.Capability()
	if published.Digest() != "sha256:6575d3610a3ae4b455513c50e8b803e7814c64937bde75ea6fd3e2fb36aa7968" {
		t.Fatalf("capability digest=%s", published.Digest())
	}
	if published.Digest() != discovered.Digest() || !bytes.Equal(published.CanonicalBytes(), discovered.CanonicalBytes()) {
		t.Fatalf("published=%s discovered=%s", published.Digest(), discovered.Digest())
	}
}

func TestAdapterPassesProviderNeutralConformanceSuite(t *testing.T) {
	toolRig := newTestRig(t)
	toolRig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
		body: readFixture(t, "completed-stream.ndjson"), contentType: "application/x-ndjson"}
	toolEvents := collectStream(t, toolRig.adapter, context.Background(), toolRig.request)

	structuredRig := newTestRig(t)
	structuredRig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
		body: readFixture(t, "structured-chat.json")}
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

	cancelRig := newTestRig(t)
	cancelRig.http.blockPath = ChatPath
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
