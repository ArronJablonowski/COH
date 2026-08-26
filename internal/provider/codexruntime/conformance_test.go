package codexruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestPublishedCapabilityMatchesDiscovery(t *testing.T) {
	fixture, err := os.ReadFile("../../../contracts/provider/codex-runtime/v1/capability.json")
	if err != nil {
		t.Skip("capability not published yet")
	}
	published, err := providercontract.DecodeCapability(context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	discovered := newRig(t).adapter.Capability()
	if published.Digest() != discovered.Digest() || !bytes.Equal(published.CanonicalBytes(), discovered.CanonicalBytes()) {
		t.Fatalf("published=%s discovered=%s", published.Digest(), discovered.Digest())
	}
	if published.Digest() != "sha256:abca41faee87118e28fb4135accbdfa624c31350d723168f75df3c4036295ee5" {
		t.Fatalf("unexpected published digest: %s", published.Digest())
	}
}

func TestProviderNeutralConformanceSuite(t *testing.T) {
	toolRig := newRig(t)
	toolEvents := collectStream(t, toolRig.adapter, context.Background(), toolRig.request)
	structuredRig := newRig(t)
	lines := structuredRig.transport.incoming
	lines[6] = []byte(strings.Replace(string(lines[6]), "Host is clean.", `{\"result\":\"ok\"}`, 1))
	lines[7] = []byte(strings.Replace(string(lines[7]), "Host is clean.", `{\"result\":\"ok\"}`, 1))
	structuredRig.transport.incoming = append(append([][]byte{}, lines[:8]...), lines[11:]...)
	request := structuredRig.request.Value()
	request.Tools = []providercontract.Tool{}
	strict := true
	request.OutputConstraint = providercontract.OutputConstraint{Kind: "json_schema", Name: "result", SchemaDigest: testDigest("3"), Strict: &strict}
	validated := decodeRequest(t, request)
	response, err := structuredRig.adapter.Invoke(context.Background(), validated)
	if err != nil {
		t.Fatal(err)
	}
	structuredEvents := []providercontract.ValidatedStreamEvent{terminalEvent(t, validated, response, structuredRig.clock)}
	cancelRig := newRig(t)
	cancelRig.transport.incoming = cancelRig.transport.incoming[:4]
	cancelRig.transport.block = true
	cancelCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	cancelEvents := collectStream(t, cancelRig.adapter, cancelCtx, cancelRig.request)
	capability := toolRig.adapter.Capability()
	traces := []providercontract.ConformanceTrace{{Kind: "cancellation", Capability: capability, Request: cancelRig.request, Events: cancelEvents}, {Kind: "capability", Capability: capability}, {Kind: "identity_provenance", Capability: capability, Request: toolRig.request, Events: toolEvents}, {Kind: "policy_route", Capability: capability, Request: toolRig.request, Events: toolEvents}, {Kind: "structured_output", Capability: capability, Request: validated, Events: structuredEvents}, {Kind: "tool_call", Capability: capability, Request: toolRig.request, Events: toolEvents}}
	if err := providercontract.EvaluateConformanceSuite(context.Background(), traces); err != nil {
		t.Fatal(err)
	}
}

func collectStream(t *testing.T, a *Adapter, ctx context.Context, request providercontract.ValidatedRequest) []providercontract.ValidatedStreamEvent {
	t.Helper()
	events := []providercontract.ValidatedStreamEvent{}
	if err := a.Stream(ctx, request, func(event providercontract.ValidatedStreamEvent) error { events = append(events, event); return nil }); err != nil {
		t.Fatal(err)
	}
	return events
}
func terminalEvent(t *testing.T, request providercontract.ValidatedRequest, response providercontract.ValidatedResponse, at time.Time) providercontract.ValidatedStreamEvent {
	t.Helper()
	v := request.Value()
	r := response.Value()
	event := providercontract.StreamEvent{SchemaVersion: providercontract.StreamEventSchemaVersion, ContractVersion: providercontract.ContractVersion, RequestID: v.RequestID, AttemptID: v.AttemptID, ObservedAt: formatTimestamp(at), Kind: "completed", Response: &r}
	encoded, _ := json.Marshal(event)
	result, err := providercontract.DecodeStreamEvent(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
