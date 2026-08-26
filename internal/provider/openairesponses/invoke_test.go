package openairesponses

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestInvokePreservesOrderedItemsStateUsageAndRequestInvariants(t *testing.T) {
	rig := newTestRig(t, "completed-response.json")
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	value := response.Value()
	if value.Outcome != "succeeded" || len(value.Items) != 3 || value.Items[0].Kind != "reasoning_ref" ||
		value.Items[1].Kind != "text" || value.Items[1].Text != "Ready." || value.Items[2].Kind != "tool_call" ||
		value.Items[2].CallID != "call_coh_001" || value.Items[2].ToolName != "query_host" {
		t.Fatalf("items=%+v outcome=%s", value.Items, value.Outcome)
	}
	if value.Usage.InputTokens != 10 || value.Usage.OutputTokens != 7 || value.Usage.TotalTokens != 17 ||
		value.Usage.CachedInputTokens != 2 || value.Usage.ReasoningTokens != 3 || value.ProvenanceDigest == "" {
		t.Fatalf("usage=%+v provenance=%s", value.Usage, value.ProvenanceDigest)
	}
	if _, err := rig.reasoning.Resolve(context.Background(), value.Items[0].ReferenceID, value.Items[0].Digest); err != nil {
		t.Fatal(err)
	}
	assertOutboundRequest(t, rig.http)
}

func TestInvokeMapsStrictStructuredOutput(t *testing.T) {
	rig := newTestRig(t, "structured-response.json")
	request := rig.request.Value()
	strict := true
	request.OutputConstraint = providercontract.OutputConstraint{Kind: "json_schema", Name: "verdict",
		SchemaDigest: testDigest("c"), Strict: &strict}
	response, err := rig.adapter.Invoke(context.Background(), decodeRequest(t, request))
	if err != nil {
		t.Fatal(err)
	}
	items := response.Value().Items
	if len(items) != 1 || items[0].Kind != "output_json" || items[0].SchemaDigest != testDigest("c") ||
		string(items[0].Value) != `{"verdict":"allow"}` {
		t.Fatalf("items=%+v", items)
	}
	var outbound createRequest
	if err := json.Unmarshal(rig.http.requestBody, &outbound); err != nil || outbound.Text == nil ||
		outbound.Text.Format.Type != "json_schema" || !outbound.Text.Format.Strict {
		t.Fatalf("outbound=%+v err=%v", outbound, err)
	}
}

func TestInvokePreservesIncompletePartialOutput(t *testing.T) {
	rig := newTestRig(t, "incomplete-response.json")
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	value := response.Value()
	if value.Outcome != "uncertain" || value.Error == nil || value.Error.Reason != "response_incomplete" ||
		len(value.Items) != 1 || value.Items[0].Text != "Partial output" || value.Usage.OutputTokens != 1024 {
		t.Fatalf("response=%+v", value)
	}
}

func TestReasoningReferenceIsResolvedForLaterTurn(t *testing.T) {
	rig := newTestRig(t, "completed-response.json")
	first, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	reasoning := first.Value().Items[0]
	request := rig.request.Value()
	request.Messages = append(request.Messages, providercontract.Message{MessageID: "0198e300-2000-7000-8000-000000000011",
		Role: "assistant", Items: []providercontract.ContentItem{reasoning}})
	if _, err := rig.adapter.Invoke(context.Background(), decodeRequest(t, request)); err != nil {
		t.Fatal(err)
	}
	var outbound createRequest
	if err := json.Unmarshal(rig.http.requestBody, &outbound); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range outbound.Input {
		if itemType, _ := peekType(item); itemType == "reasoning" {
			found = true
		}
	}
	if !found {
		t.Fatal("resolved reasoning item was not submitted")
	}
}

func assertOutboundRequest(t *testing.T, client *httpStub) {
	t.Helper()
	if client.request.Method != http.MethodPost || client.request.URL.String() != ResponsesEndpoint ||
		!client.authorizationPresent || client.request.Header.Get("Authorization") != "" ||
		client.request.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("request=%+v authorization_present=%v", client.request, client.authorizationPresent)
	}
	var request createRequest
	if err := json.Unmarshal(client.requestBody, &request); err != nil {
		t.Fatal(err)
	}
	if request.Model != "gpt-5.6" || request.Store || request.Background || request.Stream || request.Truncation != "disabled" ||
		request.ParallelToolCalls || request.MaxOutputTokens != 1024 || len(request.Include) != 1 ||
		request.Include[0] != "reasoning.encrypted_content" || len(request.Tools) != 1 || !request.Tools[0].Strict {
		t.Fatalf("outbound=%+v", request)
	}
}
