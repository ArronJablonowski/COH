package vllm

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"testing"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestStructuredOutputUsesNativeFormatAndPreservesSchema(t *testing.T) {
	rig := newTestRig(t)
	rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
		body: readFixture(t, "structured-chat.json")}
	request := rig.request.Value()
	request.Tools = []providercontract.Tool{}
	strict := true
	request.OutputConstraint = providercontract.OutputConstraint{Kind: "json_schema", Name: "verdict",
		SchemaDigest: testDigest("c"), Strict: &strict}
	validated := decodeRequest(t, request)
	response, err := rig.adapter.Invoke(context.Background(), validated)
	if err != nil {
		t.Fatal(err)
	}
	item := response.Value().Items[0]
	if item.Kind != "output_json" || item.SchemaDigest != testDigest("c") || string(item.Value) != `{"verdict":"allow"}` {
		t.Fatalf("item=%+v", item)
	}
	var wire chatRequest
	if err := decodeExact(rig.http.bodies[4], &wire); err != nil || wire.ResponseFormat == nil ||
		wire.ResponseFormat.Type != "json_schema" || wire.ResponseFormat.JSONSchema.Name != "verdict" || !wire.ResponseFormat.JSONSchema.Strict || len(wire.ResponseFormat.JSONSchema.Schema) == 0 {
		t.Fatalf("wire=%+v err=%v", wire, err)
	}
}

func TestWireRequestContainsOnlyBrokerApprovedFields(t *testing.T) {
	rig := newTestRig(t)
	if _, err := rig.adapter.Invoke(context.Background(), rig.request); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(rig.http.bodies[4], &document); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	wanted := []string{"include_reasoning", "logprobs", "max_completion_tokens", "messages", "model", "n", "parallel_tool_calls", "seed", "stream", "temperature", "tool_choice", "tools", "top_p"}
	if !reflect.DeepEqual(keys, wanted) {
		t.Fatalf("wire keys=%v", keys)
	}
	for _, forbidden := range []string{"api_key", "chat_template", "chat_template_kwargs", "documents", "echo", "guided_json", "kv_transfer_params", "media_io_kwargs", "priority", "prompt_adapter", "request_id", "structured_outputs", "truncate_prompt_tokens", "vllm_xargs"} {
		if _, exists := document[forbidden]; exists {
			t.Fatalf("forbidden field %q emitted", forbidden)
		}
	}
	var wire chatRequest
	if err := decodeExact(rig.http.bodies[4], &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Tools) != 1 || !wire.Tools[0].Function.Strict {
		t.Fatalf("tools=%+v", wire.Tools)
	}
}

func TestReasoningReferenceCanBeResolvedForLaterTurn(t *testing.T) {
	rig := newTestRig(t)
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	reasoning := response.Value().Items[1]
	request := rig.request.Value()
	request.Messages = []providercontract.Message{{MessageID: "0198e300-3000-7000-8000-000000000011", Role: "assistant",
		Items: []providercontract.ContentItem{reasoning}}}
	translation, err := rig.adapter.translateRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if translation.wire.Messages[0].Reasoning != "I checked the supplied evidence." {
		t.Fatalf("message=%+v", translation.wire.Messages[0])
	}
}

func TestToolCallAndResultTranslateWithoutVendorAuthority(t *testing.T) {
	rig := newTestRig(t)
	request := rig.request.Value()
	value := json.RawMessage(`{"reachable":true}`)
	resultDigest, err := providercontract.DigestToolResult(value)
	if err != nil {
		t.Fatal(err)
	}
	request.Messages = []providercontract.Message{
		{MessageID: "0198e300-3000-7000-8000-000000000011", Role: "assistant",
			Items: []providercontract.ContentItem{{Kind: "tool_call", CallID: "call-1", ToolName: "query_host",
				Arguments: json.RawMessage(`{"host":"srv-1"}`), InputSchemaDigest: testDigest("a")}}},
		{MessageID: "0198e300-3000-7000-8000-000000000012", Role: "tool",
			Items: []providercontract.ContentItem{{Kind: "tool_result", CallID: "call-1", Outcome: "succeeded", Value: value,
				OutputSchemaDigest: testDigest("b"), ResultDigest: resultDigest}}},
	}
	validated := decodeRequest(t, request)
	translation, err := rig.adapter.translateRequest(context.Background(), validated.Value())
	if err != nil {
		t.Fatal(err)
	}
	if len(translation.wire.Messages) != 2 || translation.wire.Messages[0].ToolCalls[0].Function.Name != "query_host" ||
		translation.wire.Messages[0].ToolCalls[0].ID != "call-1" ||
		translation.wire.Messages[1].ToolCallID != "call-1" || translation.wire.Messages[1].Content == "" {
		t.Fatalf("messages=%+v", translation.wire.Messages)
	}
}

func TestToolsAndStructuredGrammarCannotSilentlyCompete(t *testing.T) {
	rig := newTestRig(t)
	request := rig.request.Value()
	strict := true
	request.OutputConstraint = providercontract.OutputConstraint{Kind: "json_schema", Name: "verdict",
		SchemaDigest: testDigest("c"), Strict: &strict}
	_, err := rig.adapter.translateRequest(context.Background(), request)
	if Code(err) != providercontract.Unsupported || Reason(err) != "tools_with_structured_output" {
		t.Fatalf("err=%v", err)
	}
}
