package vllm

import (
	"context"
	"net/http"
	"strings"
	"testing"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestInvokeUsesQualifiedChatCompletionsSurface(t *testing.T) {
	rig := newTestRig(t)
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	value := response.Value()
	if value.Outcome != "succeeded" || value.Provider.ModelRevision != testDigest("a") ||
		value.Usage.InputTokens != 100 || value.Usage.OutputTokens != 20 || value.Usage.TotalTokens != 120 ||
		len(value.Items) != 3 || value.Items[0].Kind != "text" || value.Items[1].Kind != "reasoning_ref" ||
		value.Items[2].Kind != "tool_call" ||
		value.Items[2].CallID != "vllm:0198e300-3000-7000-8000-000000000003:0" {
		t.Fatalf("response=%+v", value)
	}
	expected := []string{routeKey(http.MethodGet, HealthPath), routeKey(http.MethodGet, VersionPath),
		routeKey(http.MethodGet, ModelsPath), routeKey(http.MethodGet, TokenizerInfoPath), routeKey(http.MethodPost, ChatPath)}
	if len(rig.http.requests) != len(expected) {
		t.Fatalf("requests=%d", len(rig.http.requests))
	}
	for index, request := range rig.http.requests {
		if routeKey(request.Method, request.URL.Path) != expected[index] || request.URL.Host != "127.0.0.1:8000" ||
			request.Header.Get("Authorization") != "" || request.Header.Get("X-API-Key") != "" {
			t.Fatalf("request[%d]=%s %s", index, request.Method, request.URL)
		}
	}
	var chat chatRequest
	if err := decodeExact(rig.http.bodies[4], &chat); err != nil {
		t.Fatal(err)
	}
	if chat.Model != "qwen3-8b-coh" || chat.Stream || chat.StreamOptions != nil || chat.N != 1 || chat.Logprobs || !chat.IncludeReasoning ||
		!chat.ParallelToolCalls || chat.ToolChoice != "auto" || chat.MaximumCompletionTokens != 1024 ||
		chat.Seed != 7 || len(chat.Tools) != 1 || len(chat.Messages) != 1 || chat.ResponseFormat != nil {
		t.Fatalf("chat=%+v", chat)
	}
}

func TestIdentityAndRouteDriftDenyBeforeChat(t *testing.T) {
	t.Run("model alias", func(t *testing.T) {
		rig := newTestRig(t)
		rig.http.responses[routeKey(http.MethodGet, ModelsPath)] = routeResponse{status: http.StatusOK,
			body: []byte(strings.Replace(string(readFixture(t, "models.json")), "qwen3-8b-coh", "other-model", 1))}
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Denied || Reason(err) != "model_metadata_invalid" || len(rig.http.requests) != 3 {
			t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
		}
	})
	t.Run("route attestation", func(t *testing.T) {
		rig := newTestRig(t)
		rig.adapter.config.Route = routeVerifierStub{err: context.Canceled}
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Denied || Reason(err) != "local_route_attestation_failed" ||
			len(rig.http.requests) != 4 {
			t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
		}
	})
}

func TestManagedRouteReceivesExactRuntimeModelParserAndGPUBinding(t *testing.T) {
	rig := newTestRig(t)
	capture := &routeVerifierCapture{}
	rig.adapter.config.Route = capture
	if _, err := rig.adapter.Invoke(context.Background(), rig.request); err != nil {
		t.Fatal(err)
	}
	observed := capture.observation
	if observed.Endpoint != VLLMEndpoint || observed.RuntimeVersion != "0.11.0" ||
		observed.ExpectedRuntimeDigest != testDigest("8") || observed.ExpectedImageDigest != testDigest("8") ||
		observed.ModelAlias != "qwen3-8b-coh" || observed.ModelRoot != "/models/Qwen3-8B" ||
		observed.ExpectedModelWeightsDigest != testDigest("a") || observed.ChatTemplateDigest != rig.request.Value().Provider.ChatTemplateDigest ||
		observed.TokenizerDigest != rig.request.Value().Provider.TokenizerDigest ||
		observed.ExpectedToolParserDigest != ToolParserDigest() || observed.ExpectedReasoningParserDigest != ReasoningParserDigest() ||
		observed.ExpectedHardwareProfileDigest != testDigest("9") || observed.RequiredStateMode != "stateless" {
		t.Fatalf("observation=%+v", observed)
	}
}
