package ollama

import (
	"context"
	"net/http"
	"testing"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestInvokeUsesNativeSurfaceAndPreservesOutput(t *testing.T) {
	rig := newTestRig(t)
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	value := response.Value()
	if value.Outcome != "succeeded" || value.Provider.ModelRevision != testDigest("a") || value.Usage.InputTokens != 100 ||
		value.Usage.OutputTokens != 20 || value.Usage.TotalTokens != 120 || len(value.Items) != 3 ||
		value.Items[0].Kind != "text" || value.Items[1].Kind != "reasoning_ref" || value.Items[2].Kind != "tool_call" ||
		value.Items[2].CallID != "ollama:0198e300-3000-7000-8000-000000000003:0" {
		t.Fatalf("response=%+v", value)
	}
	expected := []string{routeKey(http.MethodGet, VersionPath), routeKey(http.MethodGet, TagsPath),
		routeKey(http.MethodPost, ShowPath), routeKey(http.MethodPost, ChatPath)}
	if len(rig.http.requests) != len(expected) {
		t.Fatalf("requests=%d", len(rig.http.requests))
	}
	for index, request := range rig.http.requests {
		if routeKey(request.Method, request.URL.Path) != expected[index] || request.URL.Host != "127.0.0.1:11434" ||
			request.Header.Get("Authorization") != "" {
			t.Fatalf("request[%d]=%s %s", index, request.Method, request.URL)
		}
	}
	var chat chatRequest
	if err := decodeExact(rig.http.bodies[3], &chat); err != nil {
		t.Fatal(err)
	}
	if chat.Model != "qwen3:8b" || chat.Stream || !chat.Think || chat.KeepAlive != 0 || chat.Options.ContextLength != 32768 ||
		chat.Options.MaximumPredict != 1024 || chat.Options.Seed != 7 || len(chat.Tools) != 1 || len(chat.Messages) != 1 {
		t.Fatalf("chat=%+v", chat)
	}
}

func TestIdentityDriftDeniesChatDispatch(t *testing.T) {
	rig := newTestRig(t)
	rig.http.responses[routeKey(http.MethodGet, TagsPath)] = routeResponse{status: http.StatusOK,
		body: []byte(`{"models":[{"name":"qwen3:8b","model":"qwen3:8b","modified_at":"2026-08-20T10:00:00Z","size":1,"digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","details":{"format":"gguf","family":"qwen3","families":["qwen3"],"parameter_size":"8.2B","quantization_level":"Q4_K_M"}}]}`)}
	_, err := rig.adapter.Invoke(context.Background(), rig.request)
	if Code(err) != providercontract.Denied || Reason(err) != "observed_identity_drift" || len(rig.http.requests) != 3 {
		t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
	}
}
