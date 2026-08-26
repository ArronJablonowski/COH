package codexruntime

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestAppServerBridgeUsesPinnedEphemeralBrokerToolSurface(t *testing.T) {
	rig := newRig(t)
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	value := response.Value()
	if value.Outcome != "succeeded" || value.Usage.TotalTokens != 120 || value.Usage.CachedInputTokens != 20 || value.Usage.ReasoningTokens != 5 || len(value.Items) != 4 || value.Items[0].Kind != "text" || value.Items[1].Kind != "tool_call" || value.Items[2].Kind != "tool_result" || value.Items[3].Kind != "reasoning_ref" {
		t.Fatalf("response=%+v", value)
	}
	if len(rig.tools.calls) != 1 || rig.tools.calls[0].Name != "query_host" {
		t.Fatalf("calls=%+v", rig.tools.calls)
	}
	methods := []string{}
	for _, document := range rig.transport.sent {
		var envelope struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(document, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Method != "" {
			methods = append(methods, envelope.Method)
		} else {
			methods = append(methods, "response")
		}
	}
	if !reflect.DeepEqual(methods, []string{"initialize", "initialized", "thread/start", "turn/start", "response"}) {
		t.Fatalf("methods=%v", methods)
	}
	var start rpcRequest
	if err := decodeExact(rig.transport.sent[2], &start); err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(start.Params)
	var thread threadStartParams
	if err := decodeExact(params, &thread); err != nil {
		t.Fatal(err)
	}
	if !thread.Ephemeral || thread.Sandbox != "read-only" || thread.ApprovalPolicy != "untrusted" || thread.CWD != "/workspace" || len(thread.DynamicTools) != 1 {
		t.Fatalf("thread=%+v", thread)
	}
}

func TestStreamPreservesDeltasAndTerminalResponse(t *testing.T) {
	rig := newRig(t)
	events := []providercontract.ValidatedStreamEvent{}
	if err := rig.adapter.Stream(context.Background(), rig.request, func(value providercontract.ValidatedStreamEvent) error { events = append(events, value); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 || events[0].Value().Kind != "text_delta" || events[5].Value().Kind != "completed" || events[5].Value().Response == nil {
		t.Fatalf("events=%+v", events)
	}
}

func TestBatchFallbackIsExplicitBoundedAndNeverAutomatic(t *testing.T) {
	rig := newRig(t)
	request := rig.request.Value()
	request.Provider = testProvider("codex-exec")
	capability, err := DiscoverCapability(context.Background(), CapabilityDefinition{SnapshotID: "0199a213-81c0-7800-8aa1-bbab2a035a50", ObservedAt: mustTime(t, "2026-08-26T15:00:00.000000000Z"), ValidUntil: mustTime(t, "2026-08-27T15:00:00.000000000Z"), Provider: request.Provider, Limits: rig.adapter.Capability().Value().Limits})
	if err != nil {
		t.Fatal(err)
	}
	request.CapabilityDigest = capability.Digest()
	request.Tools = []providercontract.Tool{}
	rig.adapter.config.Capability = capability
	rig.adapter.config.Qualifications = qualifiedRegistry(t, capability, rig.clock)
	validated := decodeRequest(t, request)
	response, err := rig.adapter.Invoke(context.Background(), validated)
	if err != nil {
		t.Fatal(err)
	}
	if response.Value().Items[0].Text != "Batch complete." {
		t.Fatalf("response=%+v", response.Value())
	}
	wanted := []string{"codex", "exec", "--json", "--ephemeral", "--ignore-user-config", "--strict-config", "--sandbox", "read-only", "--cd", "/workspace", "--model", "gpt-5.6-terra", "-"}
	if !reflect.DeepEqual(rig.batch.invocation.Argv, wanted) || len(rig.batch.invocation.Environment) != 0 || rig.batch.invocation.WorkingDirectory != "/workspace" {
		t.Fatalf("invocation=%+v", rig.batch.invocation)
	}
}

func TestBatchFallbackRejectsToolsInsteadOfChangingRoute(t *testing.T) {
	rig := newRig(t)
	request := rig.request.Value()
	request.Provider = testProvider("codex-exec")
	capability, err := DiscoverCapability(context.Background(), CapabilityDefinition{SnapshotID: "0199a213-81c0-7800-8aa1-bbab2a035a50", ObservedAt: mustTime(t, "2026-08-26T15:00:00.000000000Z"), ValidUntil: mustTime(t, "2026-08-27T15:00:00.000000000Z"), Provider: request.Provider, Limits: rig.adapter.Capability().Value().Limits})
	if err != nil {
		t.Fatal(err)
	}
	request.CapabilityDigest = capability.Digest()
	rig.adapter.config.Capability = capability
	rig.adapter.config.Qualifications = qualifiedRegistry(t, capability, rig.clock)
	_, err = rig.adapter.Invoke(context.Background(), decodeRequest(t, request))
	if Code(err) != providercontract.Unsupported || Reason(err) != "batch_tools_not_supported" || len(rig.transport.sent) != 0 {
		t.Fatalf("err=%v sent=%d", err, len(rig.transport.sent))
	}
}
