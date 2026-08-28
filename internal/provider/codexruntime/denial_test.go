package codexruntime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestRuntimeAttestationAndRouteMismatchFailBeforeHandshake(t *testing.T) {
	for _, mutate := range []func(*LaunchObservation){func(o *LaunchObservation) { o.RuntimeDigest = testDigest("f") }, func(o *LaunchObservation) { o.ProtocolDigest = testDigest("f") }, func(o *LaunchObservation) { o.Model = "rerouted" }, func(o *LaunchObservation) { o.NetworkMode = "restricted_connected" }, func(o *LaunchObservation) { o.Sandbox = "workspace-write" }, func(o *LaunchObservation) { o.CredentialMode = "ambient" }, func(o *LaunchObservation) { o.ExperimentalSurface = "all" }, func(o *LaunchObservation) { o.CodexHome = "relative" }, func(o *LaunchObservation) { o.ConfigMode = "user" }, func(o *LaunchObservation) { o.RulesMode = "enabled" }, func(o *LaunchObservation) { o.HooksMode = "enabled" }, func(o *LaunchObservation) { o.MCPMode = "native" }, func(o *LaunchObservation) { o.WebSearchMode = "enabled" }, func(o *LaunchObservation) { o.MutationMode = "enabled" }, func(o *LaunchObservation) { o.EnvironmentMode = "inherit" }} {
		rig := newRig(t)
		factory := rig.adapter.config.Factory.(factoryStub)
		mutate(&factory.observation)
		rig.adapter.config.Factory = factory
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Denied || Reason(err) != "runtime_attestation_failed" || len(rig.transport.sent) != 0 {
			t.Fatalf("err=%v sent=%d observation=%+v", err, len(rig.transport.sent), factory.observation)
		}
	}
}

func TestInitializedCodexHomeMustMatchAttestedHome(t *testing.T) {
	rig := newRig(t)
	rig.transport.incoming[0] = []byte(strings.Replace(string(rig.transport.incoming[0]), "/managed/codex-home", "/different/codex-home", 1))
	_, err := rig.adapter.Invoke(context.Background(), rig.request)
	if Code(err) != providercontract.Denied || Reason(err) != "initialize_identity_invalid" {
		t.Fatalf("err=%v", err)
	}
}

func TestUnsupportedSamplingFailsBeforeLaunch(t *testing.T) {
	for _, mutate := range []func(*providercontract.InferenceRequest){func(r *providercontract.InferenceRequest) { r.Sampling.TemperatureMilli = 1 }, func(r *providercontract.InferenceRequest) { r.Sampling.TopPMillionths = 999999 }, func(r *providercontract.InferenceRequest) { r.Sampling.Seed = 1 }} {
		rig := newRig(t)
		request := rig.request.Value()
		mutate(&request)
		_, err := rig.adapter.Invoke(context.Background(), decodeRequest(t, request))
		if Code(err) != providercontract.Unsupported || Reason(err) != "sampling_profile" || len(rig.transport.sent) != 0 {
			t.Fatalf("err=%v sent=%d", err, len(rig.transport.sent))
		}
	}
}

func TestUsageBoundsFailClosed(t *testing.T) {
	rig := newRig(t)
	for index, line := range rig.transport.incoming {
		if strings.Contains(string(line), "thread/tokenUsage/updated") {
			rig.transport.incoming[index] = []byte(strings.NewReplacer(`"outputTokens":20`, `"outputTokens":2048`, `"totalTokens":120`, `"totalTokens":2148`).Replace(string(line)))
		}
	}
	_, err := rig.adapter.Invoke(context.Background(), rig.request)
	if Code(err) != providercontract.Denied || Reason(err) != "usage_limit_exceeded" {
		t.Fatalf("err=%v", err)
	}
}

func TestTraceOverflowFailsClosed(t *testing.T) {
	state := &runState{}
	state.addTrace('S', bytes.Repeat([]byte("x"), maximumTraceBytes))
	if !state.traceOverflow || state.trace.Len() != 0 {
		t.Fatalf("overflow=%v trace=%d", state.traceOverflow, state.trace.Len())
	}
}

func TestToolResultDigestMismatchFailsClosed(t *testing.T) {
	rig := newRig(t)
	rig.tools.result.ResultDigest = testDigest("f")
	_, err := rig.adapter.Invoke(context.Background(), rig.request)
	if Code(err) != providercontract.Denied || Reason(err) != "tool_result_digest" {
		t.Fatalf("err=%v", err)
	}
}

func TestBrokerDenialIsReturnedAsTypedToolResult(t *testing.T) {
	rig := newRig(t)
	rig.tools.result.Outcome = "denied"
	rig.transport.incoming[10] = []byte(strings.Replace(string(rig.transport.incoming[10]), `"success":true`, `"success":false`, 1))
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil {
		t.Fatal(err)
	}
	items := response.Value().Items
	if len(items) != 4 || items[2].Kind != "tool_result" || items[2].Outcome != "denied" || items[2].ResultDigest != rig.tools.result.ResultDigest {
		t.Fatalf("items=%+v", items)
	}
	if !strings.Contains(string(rig.transport.sent[len(rig.transport.sent)-1]), `"success":false`) {
		t.Fatalf("broker response=%s", rig.transport.sent[len(rig.transport.sent)-1])
	}
}

func TestDynamicToolLifecycleFailsClosed(t *testing.T) {
	t.Run("request without start", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming = append(rig.transport.incoming[:8], rig.transport.incoming[9:]...)
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Conflict || Reason(err) != "tool_call_lifecycle" || len(rig.tools.calls) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(rig.tools.calls))
		}
	})
	t.Run("argument drift", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming[9] = []byte(strings.Replace(string(rig.transport.incoming[9]), `"host":"srv-1"`, `"host":"srv-2"`, 1))
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Conflict || Reason(err) != "tool_call_lifecycle" || len(rig.tools.calls) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(rig.tools.calls))
		}
	})
	t.Run("completion without broker request", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming = append(rig.transport.incoming[:9], rig.transport.incoming[10:]...)
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Denied || Reason(err) != "dynamic_tool_item_invalid" || len(rig.tools.calls) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(rig.tools.calls))
		}
	})
}

func TestUnknownFieldsReroutesAndNativeToolsFailClosed(t *testing.T) {
	t.Run("unknown field", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming[0] = []byte(strings.Replace(string(rig.transport.incoming[0]), `"result":{`, `"unknown":true,"result":{`, 1))
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.InvalidInput {
			t.Fatalf("err=%v", err)
		}
		if !strings.HasPrefix(Provenance(err), "sha256:") || strings.Contains(err.Error(), "codexHome") || strings.Contains(err.Error(), "Host is clean") {
			t.Fatalf("unprovenanced or unredacted error: %v provenance=%s", err, Provenance(err))
		}
	})
	t.Run("model reroute", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming[4] = []byte(`{"method":"model/rerouted","params":{"threadId":"0199a213-81c0-7800-8aa1-bbab2a035a53","turnId":"0199a213-81c0-7800-8aa1-bbab2a035a54","fromModel":"gpt-5.6-terra","toModel":"other","reason":"capacity"}}`)
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Denied || Reason(err) != "model_rerouted" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("native command", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming[4] = []byte(`{"method":"item/commandExecution/requestApproval","id":77,"params":{"threadId":"0199a213-81c0-7800-8aa1-bbab2a035a53","turnId":"0199a213-81c0-7800-8aa1-bbab2a035a54","itemId":"cmd-1"}}`)
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Denied || Reason(err) != "native_tool_not_authorized" {
			t.Fatalf("err=%v", err)
		}
		if !strings.Contains(string(rig.transport.sent[len(rig.transport.sent)-1]), `"decision":"cancel"`) {
			t.Fatalf("response=%s", rig.transport.sent[len(rig.transport.sent)-1])
		}
	})
}

func TestFailedTurnAndLostConnectionPreserveTraceProvenance(t *testing.T) {
	t.Run("failed turn", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming[13] = []byte(strings.NewReplacer(`"status":"completed"`, `"status":"failed"`, `"error":null`, `"error":{"message":"vendor secret omitted"}`).Replace(string(rig.transport.incoming[13])))
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Unavailable || Reason(err) != "turn_failed" || !strings.HasPrefix(Provenance(err), "sha256:") || strings.Contains(err.Error(), "vendor secret") {
			t.Fatalf("err=%v provenance=%s", err, Provenance(err))
		}
	})
	t.Run("lost connection", func(t *testing.T) {
		rig := newRig(t)
		rig.transport.incoming = rig.transport.incoming[:4]
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Unavailable || Reason(err) != "rpc_disconnected" || !strings.HasPrefix(Provenance(err), "sha256:") {
			t.Fatalf("err=%v provenance=%s", err, Provenance(err))
		}
	})
}

func TestExpiredQualificationFailsBeforeLaunch(t *testing.T) {
	rig := newRig(t)
	rig.adapter.config.Clock = func() time.Time { return mustTime(t, "2026-10-01T15:40:00.000000000Z") }
	request := rig.request.Value()
	request.Deadline = "2026-10-01T15:50:00.000000000Z"
	_, err := rig.adapter.Invoke(context.Background(), decodeRequest(t, request))
	if Code(err) != providercontract.Unsupported || Reason(err) != "qualification_expired" || len(rig.transport.sent) != 0 {
		t.Fatalf("err=%v sent=%d", err, len(rig.transport.sent))
	}
}

func TestExecParserRejectsMalformedAndMissingTerminalStreams(t *testing.T) {
	for name, input := range map[string][]byte{
		"unknown event":             []byte(`{"type":"thread.started","thread_id":"thread-1"}` + "\n" + `{"type":"vendor.extension"}`),
		"missing terminal":          []byte(`{"type":"thread.started","thread_id":"thread-1"}` + "\n" + `{"type":"turn.started"}`),
		"native command":            []byte(`{"type":"thread.started","thread_id":"thread-1"}` + "\n" + `{"type":"turn.started"}` + "\n" + `{"type":"item.completed","item":{"id":"cmd-1","type":"command_execution","command":"id","status":"completed"}}`),
		"cache write exceeds input": []byte(`{"type":"thread.started","thread_id":"thread-1"}` + "\n" + `{"type":"turn.started"}` + "\n" + `{"type":"item.completed","item":{"id":"msg-1","type":"agent_message","text":"done"}}` + "\n" + `{"type":"turn.completed","usage":{"input_tokens":2,"cached_input_tokens":0,"cache_write_input_tokens":3,"output_tokens":1,"reasoning_output_tokens":0}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseExecJSONL(input); err == nil {
				t.Fatal("unsafe exec stream accepted")
			}
		})
	}
}

func TestExecParserPreservesMalformedVendorJSONReason(t *testing.T) {
	_, _, err := parseExecJSONL([]byte(`{"type":"thread.started","thread_id":}`))
	if Code(err) != providercontract.InvalidInput || Reason(err) != "vendor_document_malformed" {
		t.Fatalf("err=%v", err)
	}
}

func TestExecParserAcceptsProgressMessagesAndReturnsLastAgentMessage(t *testing.T) {
	input := []byte(`{"type":"thread.started","thread_id":"thread-1"}` + "\n" +
		`{"type":"turn.started"}` + "\n" +
		`{"type":"item.completed","item":{"id":"msg-1","type":"agent_message","text":"Working."}}` + "\n" +
		`{"type":"item.completed","item":{"id":"msg-2","type":"agent_message","text":"FINAL: B"}}` + "\n" +
		`{"type":"turn.completed","usage":{"input_tokens":2,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}}`)
	text, _, err := parseExecJSONL(input)
	if err != nil || text != "FINAL: B" {
		t.Fatalf("text=%q err=%v", text, err)
	}
}

func TestCancellationInterruptsExactTurnAndDoesNotFallback(t *testing.T) {
	rig := newRig(t)
	rig.transport.incoming = rig.transport.incoming[:4]
	rig.transport.block = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	events := []providercontract.ValidatedStreamEvent{}
	if err := rig.adapter.Stream(ctx, rig.request, func(event providercontract.ValidatedStreamEvent) error { events = append(events, event); return nil }); err != nil {
		t.Fatal(err)
	}
	terminal := events[len(events)-1].Value()
	if terminal.Kind != "error" || terminal.Error == nil || terminal.Error.Code != "timeout" {
		t.Fatalf("terminal=%+v", terminal)
	}
	found := false
	for _, sent := range rig.transport.sent {
		if strings.Contains(string(sent), `"method":"turn/interrupt"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("turn/interrupt not sent")
	}
	if len(rig.batch.invocation.Argv) != 0 {
		t.Fatal("automatic exec fallback occurred")
	}
}

func TestAppServerLaunchFailureNeverInvokesBatch(t *testing.T) {
	rig := newRig(t)
	rig.adapter.config.Factory = factoryStub{err: errors.New("offline")}
	_, err := rig.adapter.Invoke(context.Background(), rig.request)
	if Code(err) != providercontract.Unavailable || Reason(err) != "app_server_launch_failed" || len(rig.batch.invocation.Argv) != 0 {
		t.Fatalf("err=%v invocation=%+v", err, rig.batch.invocation)
	}
}

type recoveryFactory struct {
	calls       int
	transport   *transportStub
	observation LaunchObservation
}

func (f *recoveryFactory) Open(context.Context) (RPCTransport, LaunchObservation, error) {
	f.calls++
	if f.calls == 1 {
		return nil, LaunchObservation{}, errors.New("offline")
	}
	return f.transport, f.observation, nil
}

func TestIndependentRetryRecoversWithoutFallbackOrStateReuse(t *testing.T) {
	rig := newRig(t)
	factory := &recoveryFactory{transport: rig.transport, observation: testObservation("stdio", rig.request.Value().Provider)}
	rig.adapter.config.Factory = factory
	if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Unavailable || Reason(err) != "app_server_launch_failed" {
		t.Fatalf("first err=%v", err)
	}
	response, err := rig.adapter.Invoke(context.Background(), rig.request)
	if err != nil || response.Value().Outcome != "succeeded" || factory.calls != 2 || len(rig.batch.invocation.Argv) != 0 {
		t.Fatalf("second err=%v response=%+v calls=%d batch=%+v", err, response.Value(), factory.calls, rig.batch.invocation)
	}
}

func TestConfigurationHasNoGenericCredentialOrPassthrough(t *testing.T) {
	rig := newRig(t)
	config := rig.adapter.config
	config.Workspace = "relative"
	if _, err := New(config); err == nil {
		t.Fatal("relative workspace accepted")
	}
	config = rig.adapter.config
	config.Batch = nil
	if _, err := New(config); err == nil {
		t.Fatal("nil batch runner accepted")
	}
}
