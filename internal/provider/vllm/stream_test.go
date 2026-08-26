package vllm

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestStreamReducesBoundedSSE(t *testing.T) {
	rig := newTestRig(t)
	rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
		body: readFixture(t, "completed-stream.sse"), contentType: "text/event-stream"}
	events := collectStream(t, rig.adapter, context.Background(), rig.request)
	if len(events) != 6 {
		t.Fatalf("events=%d", len(events))
	}
	for sequence, event := range events {
		if event.Value().Sequence != uint64(sequence) {
			t.Fatalf("event[%d]=%+v", sequence, event.Value())
		}
	}
	terminal := events[5].Value()
	if events[0].Value().Kind != "text_delta" || events[1].Value().Kind != "text_delta" ||
		terminal.Kind != "completed" || terminal.Response == nil || terminal.Response.Usage.TotalTokens != 120 ||
		len(terminal.Response.Items) != 3 {
		t.Fatalf("events=%+v", events)
	}
	var request chatRequest
	if err := decodeExact(rig.http.bodies[4], &request); err != nil || !request.Stream ||
		request.StreamOptions == nil || !request.StreamOptions.IncludeUsage {
		t.Fatalf("request=%+v err=%v", request, err)
	}
}

func TestStreamFailsClosedOnMalformedCorrelationAndTruncation(t *testing.T) {
	fixture := string(readFixture(t, "completed-stream.sse"))
	tests := []struct {
		name string
		body string
		code providercontract.ErrorCode
	}{
		{"unknown field", strings.Replace(fixture, `"choices":[`, `"unknown":true,"choices":[`, 1), providercontract.InvalidInput},
		{"model drift", strings.Replace(fixture, `"qwen3-8b-coh"`, `"other-model"`, 1), providercontract.Denied},
		{"id drift", strings.Replace(fixture, `chatcmpl-fixture-stream`, `chatcmpl-other`, 1), providercontract.Denied},
		{"unframed", strings.Replace(fixture, "data: ", "event: ", 1), providercontract.InvalidInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newTestRig(t)
			rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
				body: []byte(test.body), contentType: "text/event-stream"}
			if err := rig.adapter.Stream(context.Background(), rig.request,
				func(providercontract.ValidatedStreamEvent) error { return nil }); Code(err) != test.code {
				t.Fatalf("err=%v code=%s", err, Code(err))
			}
		})
	}
	t.Run("missing done", func(t *testing.T) {
		rig := newTestRig(t)
		cut := strings.LastIndex(fixture, "data: [DONE]")
		rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
			body: []byte(fixture[:cut]), contentType: "text/event-stream"}
		events := collectStream(t, rig.adapter, context.Background(), rig.request)
		terminal := events[len(events)-1].Value()
		if terminal.Kind != "error" || terminal.Error == nil || terminal.Error.Reason != "stream_terminal_missing" {
			t.Fatalf("terminal=%+v", terminal)
		}
	})
}

func TestStreamEmitsRedactedTerminalErrors(t *testing.T) {
	t.Run("outage", func(t *testing.T) {
		rig := newTestRig(t)
		rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusServiceUnavailable,
			body: []byte(`{"error":"secret-token"}`)}
		events := collectStream(t, rig.adapter, context.Background(), rig.request)
		terminal := events[len(events)-1].Value()
		if terminal.Error == nil || terminal.Error.Code != "unavailable" || terminal.Error.Reason != "vendor_unavailable" ||
			strings.Contains(terminal.Error.Message, "secret-token") {
			t.Fatalf("terminal=%+v", terminal)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		rig := newTestRig(t)
		rig.http.blockPath = ChatPath
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		events := collectStream(t, rig.adapter, ctx, rig.request)
		terminal := events[len(events)-1].Value()
		if terminal.Error == nil || terminal.Error.Code != "timeout" || terminal.Error.Reason != "request_timeout" {
			t.Fatalf("terminal=%+v", terminal)
		}
	})
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
