package ollama

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestStreamReducesNativeNDJSON(t *testing.T) {
	rig := newTestRig(t)
	rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
		body: readFixture(t, "completed-stream.ndjson"), contentType: "application/x-ndjson"}
	events := collectStream(t, rig.adapter, context.Background(), rig.request)
	if len(events) != 6 {
		t.Fatalf("events=%d", len(events))
	}
	for sequence, event := range events {
		if event.Value().Sequence != uint64(sequence) {
			t.Fatalf("event[%d]=%+v", sequence, event.Value())
		}
	}
	if events[0].Value().Kind != "text_delta" || events[1].Value().Kind != "text_delta" ||
		events[5].Value().Kind != "completed" || events[5].Value().Response == nil ||
		events[5].Value().Response.Usage.TotalTokens != 120 || len(events[5].Value().Response.Items) != 3 {
		t.Fatalf("events=%+v", events)
	}
	var request chatRequest
	if err := decodeExact(rig.http.bodies[3], &request); err != nil || !request.Stream {
		t.Fatalf("request=%+v err=%v", request, err)
	}
}

func TestStreamFailsClosedOnMalformedDriftAndMissingTerminal(t *testing.T) {
	fixture := string(readFixture(t, "completed-stream.ndjson"))
	tests := []struct {
		name string
		body string
		code providercontract.ErrorCode
	}{
		{"unknown field", strings.Replace(fixture, `"done":false`, `"unknown":true,"done":false`, 1), providercontract.InvalidInput},
		{"model drift", strings.Replace(fixture, `"qwen3:8b"`, `"other:8b"`, 1), providercontract.Denied},
		{"time disorder", strings.Replace(fixture, "06:10:00.300Z", "06:09:00.300Z", 1), providercontract.Denied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newTestRig(t)
			rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
				body: []byte(test.body), contentType: "application/x-ndjson"}
			if err := rig.adapter.Stream(context.Background(), rig.request, func(providercontract.ValidatedStreamEvent) error { return nil }); Code(err) != test.code {
				t.Fatalf("err=%v code=%s", err, Code(err))
			}
		})
	}
	t.Run("missing terminal", func(t *testing.T) {
		rig := newTestRig(t)
		cut := strings.LastIndex(strings.TrimSpace(fixture), "\n")
		rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
			body: []byte(fixture[:cut+1]), contentType: "application/x-ndjson"}
		events := collectStream(t, rig.adapter, context.Background(), rig.request)
		terminal := events[len(events)-1].Value()
		if terminal.Kind != "error" || terminal.Error == nil || terminal.Error.Reason != "stream_terminal_missing" {
			t.Fatalf("terminal=%+v", terminal)
		}
	})
}

func TestStreamEmitsTerminalErrorsForOutageAndTimeout(t *testing.T) {
	t.Run("outage", func(t *testing.T) {
		rig := newTestRig(t)
		rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusServiceUnavailable,
			body: []byte(`{"error":"sensitive"}`)}
		events := collectStream(t, rig.adapter, context.Background(), rig.request)
		terminal := events[len(events)-1].Value()
		if terminal.Error == nil || terminal.Error.Code != "unavailable" || terminal.Error.Reason != "vendor_unavailable" {
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
