package openairesponses

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestStreamReducesTypedEventsWithExactOrdering(t *testing.T) {
	rig := newTestRig(t, "completed-response.json")
	rig.http.body = readFixture(t, "completed-stream.sse")
	rig.http.contentType = "text/event-stream; charset=utf-8"
	events := make([]providercontract.ValidatedStreamEvent, 0, 5)
	err := rig.adapter.Stream(context.Background(), rig.request, func(event providercontract.ValidatedStreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	validator := &providercontract.StreamValidator{}
	for index, event := range events {
		if event.Value().Sequence != uint64(index) {
			t.Fatalf("event %d sequence=%d", index, event.Value().Sequence)
		}
		if err := validator.Apply(event); err != nil {
			t.Fatal(err)
		}
	}
	if !validator.Complete() || len(events) != 5 || events[0].Value().Item.Kind != "reasoning_ref" ||
		events[1].Value().Kind != "text_delta" || events[1].Value().TextDelta != "Ready." ||
		events[2].Value().Item.Kind != "text" || events[3].Value().Item.Kind != "tool_call" ||
		events[4].Value().Kind != "completed" || events[4].Value().Response.Outcome != "succeeded" {
		t.Fatalf("events=%+v complete=%v", events, validator.Complete())
	}
	var outbound createRequest
	if err := json.Unmarshal(rig.http.requestBody, &outbound); err != nil || !outbound.Stream ||
		rig.http.request.Header.Get("Accept") != "text/event-stream" {
		t.Fatalf("outbound=%+v err=%v", outbound, err)
	}
}

func TestStreamFailsClosedOnSequenceCorrelationAndTerminalTamper(t *testing.T) {
	fixture := string(readFixture(t, "completed-stream.sse"))
	tests := []struct {
		name   string
		mutate func(string) string
		code   providercontract.ErrorCode
	}{
		{"sequence gap", func(value string) string {
			return strings.Replace(value, `"delta":"Ready.","logprobs":[],"sequence_number":9`,
				`"delta":"Ready.","logprobs":[],"sequence_number":10`, 1)
		}, providercontract.Conflict},
		{"argument tamper", func(value string) string {
			return strings.Replace(value, `"arguments":"{\"host\":\"example.invalid\"}","sequence_number":15`,
				`"arguments":"{\"host\":\"changed.invalid\"}","sequence_number":15`, 1)
		}, providercontract.Conflict},
		{"terminal output tamper", func(value string) string {
			marker := `"text":"Ready.","annotations":[]}]},{"id":"fc_coh_stream_001"`
			return strings.Replace(value, marker, `"text":"Changed.","annotations":[]}]},{"id":"fc_coh_stream_001"`, 1)
		}, providercontract.Conflict},
		{"unknown event", func(value string) string {
			return strings.Replace(value, "response.output_text.delta", "response.audio.delta", 2)
		}, providercontract.Unsupported},
		{"early done", func(string) string { return "data: [DONE]\n\n" }, providercontract.Conflict},
		{"missing terminal", func(value string) string {
			return value[:strings.Index(value, "event: response.completed")]
		}, providercontract.Unavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newTestRig(t, "completed-response.json")
			rig.http.body = []byte(test.mutate(fixture))
			rig.http.contentType = "text/event-stream"
			err := rig.adapter.Stream(context.Background(), rig.request, func(providercontract.ValidatedStreamEvent) error { return nil })
			if Code(err) != test.code {
				t.Fatalf("code=%s err=%v", Code(err), err)
			}
		})
	}
}

func TestStreamStopsWhenEmitterFails(t *testing.T) {
	rig := newTestRig(t, "completed-response.json")
	rig.http.body = readFixture(t, "completed-stream.sse")
	rig.http.contentType = "text/event-stream"
	err := rig.adapter.Stream(context.Background(), rig.request, func(providercontract.ValidatedStreamEvent) error {
		return errors.New("sink failed")
	})
	if Code(err) != providercontract.Unavailable || Reason(err) != "stream_emitter_failed" {
		t.Fatalf("err=%v", err)
	}
}
