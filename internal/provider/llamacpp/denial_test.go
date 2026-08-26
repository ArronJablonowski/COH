package llamacpp

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestResponseSurfaceFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
		code   providercontract.ErrorCode
	}{
		{"unknown field", func(value string) string {
			return strings.Replace(value, `"choices": [`, `"unknown": true, "choices": [`, 1)
		}, providercontract.InvalidInput},
		{"model drift", func(value string) string { return strings.Replace(value, `"qwen3-8b-coh"`, `"other-model"`, 1) }, providercontract.Denied},
		{"fingerprint drift", func(value string) string { return strings.Replace(value, `"b7000-5d5cb4c3"`, `"b7001-5d5cb4c3"`, 1) }, providercontract.Denied},
		{"unknown finish reason", func(value string) string {
			return strings.Replace(value, `"finish_reason": "tool_calls"`, `"finish_reason": "evicted"`, 1)
		}, providercontract.Unsupported},
		{"usage over limit", func(value string) string {
			return strings.Replace(value, `"completion_tokens": 20`, `"completion_tokens": 9000`, 1)
		}, providercontract.Denied},
		{"tool name tamper", func(value string) string { return strings.Replace(value, `"query_host"`, `"shell"`, 1) }, providercontract.Denied},
		{"log probabilities", func(value string) string {
			return strings.Replace(value, `"finish_reason": "tool_calls"`, `"finish_reason": "tool_calls", "logprobs": {}`, 1)
		}, providercontract.Denied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newTestRig(t)
			rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
				body: []byte(test.mutate(string(readFixture(t, "completed-chat.json"))))}
			if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != test.code {
				t.Fatalf("err=%v code=%s", err, Code(err))
			}
		})
	}
}

func TestHTTPStatusMappingIsTypedAndRedacted(t *testing.T) {
	tests := []struct {
		status    int
		code      providercontract.ErrorCode
		retryable bool
	}{
		{http.StatusBadRequest, providercontract.InvalidInput, false},
		{http.StatusRequestEntityTooLarge, providercontract.InvalidInput, false},
		{http.StatusUnprocessableEntity, providercontract.InvalidInput, false},
		{http.StatusUnauthorized, providercontract.Denied, false},
		{http.StatusForbidden, providercontract.Denied, false},
		{http.StatusNotFound, providercontract.Unsupported, false},
		{http.StatusRequestTimeout, providercontract.Timeout, true},
		{http.StatusGatewayTimeout, providercontract.Timeout, true},
		{http.StatusConflict, providercontract.Conflict, false},
		{http.StatusTooManyRequests, providercontract.Unavailable, true},
		{http.StatusServiceUnavailable, providercontract.Unavailable, true},
		{http.StatusTeapot, providercontract.Unavailable, false},
	}
	for _, test := range tests {
		rig := newTestRig(t)
		rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: test.status,
			body: []byte(strings.Repeat("sensitive-vendor-detail", 8))}
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != test.code || Retryable(err) != test.retryable || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("status=%d err=%v retryable=%v", test.status, err, Retryable(err))
		}
	}
}

func TestCancellationLimitsAndRecovery(t *testing.T) {
	t.Run("canceled before transport", func(t *testing.T) {
		rig := newTestRig(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := rig.adapter.Invoke(ctx, rig.request); Code(err) != providercontract.Canceled || len(rig.http.requests) != 0 {
			t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
		}
	})
	t.Run("canceled during chat", func(t *testing.T) {
		rig := newTestRig(t)
		rig.http.blockPath = ChatPath
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(10*time.Millisecond, cancel)
		defer timer.Stop()
		if _, err := rig.adapter.Invoke(ctx, rig.request); Code(err) != providercontract.Canceled ||
			Reason(err) != "request_canceled" || len(rig.http.requests) != 4 {
			t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
		}
	})
	t.Run("token counter failure", func(t *testing.T) {
		rig := newTestRig(t)
		rig.adapter.config.Tokens = tokenCounterStub{err: errors.New("offline")}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Unavailable || !Retryable(err) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("expired qualification", func(t *testing.T) {
		rig := newTestRig(t)
		rig.adapter.config.Clock = func() time.Time { return mustTime(t, "2026-10-01T06:10:00.000000000Z") }
		request := rig.request.Value()
		request.Deadline = "2026-10-02T06:10:00.000000000Z"
		_, err := rig.adapter.Invoke(context.Background(), decodeRequest(t, request))
		if Code(err) != providercontract.Unsupported || Reason(err) != "qualification_expired" || len(rig.http.requests) != 0 {
			t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
		}
	})
	t.Run("context limit", func(t *testing.T) {
		rig := newTestRig(t)
		rig.adapter.config.Tokens = tokenCounterStub{count: 32768}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Denied ||
			Reason(err) != "context_limit" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("local route attestation", func(t *testing.T) {
		rig := newTestRig(t)
		rig.adapter.config.Route = routeVerifierStub{err: errors.New("cloud mode enabled")}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Denied ||
			Reason(err) != "local_route_attestation_failed" || strings.Contains(err.Error(), "cloud mode") ||
			len(rig.http.requests) != 3 {
			t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
		}
	})
	t.Run("outage recovery", func(t *testing.T) {
		rig := newTestRig(t)
		rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusServiceUnavailable}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Unavailable {
			t.Fatalf("err=%v", err)
		}
		rig.http.responses[routeKey(http.MethodPost, ChatPath)] = routeResponse{status: http.StatusOK,
			body: readFixture(t, "completed-chat.json")}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRuntimePropertiesFailClosed(t *testing.T) {
	tests := []struct {
		name, old, replacement string
		requests               int
	}{
		{"context drift", `"n_ctx": 32768`, `"n_ctx": 16384`, 3},
		{"template capability", `"supports_tool_calls": true`, `"supports_tool_calls": false`, 2},
		{"sleeping runtime", `"is_sleeping": false`, `"is_sleeping": true`, 2},
		{"build syntax", `"b7000-5d5cb4c3"`, `"floating-main"`, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newTestRig(t)
			rig.http.responses[routeKey(http.MethodGet, PropertiesPath)] = routeResponse{status: http.StatusOK,
				body: []byte(strings.Replace(string(readFixture(t, "properties.json")), test.old, test.replacement, 1))}
			_, err := rig.adapter.Invoke(context.Background(), rig.request)
			if Code(err) != providercontract.Denied && Code(err) != providercontract.InvalidInput ||
				len(rig.http.requests) != test.requests {
				t.Fatalf("err=%v requests=%d", err, len(rig.http.requests))
			}
		})
	}
}

func TestConfigurationAndLoopbackTransportDenyRouteExpansion(t *testing.T) {
	rig := newTestRig(t)
	tests := []func(*Config){
		func(config *Config) { config.Endpoint = "http://localhost:8080" },
		func(config *Config) { config.Endpoint = "https://llama.example" },
		func(config *Config) { config.HTTP = nil },
		func(config *Config) { config.Schemas = nil },
		func(config *Config) { config.Route = nil },
	}
	for index, mutate := range tests {
		config := rig.adapter.config
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatalf("configuration case %d accepted", index)
		}
	}
	client, err := NewLoopbackHTTPClient(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression || transport.ForceAttemptHTTP2 || client.CheckRedirect == nil {
		t.Fatalf("client=%+v", client)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1", nil)
	redirect, _ := http.NewRequest(http.MethodGet, "http://elsewhere.invalid", nil)
	if client.CheckRedirect(redirect, []*http.Request{request}) != http.ErrUseLastResponse {
		t.Fatal("redirect was not denied")
	}
	if reflect.TypeOf(Config{}).NumField() != 9 {
		t.Fatal("configuration surface changed")
	}
}
