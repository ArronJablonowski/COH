package openairesponses

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestInvokeFailsClosedOnVendorShapeIdentityAndToolDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		code   providercontract.ErrorCode
	}{
		{"unknown top-level field", func(value map[string]any) { value["unexpected"] = true }, providercontract.InvalidInput},
		{"model drift", func(value map[string]any) { value["model"] = "different-model" }, providercontract.Denied},
		{"unknown output item", func(value map[string]any) { output(value, 0)["type"] = "hosted_tool_call" }, providercontract.Unsupported},
		{"call ID oversized", func(value map[string]any) { output(value, 2)["call_id"] = strings.Repeat("x", 129) }, providercontract.InvalidInput},
		{"tool not allowed", func(value map[string]any) { output(value, 2)["name"] = "unapproved_tool" }, providercontract.Denied},
		{"background status", func(value map[string]any) { value["status"] = "in_progress" }, providercontract.Conflict},
		{"usage exceeds request", func(value map[string]any) {
			usage := value["usage"].(map[string]any)
			usage["output_tokens"], usage["total_tokens"] = float64(2048), float64(2058)
		}, providercontract.Denied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newTestRig(t, "completed-response.json")
			rig.http.body = mutateFixture(t, rig.http.body, test.mutate)
			if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != test.code {
				t.Fatalf("code=%s err=%v", Code(err), err)
			}
		})
	}
}

func TestInvokeEnforcesTransportCredentialAndQualificationBoundaries(t *testing.T) {
	t.Run("TLS identity", func(t *testing.T) {
		rig := newTestRig(t, "completed-response.json")
		rig.http.tls = &tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true, ServerName: "other.invalid"}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Denied ||
			Reason(err) != "transport_identity_invalid" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("credential resolver redaction", func(t *testing.T) {
		rig := newTestRig(t, "completed-response.json")
		privateValue := strings.Repeat("z", 40)
		rig.adapter.config.Credentials = credentialResolverStub{err: errors.New(privateValue)}
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != providercontract.Unavailable || strings.Contains(err.Error(), privateValue) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("qualification required", func(t *testing.T) {
		rig := newTestRig(t, "completed-response.json")
		rig.adapter.config.Qualifications = providercontract.NewQualificationRegistry()
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Unsupported {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("cancellation before dispatch", func(t *testing.T) {
		rig := newTestRig(t, "completed-response.json")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := rig.adapter.Invoke(ctx, rig.request); Code(err) != providercontract.Canceled {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("context ceiling", func(t *testing.T) {
		rig := newTestRig(t, "completed-response.json")
		rig.adapter.config.Tokens = tokenCounterStub{count: 32768}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Denied ||
			Reason(err) != "context_limit" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("token counter unavailable", func(t *testing.T) {
		rig := newTestRig(t, "completed-response.json")
		rig.adapter.config.Tokens = tokenCounterStub{err: errors.New("counter offline")}
		if _, err := rig.adapter.Invoke(context.Background(), rig.request); Code(err) != providercontract.Unavailable || !Retryable(err) {
			t.Fatalf("err=%v", err)
		}
	})
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
		rig := newTestRig(t, "completed-response.json")
		rig.http.status = test.status
		rig.http.body = []byte(strings.Repeat("sensitive-vendor-detail", 8))
		_, err := rig.adapter.Invoke(context.Background(), rig.request)
		if Code(err) != test.code || Retryable(err) != test.retryable || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("status=%d err=%v retryable=%v", test.status, err, Retryable(err))
		}
	}
}

func TestConfigurationRejectsRouteAndProviderDrift(t *testing.T) {
	rig := newTestRig(t, "completed-response.json")
	tests := []func(*Config){
		func(config *Config) { config.Endpoint = "https://other.invalid/v1/responses" },
		func(config *Config) { config.CredentialReference = "" },
		func(config *Config) { config.HTTP = nil },
	}
	for index, mutate := range tests {
		config := rig.adapter.config
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestSecureHTTPClientDisablesRedirectsAndAmbientProxy(t *testing.T) {
	client, err := NewSecureHTTPClient(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || transport.TLSClientConfig.ServerName != "api.openai.com" {
		t.Fatalf("transport=%+v", transport)
	}
	request, _ := http.NewRequest(http.MethodPost, ResponsesEndpoint, nil)
	redirect, _ := http.NewRequest(http.MethodPost, "https://other.invalid/v1/responses", nil)
	if err := client.CheckRedirect(redirect, []*http.Request{request}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect err=%v", err)
	}
	if _, err := NewSecureHTTPClient(0); err == nil {
		t.Fatal("zero timeout accepted")
	}
}

func mutateFixture(t *testing.T, input []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func output(value map[string]any, index int) map[string]any {
	return value["output"].([]any)[index].(map[string]any)
}
