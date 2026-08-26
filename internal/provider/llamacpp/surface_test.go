package llamacpp

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestFrozenServerSurface(t *testing.T) {
	if AdapterVersion != "1.0.0" || VendorSurfaceVersion != "llama.cpp.server.chat-completions/5d5cb4c" ||
		LlamaCPPEndpoint != "http://127.0.0.1:8080" || HealthPath != "/health" || PropertiesPath != "/props" ||
		ModelsPath != "/v1/models" || ChatPath != "/v1/chat/completions" {
		t.Fatal("llama.cpp server surface drifted")
	}
	if EndpointIdentityDigest(LlamaCPPEndpoint) == "" {
		t.Fatal("endpoint digest missing")
	}
}

func TestConfigExposesNoCredentialOrGenericVendorSurface(t *testing.T) {
	typeOfConfig := reflect.TypeOf(Config{})
	for index := 0; index < typeOfConfig.NumField(); index++ {
		switch typeOfConfig.Field(index).Name {
		case "Credential", "Credentials", "Authorization", "Headers", "Options", "Vendor", "Passthrough":
			t.Fatalf("config exports forbidden field %s", typeOfConfig.Field(index).Name)
		}
	}
}

func TestLoopbackClientRejectsUnapprovedTargetsAndRedirects(t *testing.T) {
	client, err := NewLoopbackHTTPClient(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect err=%v", err)
	}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "localhost:8080"); err == nil {
		t.Fatal("localhost alias accepted")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:8081"); err == nil {
		t.Fatal("alternate port accepted")
	}
}

func TestOnlyFourOperationsAreAllowlisted(t *testing.T) {
	for _, operation := range []struct{ method, path string }{
		{http.MethodGet, HealthPath}, {http.MethodGet, PropertiesPath}, {http.MethodGet, ModelsPath},
		{http.MethodPost, ChatPath},
	} {
		if !allowedOperation(operation.method, operation.path) {
			t.Fatalf("operation rejected: %+v", operation)
		}
	}
	for _, operation := range []struct{ method, path string }{
		{http.MethodPost, PropertiesPath}, {http.MethodGet, "/slots"}, {http.MethodPost, "/models/load"},
		{http.MethodPost, "/v1/responses"}, {http.MethodGet, "/tools"},
	} {
		if allowedOperation(operation.method, operation.path) {
			t.Fatalf("operation accepted: %+v", operation)
		}
	}
}
