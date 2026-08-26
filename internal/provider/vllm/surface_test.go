package vllm

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestFrozenServerSurface(t *testing.T) {
	if AdapterVersion != "1.0.0" || VendorSurfaceVersion != "vllm.openai.chat-completions/796822d" ||
		VLLMEndpoint != "http://127.0.0.1:8000" || HealthPath != "/health" || VersionPath != "/version" ||
		ModelsPath != "/v1/models" || TokenizerInfoPath != "/tokenizer_info" || ChatPath != "/v1/chat/completions" {
		t.Fatal("vLLM server surface drifted")
	}
	if EndpointIdentityDigest(VLLMEndpoint) == "" {
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
	if _, err := transport.DialContext(context.Background(), "tcp", "localhost:8000"); err == nil {
		t.Fatal("localhost alias accepted")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:8001"); err == nil {
		t.Fatal("alternate port accepted")
	}
}

func TestOnlyFiveOperationsAreAllowlisted(t *testing.T) {
	for _, operation := range []struct{ method, path string }{
		{http.MethodGet, HealthPath}, {http.MethodGet, VersionPath}, {http.MethodGet, ModelsPath}, {http.MethodGet, TokenizerInfoPath},
		{http.MethodPost, ChatPath},
	} {
		if !allowedOperation(operation.method, operation.path) {
			t.Fatalf("operation rejected: %+v", operation)
		}
	}
	for _, operation := range []struct{ method, path string }{
		{http.MethodPost, TokenizerInfoPath}, {http.MethodGet, "/server_info"}, {http.MethodPost, "/invocations"},
		{http.MethodPost, "/v1/load_lora_adapter"}, {http.MethodPost, "/v1/responses"}, {http.MethodGet, "/tools"},
	} {
		if allowedOperation(operation.method, operation.path) {
			t.Fatalf("operation accepted: %+v", operation)
		}
	}
}
