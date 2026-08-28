package sentinel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type sentinelCredentialStub struct {
	token          []byte
	decision       string
	uses           int
	acceptedBefore *atomic.Int32
}

func (source *sentinelCredentialStub) Use(_ context.Context, _ CallBinding, consumer func([]byte) error) (string, error) {
	if source.acceptedBefore != nil && source.acceptedBefore.Load() == 0 {
		return "", deniedCall("credential_released_before_tls_preflight")
	}
	source.uses++
	temporary := append([]byte(nil), source.token...)
	defer func() {
		for index := range temporary {
			temporary[index] = 0
		}
	}()
	if err := consumer(temporary); err != nil {
		return "", err
	}
	return source.decision, nil
}

type sentinelCountingListener struct {
	net.Listener
	accepted *atomic.Int32
}

func (listener sentinelCountingListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted.Add(1)
	}
	return connection, err
}

func TestHTTPClientPerformsOnlyBoundMetadataGET(t *testing.T) {
	var calls []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer broker-token" || request.Header.Get("Accept") != "application/json" ||
			request.Body != http.NoBody {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(writer).Encode(sentinelVendorMetadata())
	}))
	var accepted atomic.Int32
	server.Listener = sentinelCountingListener{Listener: server.Listener, accepted: &accepted}
	server.StartTLS()
	defer server.Close()
	config, roots := sentinelHTTPTestConfig(t, server)
	credentials := &sentinelCredentialStub{token: []byte("broker-token"), decision: sentinelTestDigest("8"), acceptedBefore: &accepted}
	client, err := newHTTPClient(config, credentials, roots, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	metadata, receipt, err := client.Metadata(context.Background(), MetadataRequest{Binding: sentinelTestBinding(config)})
	if err != nil || metadata.WorkspaceID != config.WorkspaceID || metadata.Digest != metadataDigest(metadata) ||
		receipt.TransportDigest != config.TransportIdentityDigest || credentials.uses != 1 {
		t.Fatalf("metadata=%+v receipt=%+v uses=%d err=%v", metadata, receipt, credentials.uses, err)
	}
	if !slices.Equal(calls, []string{"GET /v1/workspaces/22222222-2222-2222-2222-222222222222/metadata"}) {
		t.Fatalf("calls=%v", calls)
	}
}

func TestHTTPClientRejectsBindingTLSAndCredentialDriftBeforeDisclosure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(sentinelVendorMetadata())
	}))
	defer server.Close()
	config, roots := sentinelHTTPTestConfig(t, server)

	t.Run("management endpoint configuration", func(t *testing.T) {
		drifted := config
		drifted.Endpoint = "https://management.azure.com"
		if _, err := NewHTTPClient(drifted, &sentinelCredentialStub{}, roots); queryconnector.Reason(err) != "sentinel_http_configuration_invalid" {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("binding", func(t *testing.T) {
		credentials := &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}
		client, _ := newHTTPClient(config, credentials, roots, server.URL)
		binding := sentinelTestBinding(config)
		binding.Audience = "https://management.azure.com/.default"
		if _, _, err := client.Metadata(context.Background(), MetadataRequest{Binding: binding}); queryconnector.Reason(err) != "sentinel_call_binding_invalid" || credentials.uses != 0 {
			t.Fatalf("err=%v uses=%d", err, credentials.uses)
		}
	})

	t.Run("tls substitution", func(t *testing.T) {
		drifted := config
		drifted.TransportIdentityDigest = sentinelTestDigest("9")
		credentials := &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}
		client, _ := newHTTPClient(drifted, credentials, roots, server.URL)
		binding := sentinelTestBinding(drifted)
		if _, _, err := client.Metadata(context.Background(), MetadataRequest{Binding: binding}); queryconnector.Reason(err) != "sentinel_tls_identity_mismatch" || credentials.uses != 0 {
			t.Fatalf("err=%v uses=%d", err, credentials.uses)
		}
	})

	t.Run("header injection", func(t *testing.T) {
		credentials := &sentinelCredentialStub{token: []byte("token\r\ninjected: yes"), decision: sentinelTestDigest("8")}
		client, _ := newHTTPClient(config, credentials, roots, server.URL)
		if _, _, err := client.Metadata(context.Background(), MetadataRequest{Binding: sentinelTestBinding(config)}); queryconnector.Reason(err) != "sentinel_credential_invalid" {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestHTTPClientRejectsRedirectsOversizeAndHostileMetadata(t *testing.T) {
	t.Run("redirect does not forward bearer", func(t *testing.T) {
		var redirected atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
		defer target.Close()
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
		}))
		defer server.Close()
		config, roots := sentinelHTTPTestConfig(t, server)
		client, _ := newHTTPClient(config, &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}, roots, server.URL)
		if _, _, err := client.Metadata(context.Background(), MetadataRequest{Binding: sentinelTestBinding(config)}); queryconnector.Reason(err) != "sentinel_transport_failed" || redirected.Load() != 0 {
			t.Fatalf("err=%v redirected=%d", err, redirected.Load())
		}
	})

	tests := []struct {
		name, body, reason string
	}{
		{"duplicate key", `{"tables":[],"tables":[],"workspaces":[]}`, "sentinel_metadata_response_invalid"},
		{"unknown section", `{"tables":[],"workspaces":[],"continuation":"secret"}`, "sentinel_metadata_response_invalid"},
		{"oversize", string(bytes.Repeat([]byte("x"), 2049)), "sentinel_metadata_response_oversized"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			config, roots := sentinelHTTPTestConfig(t, server)
			if test.name == "oversize" {
				config.MaximumMetadataBytes = 1024
			}
			client, _ := newHTTPClient(config, &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}, roots, server.URL)
			if _, _, err := client.Metadata(context.Background(), MetadataRequest{Binding: sentinelTestBinding(config)}); queryconnector.Reason(err) != test.reason {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestHTTPClientRedactsVendorFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, `token broker-token denied for owner`, http.StatusForbidden)
	}))
	defer server.Close()
	config, roots := sentinelHTTPTestConfig(t, server)
	client, _ := newHTTPClient(config, &sentinelCredentialStub{token: []byte("broker-token"), decision: sentinelTestDigest("8")}, roots, server.URL)
	_, _, err := client.Metadata(context.Background(), MetadataRequest{Binding: sentinelTestBinding(config)})
	if queryconnector.Reason(err) != "sentinel_authentication_or_privilege_denied" || strings.Contains(err.Error(), "broker-token") ||
		strings.Contains(err.Error(), "owner") {
		t.Fatalf("err=%v", err)
	}
}

func sentinelHTTPTestConfig(t *testing.T, server *httptest.Server) (Config, *x509.CertPool) {
	t.Helper()
	config, err := DecodeConfig(readFixture(t, "config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	certificate := server.Certificate()
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	config.TransportIdentityDigest = "sha256:" + hex.EncodeToString(sum[:])
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return config, roots
}

func sentinelTestBinding(config Config) CallBinding {
	return CallBinding{Scope: queryconnector.Scope{OrganizationID: "018f1f2e-7a6b-7c8d-8e9f-000000000101",
		TenantID: "018f1f2e-7a6b-7c8d-8e9f-000000000102", CaseID: "018f1f2e-7a6b-7c8d-8e9f-000000000103",
		SourceID: config.SourceID, ResourceIDs: []string{"security-events", "signin-events"}},
		Authority: queryconnector.AuthorityBinding{ActorID: "018f1f2e-7a6b-7c8d-8e9f-000000000104",
			AuthorizationDigest: sentinelTestDigest("1"), PolicyDecisionDigest: sentinelTestDigest("2"), AuditReservationDigest: sentinelTestDigest("3")},
		Operation: "sentinel.metadata.get", Targets: []string{"security-events", "signin-events"}, TenantID: config.TenantID,
		Audience: config.TokenAudience, Endpoint: config.Endpoint, TransportIdentityDigest: config.TransportIdentityDigest}
}

func sentinelVendorMetadata() map[string]any {
	return map[string]any{"workspaces": []any{map[string]any{"id": "22222222-2222-2222-2222-222222222222", "name": "coh-sentinel",
		"region": "westus2", "resourceId": "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/coh-security/providers/Microsoft.OperationalInsights/workspaces/coh-sentinel"}},
		"tables": []any{map[string]any{"id": "AzureActivity", "name": "AzureActivity", "timespanColumn": "TimeGenerated",
			"columns": []any{map[string]any{"name": "TimeGenerated", "type": "datetime"}, map[string]any{"name": "Category", "type": "string"}}},
			map[string]any{"id": "SigninLogs", "name": "SigninLogs", "timespanColumn": "TimeGenerated",
				"columns": []any{map[string]any{"name": "TimeGenerated", "type": "datetime"}, map[string]any{"name": "IpAddress", "type": "string"}}}}}
}

func sentinelTestDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
