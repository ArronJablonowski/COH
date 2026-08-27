package splunk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type splunkCredentialStub struct {
	token          []byte
	decision       string
	uses           int
	acceptedBefore *atomic.Int32
}

func (source *splunkCredentialStub) Use(_ context.Context, _ CallBinding, consumer func([]byte) error) (string, error) {
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

type countingListener struct {
	net.Listener
	accepted *atomic.Int32
}

func (listener countingListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted.Add(1)
	}
	return connection, err
}

func TestHTTPClientUsesOnlyPinnedTypedReadOperations(t *testing.T) {
	var calls []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.EscapedPath()+"?"+request.URL.RawQuery)
		if request.Header.Get("Authorization") != "Splunk broker-token" || request.Header.Get("Accept") != "application/json" {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/services/server/info":
			_, _ = writer.Write(readSplunkFixture(t, "server-info.json"))
		case "/services/authentication/current-context":
			_, _ = writer.Write(readSplunkFixture(t, "current-context.json"))
		case "/services/data/indexes":
			writeJSON(t, writer, map[string]any{"entry": []any{map[string]any{"name": "security", "content": map[string]any{}},
				map[string]any{"name": "audit", "content": map[string]any{}}, map[string]any{"name": "network", "content": map[string]any{}}}})
		case "/servicesNS/nobody/search/search/fields":
			writeJSON(t, writer, map[string]any{"entry": []any{map[string]any{"name": "src_ip", "content": map[string]any{"indexed": false}},
				map[string]any{"name": "_time", "content": map[string]any{"indexed": true}}}})
		default:
			http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	var accepted atomic.Int32
	server.Listener = countingListener{Listener: server.Listener, accepted: &accepted}
	server.StartTLS()
	defer server.Close()

	config, roots := splunkHTTPTestConfig(t, server)
	credentials := &splunkCredentialStub{token: []byte("broker-token"), decision: splunkTestDigest("8"), acceptedBefore: &accepted}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	binding := splunkTestBinding("splunk.server_info")
	identity, receipt, err := client.ServerInfo(context.Background(), binding)
	if err != nil || identity.GUID != config.ExpectedServerGUID || receipt.TransportDigest != config.TransportIdentityDigest {
		t.Fatalf("identity=%+v receipt=%+v err=%v", identity, receipt, err)
	}
	binding.Operation = "splunk.current_context"
	current, _, err := client.CurrentContext(context.Background(), binding)
	if err != nil || !slices.Equal(current.Capabilities, []string{"get_metadata", "search"}) {
		t.Fatalf("context=%+v err=%v", current, err)
	}
	binding.Operation = "splunk.indexes"
	indexes, _, err := client.Indexes(context.Background(), InventoryRequest{Binding: binding, MaximumEntries: 2})
	if err != nil || !indexes.Truncated || !slices.Equal(indexes.Names, []string{"audit", "network"}) {
		t.Fatalf("indexes=%+v err=%v", indexes, err)
	}
	binding.Operation = "splunk.fields"
	fields, _, err := client.RegisteredFields(context.Background(), InventoryRequest{Binding: binding, MaximumEntries: 2})
	if err != nil || fields.Truncated || len(fields.Fields) != 2 || fields.Fields[0].Name != "_time" || !fields.Fields[0].Indexed {
		t.Fatalf("fields=%+v err=%v", fields, err)
	}
	if credentials.uses != 4 || len(calls) != 4 {
		t.Fatalf("uses=%d calls=%v", credentials.uses, calls)
	}
	want := []string{
		"GET /services/server/info?count=1&output_mode=json",
		"GET /services/authentication/current-context?count=1&output_mode=json",
		"GET /services/data/indexes?count=3&offset=0&output_mode=json&summarize=true",
		"GET /servicesNS/nobody/search/search/fields?count=3&offset=0&output_mode=json",
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls=%v", calls)
	}
}

func TestHTTPClientRejectsBindingTLSAndCredentialDriftBeforeDisclosure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"entry": []any{}})
	}))
	defer server.Close()
	config, roots := splunkHTTPTestConfig(t, server)

	t.Run("binding", func(t *testing.T) {
		credentials := &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}
		client, err := NewHTTPClient(config, credentials, roots)
		if err != nil {
			t.Fatal(err)
		}
		binding := splunkTestBinding("splunk.server_info")
		binding.Targets = []string{"other"}
		if _, _, err := client.ServerInfo(context.Background(), binding); queryconnector.Reason(err) != "splunk_call_binding_invalid" || credentials.uses != 0 {
			t.Fatalf("err=%v uses=%d", err, credentials.uses)
		}
	})

	t.Run("tls substitution", func(t *testing.T) {
		drifted := config
		drifted.TransportIdentityDigest = splunkTestDigest("9")
		credentials := &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}
		client, err := NewHTTPClient(drifted, credentials, roots)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := client.ServerInfo(context.Background(), splunkTestBinding("splunk.server_info")); queryconnector.Reason(err) != "splunk_tls_identity_mismatch" || credentials.uses != 0 {
			t.Fatalf("err=%v uses=%d", err, credentials.uses)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		credentials := &splunkCredentialStub{token: []byte("token\r\ninjected: yes"), decision: splunkTestDigest("8")}
		client, err := NewHTTPClient(config, credentials, roots)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := client.ServerInfo(context.Background(), splunkTestBinding("splunk.server_info")); queryconnector.Reason(err) != "splunk_credential_invalid" {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestHTTPClientRedactsVendorFailuresAndRecovers(t *testing.T) {
	secretBody := `{"messages":[{"text":"token broker-token denied for admin"}]}`
	var attempts int
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(writer, secretBody, http.StatusForbidden)
			return
		}
		writeJSON(t, writer, map[string]any{"entry": []any{map[string]any{"name": "server-info", "content": map[string]any{
			"guid": "12345678-1234-1234-1234-123456789abc", "product_type": "enterprise", "version": "10.0.0",
			"build": "example-build", "server_roles": []string{"search_head"}}}}})
	}))
	defer server.Close()
	config, roots := splunkHTTPTestConfig(t, server)
	credentials := &splunkCredentialStub{token: []byte("broker-token"), decision: splunkTestDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	binding := splunkTestBinding("splunk.server_info")
	if _, _, err := client.ServerInfo(context.Background(), binding); queryconnector.Reason(err) != "splunk_authentication_or_privilege_denied" ||
		strings.Contains(err.Error(), "broker-token") || strings.Contains(err.Error(), "admin") {
		t.Fatalf("err=%v", err)
	}
	if identity, _, err := client.ServerInfo(context.Background(), binding); err != nil || identity.Version != "10.0.0" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
}

func TestHTTPClientCancellationDeadlineAndResponseBounds(t *testing.T) {
	t.Run("pre-canceled", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer server.Close()
		config, roots := splunkHTTPTestConfig(t, server)
		credentials := &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}
		client, _ := NewHTTPClient(config, credentials, roots)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := client.ServerInfo(ctx, splunkTestBinding("splunk.server_info")); queryconnector.Code(err) != queryconnector.Canceled || credentials.uses != 0 {
			t.Fatalf("err=%v uses=%d", err, credentials.uses)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) { <-request.Context().Done() }))
		defer server.Close()
		config, roots := splunkHTTPTestConfig(t, server)
		client, _ := NewHTTPClient(config, &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}, roots)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, _, err := client.ServerInfo(ctx, splunkTestBinding("splunk.server_info")); queryconnector.Code(err) != queryconnector.Timeout {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write(bytes.Repeat([]byte("x"), 1025))
		}))
		defer server.Close()
		config, roots := splunkHTTPTestConfig(t, server)
		config.HardLimits.MaximumBytes = 1024
		client, _ := NewHTTPClient(config, &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}, roots)
		if _, _, err := client.ServerInfo(context.Background(), splunkTestBinding("splunk.server_info")); queryconnector.Reason(err) != "splunk_response_oversized" {
			t.Fatalf("err=%v", err)
		}
	})
}

func splunkHTTPTestConfig(t testing.TB, server *httptest.Server) (Config, *x509.CertPool) {
	t.Helper()
	config, err := DecodeConfig(mustRead(t.(*testing.T), "fixtures/config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	certificate := server.Certificate()
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	config.Endpoint = server.URL
	config.TransportIdentityDigest = "sha256:" + hex.EncodeToString(sum[:])
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return config, roots
}

func splunkTestBinding(operation string) CallBinding {
	return CallBinding{Scope: queryconnector.Scope{OrganizationID: "018f1f2e-7a6b-7c8d-8e9f-000000000101",
		TenantID: "018f1f2e-7a6b-7c8d-8e9f-000000000102", CaseID: "018f1f2e-7a6b-7c8d-8e9f-000000000103",
		SourceID: "splunk-prod", ResourceIDs: []string{"security-events"}},
		Authority: queryconnector.AuthorityBinding{ActorID: "018f1f2e-7a6b-7c8d-8e9f-000000000104",
			AuthorizationDigest: splunkTestDigest("1"), PolicyDecisionDigest: splunkTestDigest("2"), AuditReservationDigest: splunkTestDigest("3")},
		Operation: operation, Targets: []string{"security-events"}}
}

func splunkTestDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func writeJSON(t testing.TB, writer io.Writer, value any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func readSplunkFixture(t testing.TB, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("testdata/splunk-10.0/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
