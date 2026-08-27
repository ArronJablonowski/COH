package elastic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type credentialStub struct {
	secret   []byte
	decision string
	uses     int
}

func (source *credentialStub) Use(_ context.Context, _ CallBinding, consumer func([]byte) error) (string, error) {
	source.uses++
	temporary := append([]byte(nil), source.secret...)
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

func TestHTTPClientUsesOnlyPinnedTypedReadOperations(t *testing.T) {
	var calls []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.EscapedPath()+"?"+request.URL.RawQuery)
		if request.Header.Get("Authorization") != "ApiKey encoded-api-key" {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/":
			_, _ = writer.Write(readElasticFixture(t, "cluster-info.json"))
		case request.Method == http.MethodGet && request.URL.Path == "/_resolve/index/logs-security-*":
			if request.URL.Query().Get("expand_wildcards") != "open" {
				http.Error(writer, "bad expansion", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write(readElasticFixture(t, "resolve-index.json"))
		case request.Method == http.MethodPost && request.URL.Path == "/logs-security-000001/_field_caps":
			body, _ := io.ReadAll(request.Body)
			var payload struct {
				Fields []string `json:"fields"`
			}
			if json.Unmarshal(body, &payload) != nil || strings.Join(payload.Fields, ",") != "@timestamp,source.ip" ||
				request.URL.Query().Get("allow_no_indices") != "false" ||
				request.URL.Query().Get("ignore_unavailable") != "false" ||
				request.URL.Query().Get("expand_wildcards") != "open" ||
				request.URL.Query().Get("include_unmapped") != "true" {
				http.Error(writer, "bad field caps", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write(readElasticFixture(t, "field-caps.json"))
		default:
			http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	config, roots := httpTestConfig(t, server)
	credentials := &credentialStub{secret: []byte("encoded-api-key"), decision: testDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	binding := CallBinding{Scope: testScope(), Authority: testAuthority(), Operation: "elastic.inspect",
		Targets: []string{"securityevent"}}
	identity, receipt, err := client.Inspect(context.Background(), binding)
	if err != nil || identity.ClusterUUID != config.ExpectedClusterUUID || receipt.TransportDigest != config.TransportIdentityDigest {
		t.Fatalf("identity=%+v receipt=%+v err=%v", identity, receipt, err)
	}
	resolveBinding := binding
	resolveBinding.Operation, resolveBinding.Targets = "elastic.resolve", []string{"securityevent"}
	resolved, _, err := client.Resolve(context.Background(), ResolveRequest{Binding: resolveBinding,
		Expression: "logs-security-*", Expand: "open"})
	if err != nil || len(resolved.Indices) != 1 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	fieldBinding := binding
	fieldBinding.Operation, fieldBinding.Targets = "elastic.field_caps", []string{"logs-security-000001"}
	caps, _, err := client.FieldCapabilities(context.Background(), FieldCapabilitiesRequest{Binding: fieldBinding,
		Indices: []string{"logs-security-000001"}, Fields: []string{"@timestamp", "source.ip"},
		ExpandWildcards: "open", IncludeUnmapped: true})
	if err != nil || len(caps.Fields) != 2 {
		t.Fatalf("caps=%+v err=%v", caps, err)
	}
	if credentials.uses != 3 {
		t.Fatalf("credential uses=%d", credentials.uses)
	}
	if len(calls) != 3 || !strings.Contains(calls[1], "/_resolve/index/logs-security-%2A?expand_wildcards=open") {
		t.Fatalf("calls=%v", calls)
	}
}

func TestHTTPClientFailsClosedWithoutLeakingVendorBody(t *testing.T) {
	secretBody := string(readElasticFixture(t, "privilege-denied.json"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, secretBody, http.StatusForbidden)
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	credentials := &credentialStub{secret: []byte("encoded-api-key"), decision: testDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.Inspect(context.Background(), httpTestBinding())
	if queryconnector.Code(err) != queryconnector.Denied ||
		queryconnector.Reason(err) != "elastic_authentication_or_privilege_denied" ||
		strings.Contains(err.Error(), secretBody) || strings.Contains(err.Error(), "encoded-api-key") {
		t.Fatalf("err=%v", err)
	}
}

func TestHTTPClientRejectsTLSIdentitySubstitutionAndOversize(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, "{}")
		}))
		defer server.Close()
		config, roots := httpTestConfig(t, server)
		config.TransportIdentityDigest = testDigest("9")
		client, err := NewHTTPClient(config, &credentialStub{secret: []byte("key"), decision: testDigest("8")}, roots)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = client.Inspect(context.Background(), httpTestBinding())
		if queryconnector.Reason(err) != "elastic_tls_identity_mismatch" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write(bytes.Repeat([]byte("x"), 1025))
		}))
		defer server.Close()
		config, roots := httpTestConfig(t, server)
		config.HardLimits.MaximumBytes = 1024
		client, err := NewHTTPClient(config, &credentialStub{secret: []byte("key"), decision: testDigest("8")}, roots)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = client.Inspect(context.Background(), httpTestBinding())
		if queryconnector.Reason(err) != "elastic_response_oversized" {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestHTTPClientCancellationAndOutageRecovery(t *testing.T) {
	var attempts int
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(writer, "temporary outage", http.StatusServiceUnavailable)
			return
		}
		_, _ = writer.Write(readElasticFixture(t, "cluster-info.json"))
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	credentials := &credentialStub{secret: []byte("key"), decision: testDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Inspect(context.Background(), httpTestBinding()); queryconnector.Reason(err) != "elastic_vendor_unavailable" {
		t.Fatalf("outage err=%v", err)
	}
	if identity, _, err := client.Inspect(context.Background(), httpTestBinding()); err != nil ||
		identity.ClusterUUID != config.ExpectedClusterUUID {
		t.Fatalf("recovery identity=%+v err=%v", identity, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	uses := credentials.uses
	if _, _, err := client.Inspect(canceled, httpTestBinding()); queryconnector.Code(err) != queryconnector.Canceled ||
		credentials.uses != uses {
		t.Fatalf("cancel err=%v uses=%d", err, credentials.uses)
	}
}

func TestHTTPClientDeadlineFailsClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	credentials := &credentialStub{secret: []byte("key"), decision: testDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, _, err := client.Inspect(ctx, httpTestBinding()); queryconnector.Code(err) != queryconnector.Timeout ||
		queryconnector.Reason(err) != "elastic_request_timeout" {
		t.Fatalf("timeout err=%v", err)
	}
}

func httpTestConfig(t testing.TB, server *httptest.Server) (Config, *x509.CertPool) {
	t.Helper()
	certificate := server.Certificate()
	spki := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	config := testConfig()
	config.Endpoint = server.URL
	config.TransportIdentityDigest = "sha256:" + hex.EncodeToString(spki[:])
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return config, roots
}

func httpTestBinding() CallBinding {
	return CallBinding{Scope: testScope(), Authority: testAuthority(), Operation: "elastic.inspect",
		Targets: []string{"securityevent"}}
}

func readElasticFixture(t testing.TB, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("testdata/elastic-8.19/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
