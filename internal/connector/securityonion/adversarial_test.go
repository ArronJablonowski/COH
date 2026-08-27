package securityonion

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestSanitizedVendorFixturesConformWithoutForbiddenMaterial(t *testing.T) {
	config := testConfig()
	clock := fixedClock{time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)}
	qualifier, _ := NewQualifier(config, clock)
	openAPI := readOnionFixture(t, "openapi-qualified.json")
	qualification, err := qualifier.Qualify(context.Background(), openAPI)
	if err != nil || len(qualification.Value().Operations) != 2 || strings.Contains(string(openAPI), `"/connect/events/ack"`) {
		t.Fatalf("qualification=%+v err=%v", qualification.Value(), err)
	}
	compiler, _ := NewOQLCompiler(config, clock)
	_, eventPlan, err := compiler.Validate(context.Background(), testOQLQuery(t,
		`{"mode":"events","filter":{"match_all":{}}}`), testOQLSchema(t), qualification)
	if err != nil {
		t.Fatal(err)
	}
	events, err := decodeEventQueryResult(readOnionFixture(t, "events.json"), eventPlan.Value())
	if err != nil || len(events.Events) != 1 || events.EventCapHit {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	_, metricPlan, err := compiler.Validate(context.Background(), testOQLQuery(t,
		`{"mode":"metrics","filter":{"match_all":{}},"group_by":["source_ip"]}`), testOQLSchema(t), qualification)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := decodeEventQueryResult(readOnionFixture(t, "metrics.json"), metricPlan.Value())
	if err != nil || len(metrics.Metrics) != 1 || !metrics.MetricCapHit {
		t.Fatalf("metrics=%+v err=%v", metrics, err)
	}
	if _, err := decodeEventQueryResult(readOnionFixture(t, "error.json"), eventPlan.Value()); queryconnector.Reason(err) != "securityonion_query_response_mismatch" {
		t.Fatalf("error fixture err=%v", err)
	}
	for _, name := range []string{"openapi-qualified.json", "info.json", "events.json", "metrics.json", "error.json"} {
		lower := strings.ToLower(string(readOnionFixture(t, name)))
		for _, forbidden := range []string{"client_secret", "access_token", "authorization:", "bearer "} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("fixture %s contains %q", name, forbidden)
			}
		}
	}
}

func TestHTTPClientDistinguishesOutageAuthTLSAndTimeout(t *testing.T) {
	t.Run("outage-recovery", func(t *testing.T) {
		attempts := 0
		server := newOnionTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			if request.URL.Path == "/oauth2/token" {
				attempts++
				if attempts == 1 {
					http.Error(writer, "temporary", http.StatusServiceUnavailable)
					return
				}
				_, _ = writer.Write([]byte(`{"access_token":"fixture-bearer-token-1234","expires_in":60,"token_type":"Bearer"}`))
				return
			}
			_, _ = writer.Write(readOnionFixture(t, "info.json"))
		}))
		defer server.Close()
		client, qualification := adversarialHTTPClient(t, server, "")
		request := InfoRequest{Binding: securityOnionHTTPBinding("securityonion.inspect"), Qualification: qualification}
		if _, _, err := client.Inspect(context.Background(), request); queryconnector.Reason(err) != "securityonion_token_service_unavailable" {
			t.Fatalf("outage err=%v", err)
		}
		if info, _, err := client.Inspect(context.Background(), request); err != nil || info.Version != "3.2.1" {
			t.Fatalf("recovery info=%+v err=%v", info, err)
		}
	})
	t.Run("authentication-redacted", func(t *testing.T) {
		server := newOnionTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"fixture-client-secret"}`))
		}))
		defer server.Close()
		client, qualification := adversarialHTTPClient(t, server, "")
		_, _, err := client.Inspect(context.Background(), InfoRequest{
			Binding: securityOnionHTTPBinding("securityonion.inspect"), Qualification: qualification})
		if queryconnector.Reason(err) != "securityonion_authentication_denied" || strings.Contains(err.Error(), "fixture-client-secret") {
			t.Fatalf("auth err=%v", err)
		}
	})
	t.Run("tls-substitution", func(t *testing.T) {
		server := newOnionTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"access_token":"fixture-bearer-token-1234","expires_in":60,"token_type":"Bearer"}`))
		}))
		defer server.Close()
		client, qualification := adversarialHTTPClient(t, server, testDigest("9"))
		_, _, err := client.Inspect(context.Background(), InfoRequest{
			Binding: securityOnionHTTPBinding("securityonion.inspect"), Qualification: qualification})
		if queryconnector.Reason(err) != "securityonion_tls_identity_mismatch" {
			t.Fatalf("tls err=%v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		server := newOnionTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"access_token":"fixture-bearer-token-1234","expires_in":60,"token_type":"Bearer"}`))
		}))
		defer server.Close()
		client, qualification := adversarialHTTPClient(t, server, "")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		_, _, err := client.Inspect(ctx, InfoRequest{Binding: securityOnionHTTPBinding("securityonion.inspect"),
			Qualification: qualification})
		if queryconnector.Code(err) != queryconnector.Timeout {
			t.Fatalf("timeout err=%v", err)
		}
	})
}

func TestOQLRuntimeRetriesOutageAndReportsLostState(t *testing.T) {
	runtime, client, capability, schema := testOQLRuntime(t)
	query := runtimeOQLQuery(t, capability.Digest(), schema.Value().SchemaDigest)
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	client.err = errors.New("temporary outage containing no vendor body")
	if _, err := runtime.Execute(context.Background(), query, validation); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("outage err=%v", err)
	}
	client.err = nil
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || client.callCount("securityonion.query_events") != 2 {
		t.Fatalf("execution=%+v calls=%d err=%v", execution.Value(), client.callCount("securityonion.query_events"), err)
	}
	runtime.mu.Lock()
	delete(runtime.jobs, execution.Value().Handle.HandleID)
	runtime.mu.Unlock()
	pollRequest := queryconnector.PollRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: execution.Value().Handle, Authority: query.Value().Authority}
	if _, err := runtime.Poll(context.Background(), pollRequest); queryconnector.Reason(err) != "securityonion_oql_job_unavailable" {
		t.Fatalf("lost poll err=%v", err)
	}
	cancellation, err := runtime.Cancel(context.Background(), queryconnector.CancelRequest{QueryID: pollRequest.QueryID,
		AttemptID: pollRequest.AttemptID, Handle: pollRequest.Handle, Authority: pollRequest.Authority,
		RequestedAt: "2026-08-27T18:00:01.000000000Z"})
	if err != nil || cancellation.Value().Outcome != "uncertain" || cancellation.Value().ConfirmedAt != nil {
		t.Fatalf("cancellation=%+v err=%v", cancellation.Value(), err)
	}
}

func readOnionFixture(t testing.TB, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("testdata/security-onion-3.x/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func newOnionTLSServer(handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	return server
}

func adversarialHTTPClient(t testing.TB, server *httptest.Server,
	overrideTransportDigest string) (*HTTPClient, ValidatedQualification) {
	t.Helper()
	config, roots := securityOnionHTTPTestConfig(t, server)
	if overrideTransportDigest != "" {
		config.TransportIdentityDigest = overrideTransportDigest
	}
	clock := fixedClock{time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)}
	qualifier, _ := NewQualifier(config, clock)
	qualification, err := qualifier.Qualify(context.Background(), testOpenAPI(t))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPClient(config, &securityOnionCredentialStub{clientID: "coh-client",
		secret: []byte("fixture-client-secret"), decision: testDigest("8")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	return client, qualification
}
