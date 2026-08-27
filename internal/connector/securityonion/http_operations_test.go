package securityonion

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type securityOnionCredentialStub struct {
	clientID string
	secret   []byte
	decision string
	uses     int
}

func (source *securityOnionCredentialStub) Use(_ context.Context, binding CallBinding,
	consumer func(ClientCredential) error) (string, error) {
	source.uses++
	temporary := append([]byte(nil), source.secret...)
	defer func() {
		for index := range temporary {
			temporary[index] = 0
		}
	}()
	if binding.Operation == "" {
		return "", denied("test_binding_missing")
	}
	if err := consumer(ClientCredential{ClientID: source.clientID, Secret: temporary}); err != nil {
		return "", err
	}
	return source.decision, nil
}

func TestHTTPClientUsesFreshOAuthAndOnlyQualifiedReadPaths(t *testing.T) {
	const clientSecret = "fixture-client-secret"
	var calls []string
	var plan OQLPlan
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.EscapedPath())
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/oauth2/token":
			clientID, secret, ok := request.BasicAuth()
			if request.Method != http.MethodPost || !ok || clientID != "coh-client" || secret != clientSecret ||
				request.FormValue("grant_type") != "client_credentials" {
				http.Error(writer, "bad token request", http.StatusUnauthorized)
				return
			}
			_, _ = writer.Write([]byte(`{"access_token":"fixture-bearer-token-1234","expires_in":300,"token_type":"Bearer"}`))
		case "/connect/info/":
			assertBearer(t, request)
			_, _ = writer.Write([]byte(`{"version":"3.2.1","elasticVersion":"9.1.0","srvToken":"must-not-escape"}`))
		case "/connect/events/":
			assertBearer(t, request)
			query := request.URL.Query()
			if query.Get("query") != plan.RenderedQuery || query.Get("range") != plan.Range ||
				query.Get("zone") != "UTC" || query.Get("format") != connectRangeLayout ||
				query.Get("eventLimit") != "10" || query.Get("metricLimit") != "1" || len(query) != 6 {
				http.Error(writer, "bad query", http.StatusBadRequest)
				return
			}
			response := []any{map[string]any{
				"completeTime": "2026-08-27T18:00:00Z", "createTime": "2026-08-27T17:59:59Z",
				"criteria": map[string]any{"beginTime": "2026-08-27T17:00:00Z", "createTime": "", "dateRange": "",
					"endTime":    "2026-08-27T18:00:00Z",
					"eventLimit": plan.EventLimit, "metricLimit": plan.MetricLimit, "query": plan.RenderedQuery},
				"elapsedMs": 12, "errors": []any{}, "metrics": map[string]any{}, "totalEvents": 1,
				"events": []any{map[string]any{"id": "event-1", "payload": map[string]any{
					"@timestamp": "2026-08-27T17:30:00.000Z", "event.id": "event-1", "message": "allowed",
					"source.ip": "10.0.0.1", "secret.field": "must-not-escape"},
					"score": 0, "sort": []any{"2026-08-27T17:30:00.000Z", "event-1"}, "source": "so:index",
					"time": "2026-08-27T17:30:00.000Z", "timestamp": "2026-08-27T17:30:00.000Z", "type": ""}},
			}}
			_ = json.NewEncoder(writer).Encode(response)
		default:
			http.Error(writer, "unexpected path", http.StatusMethodNotAllowed)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	config, roots := securityOnionHTTPTestConfig(t, server)
	qualification, validatedPlan := securityOnionHTTPTestPlan(t, config)
	plan = validatedPlan.Value()
	credentials := &securityOnionCredentialStub{clientID: "coh-client", secret: []byte(clientSecret), decision: testDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	infoBinding := securityOnionHTTPBinding("securityonion.inspect")
	info, infoReceipt, err := client.Inspect(context.Background(), InfoRequest{Binding: infoBinding, Qualification: qualification})
	if err != nil || info.Version != "3.2.1" || info.ElasticVersion != "9.1.0" ||
		infoReceipt.TransportDigest != config.TransportIdentityDigest {
		t.Fatalf("info=%+v receipt=%+v err=%v", info, infoReceipt, err)
	}
	queryBinding := securityOnionHTTPBinding("securityonion.query_events")
	result, receipt, err := client.QueryEvents(context.Background(), EventQueryRequest{
		Binding: queryBinding, Qualification: qualification, Plan: validatedPlan})
	if err != nil || len(result.Events) != 1 || result.Events[0].Payload["message"] != "allowed" ||
		len(result.Events[0].Payload) != len(plan.Columns) || result.EventCapHit || receipt.TransportDigest != config.TransportIdentityDigest {
		t.Fatalf("result=%+v receipt=%+v err=%v", result, receipt, err)
	}
	encoded, _ := json.Marshal([]any{info, infoReceipt, result, receipt})
	if strings.Contains(string(encoded), clientSecret) || strings.Contains(string(encoded), "fixture-bearer") ||
		strings.Contains(string(encoded), "must-not-escape") || credentials.uses != 2 {
		t.Fatalf("secret escaped or OAuth not fresh: uses=%d output=%s", credentials.uses, encoded)
	}
	if strings.Join(calls, ",") != "POST /oauth2/token,GET /connect/info/,POST /oauth2/token,GET /connect/events/" {
		t.Fatalf("calls=%v", calls)
	}
}

func TestHTTPClientRejectsEmbeddedErrorsBeforeProjection(t *testing.T) {
	var plan OQLPlan
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/oauth2/token" {
			_, _ = writer.Write([]byte(`{"access_token":"fixture-bearer-token-1234","expires_in":300,"token_type":"Bearer"}`))
			return
		}
		_ = json.NewEncoder(writer).Encode([]any{map[string]any{
			"completeTime": "", "createTime": "", "criteria": map[string]any{"beginTime": "2026-08-27T17:00:00Z", "createTime": "",
				"dateRange": "", "endTime": "2026-08-27T18:00:00Z", "eventLimit": plan.EventLimit, "metricLimit": plan.MetricLimit,
				"query": plan.RenderedQuery}, "elapsedMs": 1, "errors": []string{"all shards failed"},
			"events": []any{}, "metrics": map[string]any{}, "totalEvents": 0,
		}})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, roots := securityOnionHTTPTestConfig(t, server)
	qualification, validatedPlan := securityOnionHTTPTestPlan(t, config)
	plan = validatedPlan.Value()
	client, err := NewHTTPClient(config, &securityOnionCredentialStub{clientID: "coh-client",
		secret: []byte("fixture-client-secret"), decision: testDigest("8")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.QueryEvents(context.Background(), EventQueryRequest{Binding: securityOnionHTTPBinding("securityonion.query_events"),
		Qualification: qualification, Plan: validatedPlan})
	if queryconnector.Reason(err) != "securityonion_query_response_mismatch" {
		t.Fatalf("err=%v", err)
	}
}

func assertBearer(t testing.TB, request *http.Request) {
	t.Helper()
	if request.Header.Get("Authorization") != "Bearer fixture-bearer-token-1234" {
		t.Fatalf("authorization missing")
	}
}

func securityOnionHTTPTestConfig(t testing.TB, server *httptest.Server) (Config, *x509.CertPool) {
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

func securityOnionHTTPTestPlan(t testing.TB, config Config) (ValidatedQualification, ValidatedOQLPlan) {
	t.Helper()
	clock := fixedClock{time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)}
	qualifier, err := NewQualifier(config, clock)
	if err != nil {
		t.Fatal(err)
	}
	qualification, err := qualifier.Qualify(context.Background(), testOpenAPI(t))
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewOQLCompiler(config, clock)
	if err != nil {
		t.Fatal(err)
	}
	_, plan, err := compiler.Validate(context.Background(), testOQLQuery(t, `{"mode":"events","filter":{"match_all":{}}}`),
		testOQLSchema(t), qualification)
	if err != nil || plan == nil {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	return qualification, *plan
}

func securityOnionHTTPBinding(operation string) CallBinding {
	return CallBinding{Scope: queryconnector.Scope{OrganizationID: testID("1"), TenantID: testID("2"),
		CaseID: testID("3"), SourceID: "security-onion-prod", ResourceIDs: []string{"securityevent"}},
		Authority: queryconnector.AuthorityBinding{ActorID: testID("4"), AuthorizationDigest: testDigest("3"),
			PolicyDecisionDigest: testDigest("4"), AuditReservationDigest: testDigest("5")},
		Operation: operation, Targets: []string{"securityevent"}}
}
