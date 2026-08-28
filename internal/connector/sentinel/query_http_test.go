package sentinel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestHTTPQueryClientPerformsOnlyBoundPOST(t *testing.T) {
	var calls []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.RequestURI())
		var body map[string]interface{}
		if request.Header.Get("Authorization") != "Bearer broker-token" || request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Prefer") != "include-statistics=true,wait=30" ||
			json.NewDecoder(request.Body).Decode(&body) != nil || body["query"] != "SecurityEvent | take 500" ||
			body["timespan"] != "2026-08-27T00:00:00.000000000Z/2026-08-27T01:00:00.000000000Z" {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(writer).Encode(sentinelVendorQueryResult())
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
	call := sentinelTestQueryCall(config)
	response, err := client.Query(context.Background(), call)
	if err != nil || response.Error != nil || len(response.Tables) != 1 || len(response.Tables[0].Rows) != 2 ||
		response.Receipt.RequestDigest != call.Request.RequestDigest || credentials.uses != 1 {
		t.Fatalf("response=%+v uses=%d err=%v", response, credentials.uses, err)
	}
	if !slices.Equal(calls, []string{"POST /v1/workspaces/22222222-2222-2222-2222-222222222222/query"}) {
		t.Fatalf("calls=%v", calls)
	}
}

func TestHTTPQueryClientRejectsPartialErrorWithoutRows(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{
			"tables": []interface{}{map[string]interface{}{"name": "PrimaryResult",
				"columns": []interface{}{map[string]interface{}{"name": "TimeGenerated", "type": "datetime"}},
				"rows":    []interface{}{[]interface{}{"2026-08-27T00:30:00.000000000Z"}}}},
			"error": map[string]interface{}{"code": "PartialError", "message": "private row literal and owner",
				"details": []interface{}{map[string]interface{}{"code": "QueryTimeout", "message": "private workspace"}}},
		})
	}))
	defer server.Close()
	config, roots := sentinelHTTPTestConfig(t, server)
	client, _ := newHTTPClient(config, &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}, roots, server.URL)
	response, err := client.Query(context.Background(), sentinelTestQueryCall(config))
	if err != nil || response.Error == nil || response.Error.Code != "PartialError" ||
		!slices.Equal(response.Error.DetailCodes, []string{"query_timeout"}) || len(response.Tables) != 0 || response.Statistics.RowsReturned != 0 {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	encoded, _ := json.Marshal(response)
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "owner") || strings.Contains(string(encoded), "workspace") {
		t.Fatalf("partial response leaked vendor content: %s", encoded)
	}
}

func TestHTTPQueryClientDeniesBindingAndHostileResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"tables":[],"tables":[],"statistics":{}}`))
	}))
	defer server.Close()
	config, roots := sentinelHTTPTestConfig(t, server)
	credentials := &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}
	client, _ := newHTTPClient(config, credentials, roots, server.URL)

	call := sentinelTestQueryCall(config)
	call.Binding.Operation = "sentinel.metadata.get"
	if _, err := client.Query(context.Background(), call); queryconnector.Reason(err) != "sentinel_operation_denied" || credentials.uses != 0 {
		t.Fatalf("binding err=%v uses=%d", err, credentials.uses)
	}

	call = sentinelTestQueryCall(config)
	if _, err := client.Query(context.Background(), call); queryconnector.Reason(err) != "sentinel_query_response_invalid" {
		t.Fatalf("hostile response err=%v", err)
	}
}

func sentinelTestQueryCall(config Config) QueryCall {
	binding := sentinelTestBinding(config)
	binding.Operation = QueryOperation
	request := queryTestTransportRequest()
	request.SourceID, request.WorkspaceID = config.SourceID, config.WorkspaceID
	request.ScopeDigest = hashValue("COH-SENTINEL-QUERY-SCOPE-V1\x00", binding.Scope)
	request.AuthorityDigest = hashValue("COH-SENTINEL-QUERY-AUTHORITY-V1\x00", binding.Authority)
	request.PolicyDecisionDigest = binding.Authority.PolicyDecisionDigest
	request.TransportIdentityDigest = config.TransportIdentityDigest
	request.RequestDigest = queryTransportRequestDigest(request)
	return QueryCall{Binding: binding, Request: request}
}

func sentinelVendorQueryResult() map[string]interface{} {
	return map[string]interface{}{"tables": []interface{}{map[string]interface{}{"name": "PrimaryResult",
		"columns": []interface{}{map[string]interface{}{"name": "TimeGenerated", "type": "datetime"},
			map[string]interface{}{"name": "EventRecordId", "type": "long"}, map[string]interface{}{"name": "Computer", "type": "string"}},
		"rows": []interface{}{[]interface{}{"2026-08-27T00:15:00.000000000Z", 41, "host-a"},
			[]interface{}{"2026-08-27T00:45:00.000000000Z", 42, "host-b"}}}},
		"statistics": map[string]interface{}{"query": map[string]interface{}{"executionTime": 0.015}}}
}
