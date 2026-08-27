package elastic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/connector/elasticesql"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestHTTPClientExecutesOnlyValidatedBoundedESQL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodPost || request.URL.Path != "/_query" ||
			request.URL.Query().Get("format") != "json" || request.URL.Query().Get("allow_partial_results") != "false" ||
			request.URL.Query().Get("drop_null_columns") != "false" || request.Header.Get("Authorization") != "ApiKey key" {
			http.Error(writer, "request denied", http.StatusBadRequest)
			return
		}
		var payload struct {
			Query    string         `json:"query"`
			Params   []any          `json:"params"`
			Filter   map[string]any `json:"filter"`
			Columnar bool           `json:"columnar"`
		}
		body, _ := io.ReadAll(request.Body)
		if json.Unmarshal(body, &payload) != nil || payload.Query != "FROM logs-security-000001 | KEEP @timestamp, event.id | SORT @timestamp DESC, event.id ASC | LIMIT 10" ||
			payload.Columnar || len(payload.Params) != 0 || payload.Filter["bool"] == nil {
			http.Error(writer, "payload denied", http.StatusBadRequest)
			return
		}
		_, _ = writer.Write(readElasticFixture(t, "esql-response.json"))
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	credentials := &credentialStub{secret: []byte("key"), decision: testDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	plan := testESQLPlan(t)
	binding := CallBinding{Scope: testScope(), Authority: testAuthority(), Operation: "elastic.esql",
		Targets: []string{"logs-security-000001"}}
	result, receipt, err := client.ExecuteESQL(context.Background(), ESQLRequest{Binding: binding,
		Indices: []string{"logs-security-000001"}, Plan: plan})
	if err != nil || result.ResultDigest == "" || receipt.RequestDigest == "" || len(result.Rows) != 1 ||
		result.Rows[0]["event_id"] != "event-1" || result.Rows[0]["event_timestamp"] != "2026-08-27T17:30:00Z" {
		t.Fatalf("result=%+v receipt=%+v err=%v", result, receipt, err)
	}
}

func TestESQLResponseFailsClosedOnPartialDriftAndMalformedCells(t *testing.T) {
	plan := testESQLPlan(t).Value()
	base := readElasticFixture(t, "esql-response.json")
	cases := map[string]struct {
		mutate func(map[string]any)
		reason string
	}{
		"partial":    {func(value map[string]any) { value["is_partial"] = true }, "elastic_esql_response_incomplete"},
		"clusters":   {func(value map[string]any) { value["_clusters"] = map[string]any{"total": 1} }, "elastic_esql_response_incomplete"},
		"column":     {func(value map[string]any) { value["columns"].([]any)[0].(map[string]any)["name"] = "other" }, "elastic_esql_column_mismatch"},
		"type":       {func(value map[string]any) { value["columns"].([]any)[0].(map[string]any)["type"] = "unsupported" }, "elastic_esql_column_mismatch"},
		"row-shape":  {func(value map[string]any) { value["values"] = []any{[]any{"only-one"}} }, "elastic_esql_row_shape_invalid"},
		"multivalue": {func(value map[string]any) { value["values"].([]any)[0].([]any)[1] = []any{"a", "b"} }, "elastic_esql_cell_invalid"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(base, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			encoded, _ := json.Marshal(value)
			_, err := decodeESQLResponse(encoded, plan)
			if queryconnector.Reason(err) != test.reason {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestHTTPESQLRejectsVendorWarnings(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Warning", `299 Elasticsearch "multivalued field warning"`)
		_, _ = writer.Write(readElasticFixture(t, "esql-response.json"))
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	client, err := NewHTTPClient(config, &credentialStub{secret: []byte("key"), decision: testDigest("8")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	request := ESQLRequest{Binding: CallBinding{Scope: testScope(), Authority: testAuthority(), Operation: "elastic.esql",
		Targets: []string{"logs-security-000001"}}, Indices: []string{"logs-security-000001"}, Plan: testESQLPlan(t)}
	if _, _, err := client.ExecuteESQL(context.Background(), request); queryconnector.Reason(err) != "elastic_esql_response_warning" {
		t.Fatalf("err=%v", err)
	}
}

func TestHTTPESQLPreservesAuthenticationErrorPrecedence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Warning", `299 Elasticsearch "warning must not mask auth"`)
		http.Error(writer, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	client, err := NewHTTPClient(config, &credentialStub{secret: []byte("key"), decision: testDigest("8")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	request := ESQLRequest{Binding: CallBinding{Scope: testScope(), Authority: testAuthority(), Operation: "elastic.esql",
		Targets: []string{"logs-security-000001"}}, Indices: []string{"logs-security-000001"}, Plan: testESQLPlan(t)}
	if _, _, err := client.ExecuteESQL(context.Background(), request); queryconnector.Reason(err) != "elastic_authentication_or_privilege_denied" {
		t.Fatalf("err=%v", err)
	}
}

func testESQLPlan(t testing.TB) elasticesql.ValidatedPlan {
	t.Helper()
	compiler, err := elasticesql.New(elasticesql.Definition{SourceID: "elastic-prod", Resources: []string{"securityevent"},
		Fields: []elasticesql.FieldRule{
			{Name: "event_id", VendorName: "event.id", Type: "string", Projectable: true, Sortable: true},
			{Name: "event_timestamp", VendorName: "@timestamp", Type: "timestamp", Projectable: true, Filterable: true, Sortable: true},
		}, DefaultProjection: []string{"event_timestamp", "event_id"},
		StableSort:     []elasticesql.SortField{{Name: "event_timestamp", Direction: "DESC"}, {Name: "event_id", Direction: "ASC"}},
		TimestampField: "event_timestamp", HardMaximumRows: 10})
	if err != nil {
		t.Fatal(err)
	}
	queryValue := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: testID("5"), Scope: testScope(), Authority: testAuthority(), CapabilityDigest: testDigest("5"),
		SchemaDigest: testDigest("6"), Language: "esql", NativeText: "FROM securityevent",
		TimeRange: queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits: queryconnector.Limits{MaximumRows: 10, MaximumBytes: 100000, MaximumDurationMillis: 5000,
			MaximumPages: 1, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2},
		RequestedAt: "2026-08-27T16:59:00.000000000Z", Deadline: "2026-08-27T18:01:00.000000000Z"}
	queryBytes, _ := json.Marshal(queryValue)
	query, err := queryconnector.DecodeQuery(context.Background(), queryBytes)
	if err != nil {
		t.Fatal(err)
	}
	schemaValue := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, RequestID: testID("6"), SchemaDigest: testDigest("6"),
		Entries: []queryconnector.SchemaEntry{{ResourceID: "securityevent", Name: "event_id", Type: "string"},
			{ResourceID: "securityevent", Name: "event_timestamp", Type: "timestamp"}},
		Complete: true, ProvenanceDigest: testDigest("7")}
	schemaBytes, _ := json.Marshal(schemaValue)
	schema, err := queryconnector.DecodeSchemaPage(context.Background(), schemaBytes)
	if err != nil {
		t.Fatal(err)
	}
	validation, plan, err := compiler.Validate(context.Background(), query, schema)
	if err != nil || validation.Value().Outcome != "accepted" || plan == nil {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	return *plan
}

func TestESQLRequestNeverContainsLogicalSourceOrNativeLiterals(t *testing.T) {
	value := testESQLPlan(t).Value()
	if strings.Contains(value.CanonicalPipeline, "logs-security") || strings.Contains(value.CanonicalPipeline, "credential") {
		t.Fatalf("plan=%+v", value)
	}
}
