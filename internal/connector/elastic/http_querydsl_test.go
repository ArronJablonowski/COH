package elastic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticquerydsl"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestHTTPClientUsesOnlyTypedQueryDSLAndPITOperations(t *testing.T) {
	var calls []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.Path+"?"+request.URL.RawQuery)
		writer.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(request.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		switch len(calls) {
		case 1:
			if request.Method != http.MethodPost || request.URL.Path != "/logs-security-000001/_validate/query" ||
				request.URL.Query().Get("all_shards") != "true" || request.URL.Query().Get("allow_no_indices") != "false" ||
				len(payload) != 1 || payload["query"] == nil {
				http.Error(writer, "invalid validation", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write(readElasticFixture(t, "query-validate-response.json"))
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/logs-security-000001/_pit" ||
				request.URL.Query().Get("keep_alive") != "30000ms" || request.URL.Query().Get("allow_partial_search_results") != "false" || len(body) != 0 {
				http.Error(writer, "invalid PIT open", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write(readElasticFixture(t, "pit-open-response.json"))
		case 3:
			pit, _ := payload["pit"].(map[string]any)
			if request.Method != http.MethodPost || request.URL.Path != "/_search" || request.URL.Query().Get("allow_partial_search_results") != "false" ||
				payload["_source"] != false || payload["track_total_hits"] != false || payload["size"] != float64(3) ||
				pit["id"] != "pit-version-1" || payload["query"] == nil || len(payload["fields"].([]any)) != 3 ||
				len(payload["sort"].([]any)) != 3 || payload["search_after"] != nil {
				http.Error(writer, "invalid PIT search", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write(readElasticFixture(t, "pit-search-page.json"))
		case 4:
			if request.Method != http.MethodDelete || request.URL.Path != "/_pit" || payload["id"] != "pit-version-2" {
				http.Error(writer, "invalid PIT close", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write(readElasticFixture(t, "pit-close-response.json"))
		default:
			http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	credentials := &credentialStub{secret: []byte("key"), decision: testDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	plan := testQueryDSLPlan(t)
	targets := []string{"logs-security-000001"}
	binding := func(operation string) CallBinding {
		return CallBinding{Scope: testScope(), Authority: testAuthority(), Operation: operation, Targets: targets}
	}
	validated, _, err := client.ValidateQuery(context.Background(), QueryValidationRequest{Binding: binding("elastic.query.validate"), Indices: targets, Plan: plan})
	if err != nil || !validated.Valid || validated.ResultDigest == "" {
		t.Fatalf("validation=%+v err=%v", validated, err)
	}
	opened, _, err := client.OpenPIT(context.Background(), OpenPITRequest{Binding: binding("elastic.pit.open"), Indices: targets, Plan: plan, KeepAlive: 30 * time.Second})
	if err != nil || opened.ID != "pit-version-1" || opened.PITDigest == "" {
		t.Fatalf("open=%+v err=%v", opened, err)
	}
	searched, _, err := client.SearchPIT(context.Background(), SearchPITRequest{Binding: binding("elastic.pit.search"), Indices: targets, Plan: plan, PITID: opened.ID, KeepAlive: 30 * time.Second, Size: 3})
	if err != nil || searched.PITID != "pit-version-2" || len(searched.Hits) != 3 || searched.Hits[0].Row["event_id"] != "event-1" ||
		searched.Hits[0].Sort[2] != int64(1) || searched.ResultDigest == "" {
		t.Fatalf("search=%+v err=%v", searched, err)
	}
	closed, _, err := client.ClosePIT(context.Background(), ClosePITRequest{Binding: binding("elastic.pit.close"), Indices: targets, PITID: searched.PITID})
	if err != nil || !closed.Succeeded || closed.Freed != 1 || closed.ResultDigest == "" {
		t.Fatalf("close=%+v err=%v", closed, err)
	}
	if credentials.uses != 4 || len(calls) != 4 {
		t.Fatalf("uses=%d calls=%v", credentials.uses, calls)
	}
}

func TestQueryDSLTransportRejectsBindingAndSearchAfterSubstitution(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(readElasticFixture(t, "pit-search-page.json"))
	}))
	defer server.Close()
	config, roots := httpTestConfig(t, server)
	client, _ := NewHTTPClient(config, &credentialStub{secret: []byte("key"), decision: testDigest("8")}, roots)
	plan, targets := testQueryDSLPlan(t), []string{"logs-security-000001"}
	binding := CallBinding{Scope: testScope(), Authority: testAuthority(), Operation: "elastic.pit.search", Targets: targets}
	badBinding := binding
	badBinding.Targets = []string{"other-index"}
	request := SearchPITRequest{Binding: badBinding, Indices: targets, Plan: plan, PITID: "pit-version-1", KeepAlive: time.Minute, Size: 3}
	if _, _, err := client.SearchPIT(context.Background(), request); err == nil {
		t.Fatal("target substitution accepted")
	}
	request.Binding, request.SearchAfter = binding, []any{"2026-08-27T17:00:00Z", "event-1", "not-an-integer"}
	if _, _, err := client.SearchPIT(context.Background(), request); queryconnector.Reason(err) != "elastic_pit_search_request_invalid" &&
		queryconnector.Reason(err) != "elastic_search_after_invalid" {
		t.Fatalf("search_after err=%v", err)
	}
}

func TestQueryDSLResponseFailsClosedOnCompletenessAndShapeDrift(t *testing.T) {
	plan := testQueryDSLPlan(t).Value()
	base := readElasticFixture(t, "pit-search-page.json")
	cases := map[string]struct {
		mutate func(map[string]any)
		reason string
	}{
		"timeout":       {func(v map[string]any) { v["timed_out"] = true }, "elastic_pit_search_response_incomplete"},
		"shard-failure": {func(v map[string]any) { v["_shards"].(map[string]any)["failed"] = float64(1) }, "elastic_pit_search_response_incomplete"},
		"clusters":      {func(v map[string]any) { v["_clusters"] = map[string]any{"total": 1} }, "elastic_pit_search_response_incomplete"},
		"bad-pit":       {func(v map[string]any) { v["pit_id"] = "" }, "elastic_pit_search_response_incomplete"},
		"source":        {func(v map[string]any) { firstHit(v)["_source"] = map[string]any{"secret": "x"} }, "elastic_pit_search_hit_invalid"},
		"score":         {func(v map[string]any) { firstHit(v)["_score"] = float64(1) }, "elastic_pit_search_hit_invalid"},
		"target-drift":  {func(v map[string]any) { firstHit(v)["_index"] = "other-index" }, "elastic_pit_search_hit_invalid"},
		"extra-field":   {func(v map[string]any) { firstHit(v)["fields"].(map[string]any)["secret"] = []any{"x"} }, "elastic_pit_search_hit_invalid"},
		"multivalue":    {func(v map[string]any) { firstHit(v)["fields"].(map[string]any)["event.id"] = []any{"a", "b"} }, "elastic_pit_search_fields_invalid"},
		"sort-shape":    {func(v map[string]any) { firstHit(v)["sort"] = []any{"only-one"} }, "elastic_search_after_invalid"},
		"null-sort":     {func(v map[string]any) { firstHit(v)["sort"].([]any)[1] = nil }, "elastic_search_after_invalid"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(base, &value) != nil {
				t.Fatal("fixture")
			}
			test.mutate(value)
			encoded, _ := json.Marshal(value)
			_, err := decodeSearchPIT(encoded, plan, []string{"logs-security-000001"}, 3)
			if queryconnector.Reason(err) != test.reason {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestQueryDSLResponseRepresentsMissingProjectedFieldAsNull(t *testing.T) {
	var value map[string]any
	if json.Unmarshal(readElasticFixture(t, "pit-search-page.json"), &value) != nil {
		t.Fatal("fixture")
	}
	delete(firstHit(value)["fields"].(map[string]any), "message")
	encoded, _ := json.Marshal(value)
	result, err := decodeSearchPIT(encoded, testQueryDSLPlan(t).Value(), []string{"logs-security-000001"}, 3)
	if err != nil || result.Hits[0].Row["message"] != nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestQueryDSLValidationOpenAndCloseResponsesFailClosed(t *testing.T) {
	validation := []byte(`{"valid":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0,"failures":[]}}`)
	if _, err := decodeQueryValidation(validation); queryconnector.Reason(err) != "elastic_querydsl_vendor_validation_denied" {
		t.Fatalf("validation err=%v", err)
	}
	open := []byte(`{"id":"pit","_shards":{"total":1,"successful":0,"skipped":0,"failed":1,"failures":[{}]}}`)
	if _, err := decodeOpenPIT(open); queryconnector.Reason(err) != "elastic_pit_open_response_invalid" {
		t.Fatalf("open err=%v", err)
	}
	if _, err := decodeClosePIT([]byte(`{"succeeded":false,"num_freed":0}`)); queryconnector.Reason(err) != "elastic_pit_close_unconfirmed" {
		t.Fatalf("close err=%v", err)
	}
	duplicate := []byte(`{"valid":true,"valid":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0,"failures":[]}}`)
	if _, err := decodeQueryValidation(duplicate); queryconnector.Reason(err) != "elastic_querydsl_vendor_validation_denied" {
		t.Fatalf("duplicate vendor key err=%v", err)
	}
}

func firstHit(value map[string]any) map[string]any {
	return value["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
}

func testQueryDSLPlan(t testing.TB) elasticquerydsl.ValidatedPlan {
	t.Helper()
	compiler, err := elasticquerydsl.New(elasticquerydsl.Definition{SourceID: "elastic-prod", Resources: []string{"securityevent"},
		Fields: []elasticquerydsl.FieldRule{
			{Name: "event_id", VendorName: "event.id", Type: "string", Projectable: true, Exact: true, Sortable: true},
			{Name: "event_timestamp", VendorName: "@timestamp", Type: "timestamp", Projectable: true, Exact: true, Range: true, Sortable: true},
			{Name: "message", VendorName: "message", Type: "string", Projectable: true, TextSearchable: true},
		}, Projection: []string{"event_timestamp", "event_id", "message"}, StableSort: []elasticquerydsl.SortField{{Name: "event_timestamp", Direction: "ASC"}, {Name: "event_id", Direction: "ASC"}},
		TimestampField: "event_timestamp", HardMaximumRows: 10, HardMaximumPages: 3, HardPageRows: 2})
	if err != nil {
		t.Fatal(err)
	}
	queryValue := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: testID("5"), Scope: testScope(), Authority: testAuthority(), CapabilityDigest: testDigest("5"), SchemaDigest: testDigest("6"),
		Language: "elastic-query-dsl", NativeText: `{"match":{"message":{"query":"credential access","operator":"and"}}}`,
		TimeRange:   queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits:      queryconnector.Limits{MaximumRows: 10, MaximumBytes: 100000, MaximumDurationMillis: 5000, MaximumPages: 3, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2},
		RequestedAt: "2026-08-27T16:59:00.000000000Z", Deadline: "2026-08-27T18:01:00.000000000Z"}
	queryBytes, _ := json.Marshal(queryValue)
	query, err := queryconnector.DecodeQuery(context.Background(), queryBytes)
	if err != nil {
		t.Fatal(err)
	}
	schemaValue := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		RequestID: testID("6"), SchemaDigest: testDigest("6"), Entries: []queryconnector.SchemaEntry{
			{ResourceID: "securityevent", Name: "event_id", Type: "string"}, {ResourceID: "securityevent", Name: "event_timestamp", Type: "timestamp"},
			{ResourceID: "securityevent", Name: "message", Type: "string"}}, Complete: true, ProvenanceDigest: testDigest("7")}
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

func TestQueryDSLFixtureManifestContainsNoSensitiveValues(t *testing.T) {
	var manifest struct {
		SchemaVersion   string   `json:"schema_version"`
		SensitiveValues string   `json:"sensitive_values"`
		Records         []string `json:"records"`
	}
	if json.Unmarshal(readElasticFixture(t, "querydsl-fixture-manifest.json"), &manifest) != nil ||
		manifest.SchemaVersion != "coh.elastic-querydsl-vendor-fixture/v1" || manifest.SensitiveValues != "none" || len(manifest.Records) != 4 {
		t.Fatalf("manifest=%+v", manifest)
	}
	for _, record := range manifest.Records {
		content := string(readElasticFixture(t, record))
		if strings.Contains(strings.ToLower(content), "api_key") {
			t.Fatalf("sensitive fixture %s", record)
		}
	}
}
