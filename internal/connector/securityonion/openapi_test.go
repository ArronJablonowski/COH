package securityonion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func TestQualifierBindsOnlyExactReadOperations(t *testing.T) {
	qualifier, err := NewQualifier(testConfig(), fixedClock{time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	document := testOpenAPI(t)
	first, err := qualifier.Qualify(context.Background(), document)
	if err != nil {
		t.Fatal(err)
	}
	second, err := qualifier.Qualify(context.Background(), document)
	value := first.Value()
	if err != nil || second.Digest() != first.Digest() || value.Digest != first.Digest() ||
		value.SourceID != "security-onion-prod" || value.SecurityScheme != "bearer" || len(value.Operations) != 2 ||
		value.Operations[0].Path != "/connect/events/" || value.Operations[1].Path != "/connect/info/" ||
		strings.Contains(string(mustJSON(t, value)), "/connect/case/") {
		t.Fatalf("qualification=%+v second=%s err=%v", value, second.Digest(), err)
	}
	copyValue := first.Value()
	copyValue.Operations[0].RequiredParameters[0] = "changed"
	if first.Value().Operations[0].RequiredParameters[0] == "changed" {
		t.Fatal("qualification exposed mutable state")
	}
}

func TestQualifierRejectsAmbiguityAndContractDrift(t *testing.T) {
	qualifier, err := NewQualifier(testConfig(), fixedClock{time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := []byte(`{"openapi":"3.0.3","openapi":"3.1.0","paths":{},"components":{}}`)
	if _, err := qualifier.Qualify(context.Background(), duplicate); queryconnector.Reason(err) != "securityonion_openapi_invalid" {
		t.Fatalf("duplicate err=%v", err)
	}
	cases := map[string]func(map[string]any){
		"missing-events": func(value map[string]any) { delete(value["paths"].(map[string]any), "/connect/events/") },
		"method-drift": func(value map[string]any) {
			operation := value["paths"].(map[string]any)["/connect/events/"].(map[string]any)
			operation["post"], operation["get"] = operation["get"], nil
		},
		"parameter-drift": func(value map[string]any) {
			operation := value["paths"].(map[string]any)["/connect/events/"].(map[string]any)["get"].(map[string]any)
			operation["parameters"].([]any)[0].(map[string]any)["required"] = false
		},
		"security-drift": func(value map[string]any) {
			value["components"].(map[string]any)["securitySchemes"] = map[string]any{"api": map[string]any{"type": "apiKey"}}
		},
		"media-drift": func(value map[string]any) {
			operation := value["paths"].(map[string]any)["/connect/info/"].(map[string]any)["get"].(map[string]any)
			operation["responses"].(map[string]any)["200"].(map[string]any)["content"] = map[string]any{"text/plain": map[string]any{}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := decodeMap(t, testOpenAPI(t))
			mutate(value)
			if _, err := qualifier.Qualify(context.Background(), mustJSON(t, value)); queryconnector.Code(err) != queryconnector.Conflict {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestConfigDeniesUnsafeOriginSecretAndPermissionExpansion(t *testing.T) {
	valid := testConfig()
	cases := []Config{valid, valid, valid, valid}
	cases[0].Endpoint = "http://manager.example"
	cases[1].Endpoint = "https://user:secret@manager.example"
	cases[2].CredentialReference = "raw secret"
	cases[3].Permissions = []string{"cases/read", "events/read"}
	for index, value := range cases {
		if _, err := NewQualifier(value, fixedClock{time.Now()}); err == nil {
			t.Fatalf("unsafe config %d accepted", index)
		}
	}
}

func testConfig() Config {
	return Config{SourceID: "security-onion-prod", AdapterVersion: "security-onion-1.0.0",
		Endpoint: "https://manager.example", CredentialReference: "security-onion-query-client",
		TLSRootDigest: testDigest("1"), TransportIdentityDigest: testDigest("2"), Permissions: []string{"events/read"},
		Resources: []Resource{{ID: "securityevent"}}, Fields: []Field{
			{LogicalName: "event_id", VendorName: "event.id", Type: "string", Exact: true, Exists: true, Projectable: true, Sortable: true},
			{LogicalName: "event_sequence", VendorName: "event.sequence", Type: "integer", Exact: true, Range: true, Exists: true, Projectable: true},
			{LogicalName: "event_timestamp", VendorName: "@timestamp", Type: "timestamp", Exact: true, Range: true, Exists: true, Projectable: true, Sortable: true},
			{LogicalName: "message", VendorName: "message", Type: "string", Exists: true, Projectable: true},
			{LogicalName: "source_id", VendorName: "observer.name", Type: "string", Exact: true},
			{LogicalName: "source_ip", VendorName: "source.ip", Type: "ip", Exact: true, Range: true, Exists: true, Projectable: true, Groupable: true},
			{LogicalName: "tenant_id", VendorName: "tenant.id", Type: "string", Exact: true}},
		Projection: []string{"event_timestamp", "event_id", "message", "source_ip"}, StableSort: []string{"event_timestamp", "event_id"},
		TimestampField: "event_timestamp", TenantField: "tenant_id", SourceField: "source_id",
		HardLimits: queryconnector.Limits{MaximumRows: 1000, MaximumBytes: 1048576, MaximumDurationMillis: 60000,
			MaximumPages: 1, MaximumSlices: 4, MaximumCostMillionths: 1000000, RequestsPerMinute: 12},
		MaximumInterval: 24 * time.Hour, MaximumEventLimit: 1000, MaximumMetricLimit: 100,
		MaximumOpenAPIBytes: 1048576, QualificationLifetime: 10 * time.Minute}
}

func testOpenAPI(t testing.TB) []byte {
	t.Helper()
	parameter := func(name, kind string) map[string]any {
		return map[string]any{"name": name, "in": "query", "required": true, "schema": map[string]any{"type": kind}}
	}
	operation := func(parameters []any, responseType string) map[string]any {
		return map[string]any{"parameters": parameters, "security": []any{map[string]any{"bearer": []any{}}},
			"responses": map[string]any{"200": map[string]any{"content": map[string]any{"application/json": map[string]any{
				"schema": map[string]any{"type": responseType}}}}}}
	}
	parameters := []any{parameter("query", "string"), parameter("range", "string"), parameter("zone", "string"),
		parameter("format", "string"), parameter("metricLimit", "integer"), parameter("eventLimit", "integer")}
	value := map[string]any{"openapi": "3.0.3", "components": map[string]any{"securitySchemes": map[string]any{
		"bearer": map[string]any{"type": "http", "scheme": "bearer"}}}, "paths": map[string]any{
		"/connect/events/": map[string]any{"get": operation(parameters, "array")},
		"/connect/info/":   map[string]any{"get": operation(nil, "object")},
		"/connect/case/":   map[string]any{"post": map[string]any{"responses": map[string]any{}}}}}
	return mustJSON(t, value)
}

func decodeMap(t testing.TB, input []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if json.Unmarshal(input, &value) != nil {
		t.Fatal("json")
	}
	return value
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }
