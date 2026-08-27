package elasticesql

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestCompilerRebuildsParameterizedBoundedPipeline(t *testing.T) {
	compiler := testCompiler(t)
	query := testQuery(t, "FROM securityevent | WHERE source_ip == \"10.0.0.1\" AND message != \"credential-value\" | KEEP event_timestamp, message | SORT event_timestamp DESC | LIMIT 500")
	validation, plan, err := compiler.Validate(context.Background(), query, testSchema(t))
	if err != nil || validation.Value().Outcome != "accepted" || plan == nil {
		t.Fatalf("validation=%+v plan=%+v err=%v", validation.Value(), plan, err)
	}
	value := plan.Value()
	want := "FROM securityevent | WHERE (source.ip == ? AND message != ?) | KEEP @timestamp, message, event.id | SORT @timestamp DESC, event.id ASC | LIMIT 100"
	if value.CanonicalPipeline != want || value.MaximumRows != 100 || len(value.Parameters) != 2 ||
		value.Parameters[0].Type != "ip" || value.Parameters[0].Value != "10.0.0.1" ||
		value.Parameters[1].Type != "string" || value.Parameters[1].Value != "credential-value" {
		t.Fatalf("plan=%+v", value)
	}
	if strings.Contains(value.CanonicalPipeline, "10.0.0.1") || strings.Contains(value.CanonicalPipeline, "credential-value") {
		t.Fatalf("canonical pipeline leaked literals: %s", value.CanonicalPipeline)
	}
	filter, _ := json.Marshal(value.MandatoryFilter)
	if !strings.Contains(string(filter), testID("2")) || !strings.Contains(string(filter), "2026-08-27T17:00:00.000000000Z") {
		t.Fatalf("mandatory filter=%s", filter)
	}
	copyValue := plan.Value()
	copyValue.Parameters[0].Value = "changed"
	copyValue.MandatoryFilter["changed"] = true
	if plan.Value().Parameters[0].Value != "10.0.0.1" || plan.Value().MandatoryFilter["changed"] != nil {
		t.Fatal("validated plan exposed mutable state")
	}
}

func TestCompilerAddsSafeDefaults(t *testing.T) {
	validation, plan, err := testCompiler(t).Validate(context.Background(), testQuery(t, "from securityevent"), testSchema(t))
	if err != nil || validation.Value().Outcome != "accepted" {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	want := "FROM securityevent | KEEP @timestamp, event.id, message | SORT @timestamp DESC, event.id ASC | LIMIT 100"
	if plan.Value().CanonicalPipeline != want || len(plan.Value().Parameters) != 0 {
		t.Fatalf("plan=%+v", plan.Value())
	}
}

func TestCompilerDenialCorpus(t *testing.T) {
	cases := map[string]struct{ text, reason string }{
		"fork":             {"FROM securityevent | FORK (WHERE message == \"x\") (WHERE message == \"y\")", "esql_command_unsupported"},
		"source-widening":  {"FROM securityevent,other", "esql_pipeline_invalid"},
		"wildcard-source":  {"FROM securityevent*", "esql_character_unsupported"},
		"comment":          {"FROM securityevent // bypass", "esql_character_unsupported"},
		"directive":        {"SET time_zone = \"UTC\"; FROM securityevent", "esql_operator_unsupported"},
		"semicolon":        {"FROM securityevent; | LIMIT 1", "esql_character_unsupported"},
		"subquery":         {"FROM securityevent | WHERE event_id == (FROM other)", "esql_filter_field_denied"},
		"function":         {"FROM securityevent | WHERE KQL(\"*\") == true", "esql_filter_field_denied"},
		"field-wildcard":   {"FROM securityevent | KEEP message*", "esql_character_unsupported"},
		"unknown-field":    {"FROM securityevent | KEEP secret.value", "esql_field_denied"},
		"unfilterable":     {"FROM securityevent | WHERE event_id == \"x\"", "esql_filter_field_denied"},
		"wrong-literal":    {"FROM securityevent | WHERE source_ip == 42", "esql_literal_type_mismatch"},
		"invalid-ip":       {"FROM securityevent | WHERE source_ip == \"not-an-ip\"", "esql_ip_invalid"},
		"zero-limit":       {"FROM securityevent | LIMIT 0", "esql_limit_invalid"},
		"negative-limit":   {"FROM securityevent | LIMIT -1", "esql_limit_invalid"},
		"duplicate-limit":  {"FROM securityevent | LIMIT 1 | LIMIT 1", "esql_command_order_invalid"},
		"nonfinal-limit":   {"FROM securityevent | LIMIT 1 | SORT event_timestamp", "esql_command_order_invalid"},
		"repeated-where":   {"FROM securityevent | WHERE message == \"a\" | WHERE message == \"b\"", "esql_command_order_invalid"},
		"triple-string":    {"FROM securityevent | WHERE message == \"\"\"x\"\"\"", "esql_string_invalid"},
		"boolean-mismatch": {"FROM securityevent | WHERE enabled == \"true\"", "esql_literal_type_mismatch"},
		"integer-overflow": {"FROM securityevent | WHERE event_sequence == 999999999999999999999999", "esql_integer_invalid"},
		"quoted-field":     {"FROM securityevent | KEEP \"message\"", "esql_field_required"},
		"backtick-field":   {"FROM securityevent | KEEP \x60message\x60", "esql_character_unsupported"},
		"other-source":     {"FROM other", "esql_resource_denied"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			validation, plan, err := testCompiler(t).Validate(context.Background(), testQuery(t, test.text), testSchema(t))
			if err != nil || plan != nil || validation.Value().Outcome != "denied" ||
				len(validation.Value().ReasonCodes) != 1 || validation.Value().ReasonCodes[0] != test.reason ||
				validation.Value().ProvenanceDigest == "" {
				t.Fatalf("validation=%+v plan=%+v err=%v", validation.Value(), plan, err)
			}
		})
	}
}

func TestCompilerBindsSchemaAndSupportsCancellation(t *testing.T) {
	compiler := testCompiler(t)
	query := testQuery(t, "FROM securityevent")
	schemaValue := testSchema(t).Value()
	schemaValue.Entries[0].ResourceID = "other"
	validation, plan, err := compiler.Validate(context.Background(), query, decodeSchema(t, schemaValue))
	if err != nil || plan != nil || validation.Value().Outcome != "denied" {
		t.Fatalf("validation=%+v plan=%+v err=%v", validation.Value(), plan, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := compiler.Validate(canceled, query, testSchema(t)); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("cancel err=%v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, _, err := compiler.Validate(deadline, query, testSchema(t)); queryconnector.Code(err) != queryconnector.Timeout {
		t.Fatalf("timeout err=%v", err)
	}
}

func testCompiler(t testing.TB) *Compiler {
	t.Helper()
	compiler, err := New(testDefinition())
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

func testDefinition() Definition {
	return Definition{SourceID: "elastic-prod", Resources: []string{"securityevent"},
		Fields: []FieldRule{
			{Name: "enabled", VendorName: "enabled", Type: "boolean", Projectable: true, Filterable: true},
			{Name: "event_id", VendorName: "event.id", Type: "string", Projectable: true, Sortable: true},
			{Name: "event_sequence", VendorName: "event.sequence", Type: "integer", Projectable: true, Filterable: true, Sortable: true},
			{Name: "event_timestamp", VendorName: "@timestamp", Type: "timestamp", Projectable: true, Filterable: true, Sortable: true},
			{Name: "message", VendorName: "message", Type: "string", Projectable: true, Filterable: true},
			{Name: "source_ip", VendorName: "source.ip", Type: "ip", Projectable: true, Filterable: true, Sortable: true},
			{Name: "tenant_id", VendorName: "tenant.id", Type: "string", Filterable: true},
		},
		DefaultProjection: []string{"event_timestamp", "event_id", "message"},
		StableSort:        []SortField{{Name: "event_timestamp", Direction: "DESC"}, {Name: "event_id", Direction: "ASC"}},
		TimestampField:    "event_timestamp", TenantField: "tenant_id", HardMaximumRows: 200}
}

func testQuery(t testing.TB, native string) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: testID("5"), Scope: queryconnector.Scope{OrganizationID: testID("1"), TenantID: testID("2"),
			CaseID: testID("3"), SourceID: "elastic-prod", ResourceIDs: []string{"securityevent"}},
		Authority: queryconnector.AuthorityBinding{ActorID: testID("4"), AuthorizationDigest: testDigest("1"),
			PolicyDecisionDigest: testDigest("2"), AuditReservationDigest: testDigest("3")},
		CapabilityDigest: testDigest("4"), SchemaDigest: testDigest("5"), Language: "esql", NativeText: native,
		TimeRange: queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits: queryconnector.Limits{MaximumRows: 100, MaximumBytes: 100000, MaximumDurationMillis: 5000,
			MaximumPages: 2, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2},
		RequestedAt: "2026-08-27T16:59:00.000000000Z", Deadline: "2026-08-27T18:01:00.000000000Z"}
	return decodeQuery(t, value)
}

func testSchema(t testing.TB) queryconnector.ValidatedSchemaPage {
	t.Helper()
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, RequestID: testID("6"), SchemaDigest: testDigest("5"),
		Entries: []queryconnector.SchemaEntry{
			{ResourceID: "securityevent", Name: "enabled", Type: "boolean"},
			{ResourceID: "securityevent", Name: "event_id", Type: "string"},
			{ResourceID: "securityevent", Name: "event_sequence", Type: "integer"},
			{ResourceID: "securityevent", Name: "event_timestamp", Type: "timestamp"},
			{ResourceID: "securityevent", Name: "message", Type: "string"},
			{ResourceID: "securityevent", Name: "source_ip", Type: "ip"},
			{ResourceID: "securityevent", Name: "tenant_id", Type: "string"},
		}, Complete: true, ProvenanceDigest: testDigest("6")}
	return decodeSchema(t, value)
}

func decodeQuery(t testing.TB, value queryconnector.Query) queryconnector.ValidatedQuery {
	t.Helper()
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func decodeSchema(t testing.TB, value queryconnector.SchemaPage) queryconnector.ValidatedSchemaPage {
	t.Helper()
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeSchemaPage(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func testID(value string) string     { return "018f1f2e-7a6b-7c8d-8e9f-00000000000" + value }
func testDigest(value string) string { return "sha256:" + strings.Repeat("0", 63) + value }
