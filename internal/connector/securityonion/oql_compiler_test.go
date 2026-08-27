package securityonion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestOQLCompilerBuildsMandatoryBoundedEscapedEventPlan(t *testing.T) {
	compiler, qualification := testOQLCompiler(t)
	query := testOQLQuery(t, `{"mode":"events","filter":{"bool":{"filter":[{"term":{"source_ip":"10.0.0.1"}},{"terms":{"event_sequence":[3,1,2]}}],"should":[{"term":{"event_id":"x | groupby secret"}},{"exists":{"field":"message"}}],"minimum_should_match":1}}}`)
	validation, plan, err := compiler.Validate(context.Background(), query, testOQLSchema(t), qualification)
	if err != nil || plan == nil || validation.Value().Outcome != "accepted" || validation.Value().ProvenanceDigest != plan.Digest() {
		t.Fatalf("validation=%+v plan=%+v err=%v", validation.Value(), plan, err)
	}
	value := plan.Value()
	for _, required := range []string{`tenant.id:"`, `observer.name:"security\-onion\-prod"`, `event.id:"x \| groupby secret"`,
		"| table @timestamp event.id message source.ip", "| sortby @timestamp^ event.id^"} {
		if !strings.Contains(value.RenderedQuery, required) {
			t.Fatalf("rendered query missing %q: %s", required, value.RenderedQuery)
		}
	}
	if strings.Count(value.RenderedQuery, " | ") != 2 || value.EventLimit != 10 || value.MetricLimit != 1 ||
		value.Zone != "UTC" || value.Format != connectRangeLayout || len(value.Columns) != 4 || len(value.GroupBy) != 0 ||
		value.QualificationDigest != qualification.Digest() || value.PlanDigest != plan.Digest() {
		t.Fatalf("plan=%+v", value)
	}
	copyValue := plan.Value()
	copyValue.Columns[0].VendorName = "changed"
	if plan.Value().Columns[0].VendorName == "changed" {
		t.Fatal("plan exposed mutable columns")
	}
}

func TestOQLCompilerBuildsMetricPlanAndCanonicalizesSets(t *testing.T) {
	compiler, qualification := testOQLCompiler(t)
	first := testOQLQuery(t, `{"mode":"metrics","filter":{"terms":{"event_sequence":[3,1,2]}},"group_by":["source_ip"]}`)
	second := testOQLQuery(t, `{"mode":"metrics","filter":{"terms":{"event_sequence":[2,3,1]}},"group_by":["source_ip"]}`)
	_, planOne, err := compiler.Validate(context.Background(), first, testOQLSchema(t), qualification)
	if err != nil {
		t.Fatal(err)
	}
	_, planTwo, err := compiler.Validate(context.Background(), second, testOQLSchema(t), qualification)
	if err != nil || planOne.Value().RenderedQuery != planTwo.Value().RenderedQuery ||
		!strings.HasSuffix(planOne.Value().RenderedQuery, " | groupby source.ip") || planOne.Value().MetricLimit != 10 || planOne.Value().EventLimit != 1 {
		t.Fatalf("one=%+v two=%+v err=%v", planOne.Value(), planTwo.Value(), err)
	}
}

func TestOQLCompilerDenialCorpus(t *testing.T) {
	compiler, qualification := testOQLCompiler(t)
	cases := map[string]struct{ text, reason string }{
		"duplicate":       {`{"mode":"events","mode":"metrics","filter":{"match_all":{}}}`, "securityonion_oql_json_invalid"},
		"script":          {`{"mode":"events","filter":{"script":{"source":"x"}}}`, "securityonion_oql_operator_unsupported"},
		"unknown-root":    {`{"mode":"events","filter":{"match_all":{}},"pipeline":"| grid"}`, "securityonion_oql_document_invalid"},
		"unknown-field":   {`{"mode":"events","filter":{"term":{"secret":"x"}}}`, "securityonion_oql_exact_field_denied"},
		"float":           {`{"mode":"events","filter":{"term":{"event_sequence":1.5}}}`, "securityonion_oql_json_invalid"},
		"wrong-type":      {`{"mode":"events","filter":{"term":{"event_sequence":"1"}}}`, "securityonion_oql_literal_type_mismatch"},
		"bad-range":       {`{"mode":"events","filter":{"range":{"message":{"gte":"a"}}}}`, "securityonion_oql_range_field_denied"},
		"contradictory":   {`{"mode":"events","filter":{"range":{"event_sequence":{"gte":9,"lt":9}}}}`, "securityonion_oql_range_contradictory"},
		"events-group":    {`{"mode":"events","filter":{"match_all":{}},"group_by":["source_ip"]}`, "securityonion_oql_group_invalid"},
		"metric-no-group": {`{"mode":"metrics","filter":{"match_all":{}}}`, "securityonion_oql_group_required"},
		"group-denied":    {`{"mode":"metrics","filter":{"match_all":{}},"group_by":["message"]}`, "securityonion_oql_group_field_denied"},
		"bool-min":        {`{"mode":"events","filter":{"bool":{"should":[{"match_all":{}}]}}}`, "securityonion_oql_bool_invalid"},
		"raw-string":      {`tags:conn | groupby secret`, "securityonion_oql_json_invalid"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			validation, plan, err := compiler.Validate(context.Background(), testOQLQuery(t, test.text), testOQLSchema(t), qualification)
			if err != nil || plan != nil || validation.Value().Outcome != "denied" || len(validation.Value().ReasonCodes) != 1 ||
				validation.Value().ReasonCodes[0] != test.reason {
				t.Fatalf("validation=%+v plan=%+v err=%v", validation.Value(), plan, err)
			}
		})
	}
}

func TestOQLCompilerBindsLanguageSchemaQualificationAndCancellation(t *testing.T) {
	compiler, qualification := testOQLCompiler(t)
	queryValue := testOQLQuery(t, `{"mode":"events","filter":{"match_all":{}}}`).Value()
	queryValue.Language = "oql"
	validation, plan, err := compiler.Validate(context.Background(), decodeOQLQuery(t, queryValue), testOQLSchema(t), qualification)
	if err != nil || plan != nil || validation.Value().ReasonCodes[0] != "securityonion_oql_binding_invalid" {
		t.Fatal("language substitution accepted")
	}
	schemaValue := testOQLSchema(t).Value()
	schemaValue.Entries[0].Type = "boolean"
	validation, plan, err = compiler.Validate(context.Background(), testOQLQuery(t, `{"mode":"events","filter":{"match_all":{}}}`), decodeOQLSchema(t, schemaValue), qualification)
	if err != nil || plan != nil || validation.Value().ReasonCodes[0] != "securityonion_oql_schema_field_mismatch" {
		t.Fatal("schema drift accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := compiler.Validate(canceled, testOQLQuery(t, `{"mode":"events","filter":{"match_all":{}}}`), testOQLSchema(t), qualification); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("cancel err=%v", err)
	}
}

func testOQLCompiler(t testing.TB) (*OQLCompiler, ValidatedQualification) {
	t.Helper()
	clock := fixedClock{time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)}
	compiler, err := NewOQLCompiler(testConfig(), clock)
	if err != nil {
		t.Fatal(err)
	}
	qualifier, _ := NewQualifier(testConfig(), clock)
	qualification, err := qualifier.Qualify(context.Background(), testOpenAPI(t))
	if err != nil {
		t.Fatal(err)
	}
	return compiler, qualification
}

func testOQLQuery(t testing.TB, native string) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: testID("5"), Scope: queryconnector.Scope{OrganizationID: testID("1"), TenantID: testID("2"), CaseID: testID("3"), SourceID: "security-onion-prod", ResourceIDs: []string{"securityevent"}},
		Authority:        queryconnector.AuthorityBinding{ActorID: testID("4"), AuthorizationDigest: testDigest("3"), PolicyDecisionDigest: testDigest("4"), AuditReservationDigest: testDigest("5")},
		CapabilityDigest: testDigest("6"), SchemaDigest: testDigest("7"), Language: "security-onion-oql", NativeText: native,
		TimeRange:   queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits:      queryconnector.Limits{MaximumRows: 10, MaximumBytes: 100000, MaximumDurationMillis: 5000, MaximumPages: 1, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2},
		RequestedAt: "2026-08-27T16:59:00.000000000Z", Deadline: "2026-08-27T18:01:00.000000000Z"}
	return decodeOQLQuery(t, value)
}

func testOQLSchema(t testing.TB) queryconnector.ValidatedSchemaPage {
	t.Helper()
	entries := make([]queryconnector.SchemaEntry, len(testConfig().Fields))
	for index, field := range testConfig().Fields {
		entries[index] = queryconnector.SchemaEntry{ResourceID: "securityevent", Name: field.LogicalName, Type: field.Type}
	}
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		RequestID: testID("6"), SchemaDigest: testDigest("7"), Entries: entries, Complete: true, ProvenanceDigest: testDigest("8")}
	return decodeOQLSchema(t, value)
}

func decodeOQLQuery(t testing.TB, value queryconnector.Query) queryconnector.ValidatedQuery {
	t.Helper()
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeOQLSchema(t testing.TB, value queryconnector.SchemaPage) queryconnector.ValidatedSchemaPage {
	t.Helper()
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeSchemaPage(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testID(value string) string { return "018f1f2e-7a6b-7c8d-8e9f-00000000000" + value }
