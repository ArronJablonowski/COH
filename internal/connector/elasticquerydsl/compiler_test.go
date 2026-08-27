package elasticquerydsl

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestCompilerRebuildsTypedMandatoryBoundedPlan(t *testing.T) {
	native := `{"bool":{"filter":[{"term":{"enabled":true}},{"terms":{"event_sequence":[3,1,2]}},{"range":{"source_ip":{"gte":"10.0.0.1","lt":"10.0.0.9"}}}],"should":[{"match":{"message":{"query":"credential access","operator":"and"}}},{"match_phrase":{"message":{"query":"remote service","slop":0}}}],"minimum_should_match":1}}`
	query := testQuery(t, native)
	validation, plan, err := testCompiler(t).Validate(context.Background(), query, testSchema(t))
	if err != nil || validation.Value().Outcome != "accepted" || plan == nil ||
		validation.Value().ProvenanceDigest != plan.Digest() || validation.Value().CanonicalQueryDigest != query.Digest() {
		t.Fatalf("validation=%+v plan=%+v err=%v", validation.Value(), plan, err)
	}
	value := plan.Value()
	if value.MaximumRows != 100 || value.MaximumPages != 2 || value.PageRows != 25 || len(value.Columns) != 3 ||
		len(value.Sort) != 3 || value.Sort[2].VendorName != "_shard_doc" || value.Sort[2].Direction != "ASC" ||
		value.CallerQueryDigest == "" || value.MandatoryFilterDigest == "" || value.PlanDigest != plan.Digest() {
		t.Fatalf("plan=%+v", value)
	}
	encoded, _ := json.Marshal(value.CanonicalQuery)
	text := string(encoded)
	for _, required := range []string{"@timestamp", testID("2"), "event.sequence", "source.ip", "credential access"} {
		if !strings.Contains(text, required) {
			t.Fatalf("canonical query missing %q: %s", required, text)
		}
	}
	if !strings.Contains(text, `"event.sequence":[1,2,3]`) {
		t.Fatalf("terms were not normalized: %s", text)
	}
	copyValue := plan.Value()
	copyValue.CanonicalQuery["changed"] = true
	copyValue.Columns[0].VendorName = "changed"
	if plan.Value().CanonicalQuery["changed"] != nil || plan.Value().Columns[0].VendorName == "changed" {
		t.Fatal("validated plan exposed mutable state")
	}
}

func TestCompilerCanonicalizesEquivalentTermSets(t *testing.T) {
	first, planOne, err := testCompiler(t).Validate(context.Background(), testQuery(t,
		`{"terms":{"event_sequence":[3,1,2]}}`), testSchema(t))
	if err != nil || first.Value().Outcome != "accepted" {
		t.Fatal(err)
	}
	second, planTwo, err := testCompiler(t).Validate(context.Background(), testQuery(t,
		`{"terms":{"event_sequence":[2,3,1]}}`), testSchema(t))
	if err != nil || second.Value().Outcome != "accepted" {
		t.Fatal(err)
	}
	if planOne.Value().CallerQueryDigest != planTwo.Value().CallerQueryDigest {
		t.Fatalf("term set digests differ: %s %s", planOne.Value().CallerQueryDigest, planTwo.Value().CallerQueryDigest)
	}
}

func TestCompilerCanonicalizesEquivalentBooleanSets(t *testing.T) {
	first, planOne, err := testCompiler(t).Validate(context.Background(), testQuery(t,
		`{"bool":{"filter":[{"term":{"enabled":true}},{"exists":{"field":"message"}}]}}`), testSchema(t))
	if err != nil || first.Value().Outcome != "accepted" {
		t.Fatal(err)
	}
	second, planTwo, err := testCompiler(t).Validate(context.Background(), testQuery(t,
		`{"bool":{"filter":[{"exists":{"field":"message"}},{"term":{"enabled":true}}]}}`), testSchema(t))
	if err != nil || second.Value().Outcome != "accepted" {
		t.Fatal(err)
	}
	if planOne.Value().CallerQueryDigest != planTwo.Value().CallerQueryDigest {
		t.Fatalf("boolean set digests differ: %s %s", planOne.Value().CallerQueryDigest, planTwo.Value().CallerQueryDigest)
	}
}

func TestCompilerDenialCorpus(t *testing.T) {
	tooManyTerms := make([]string, maximumTerms+1)
	for index := range tooManyTerms {
		tooManyTerms[index] = "1"
	}
	cases := map[string]struct{ text, reason string }{
		"duplicate-key":       {`{"term":{"enabled":true},"term":{"enabled":false}}`, "querydsl_json_invalid"},
		"script":              {`{"script":{"script":"return true"}}`, "querydsl_operator_unsupported"},
		"query-string":        {`{"query_string":{"query":"*"}}`, "querydsl_operator_unsupported"},
		"multiple-root":       {`{"match_all":{},"term":{"enabled":true}}`, "querydsl_node_invalid"},
		"array-root":          {`[]`, "querydsl_node_invalid"},
		"unknown-field":       {`{"term":{"secret.value":"x"}}`, "querydsl_exact_field_denied"},
		"field-wildcard":      {`{"term":{"message*":"x"}}`, "querydsl_field_invalid"},
		"exact-denied":        {`{"term":{"message":"x"}}`, "querydsl_exact_field_denied"},
		"range-denied":        {`{"range":{"enabled":{"gte":true}}}`, "querydsl_range_field_denied"},
		"range-option":        {`{"range":{"event_sequence":{"gte":1,"boost":2}}}`, "querydsl_range_invalid"},
		"range-same-side":     {`{"range":{"event_sequence":{"gt":1,"gte":2}}}`, "querydsl_range_invalid"},
		"range-contradiction": {`{"range":{"event_sequence":{"gte":9,"lt":9}}}`, "querydsl_range_contradictory"},
		"float":               {`{"term":{"event_sequence":1.5}}`, "querydsl_json_invalid"},
		"wrong-type":          {`{"term":{"enabled":"true"}}`, "querydsl_literal_type_mismatch"},
		"noncanonical-ip":     {`{"term":{"source_ip":"2001:0db8::1"}}`, "querydsl_ip_invalid"},
		"timestamp-offset":    {`{"range":{"event_timestamp":{"gte":"2026-08-27T17:00:00-01:00"}}}`, "querydsl_timestamp_invalid"},
		"empty-terms":         {`{"terms":{"event_sequence":[]}}`, "querydsl_terms_invalid"},
		"duplicate-terms":     {`{"terms":{"event_sequence":[1,1]}}`, "querydsl_terms_duplicate"},
		"too-many-terms":      {`{"terms":{"event_sequence":[` + strings.Join(tooManyTerms, ",") + `]}}`, "querydsl_terms_invalid"},
		"must-scoring":        {`{"bool":{"must":[{"match_all":{}}]}}`, "querydsl_bool_invalid"},
		"empty-bool":          {`{"bool":{}}`, "querydsl_bool_invalid"},
		"should-no-min":       {`{"bool":{"should":[{"match_all":{}}]}}`, "querydsl_bool_invalid"},
		"min-without-should":  {`{"bool":{"filter":[{"match_all":{}}],"minimum_should_match":1}}`, "querydsl_bool_invalid"},
		"bad-match-option":    {`{"match":{"message":{"query":"x","operator":"or"}}}`, "querydsl_text_invalid"},
		"bad-phrase-option":   {`{"match_phrase":{"message":{"query":"x","slop":1}}}`, "querydsl_text_invalid"},
		"text-denied":         {`{"match":{"event_id":{"query":"x","operator":"and"}}}`, "querydsl_text_field_denied"},
		"exists-denied":       {`{"exists":{"field":"event_id"}}`, "querydsl_exists_field_denied"},
		"null":                {`{"term":{"enabled":null}}`, "querydsl_literal_type_mismatch"},
		"trailing":            {`{"match_all":{}} {}`, "querydsl_json_invalid"},
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

func TestCompilerBindsLanguageSchemaScopeAndCancellation(t *testing.T) {
	compiler := testCompiler(t)
	queryValue := testQuery(t, `{"match_all":{}}`).Value()
	queryValue.Language = "esql"
	validation, plan, err := compiler.Validate(context.Background(), decodeQuery(t, queryValue), testSchema(t))
	if err != nil || plan != nil || validation.Value().ReasonCodes[0] != "querydsl_binding_invalid" {
		t.Fatal("language binding accepted")
	}
	schemaValue := testSchema(t).Value()
	schemaValue.Entries[0].ResourceID = "other"
	validation, plan, err = compiler.Validate(context.Background(), testQuery(t, `{"match_all":{}}`), decodeSchema(t, schemaValue))
	if err != nil || plan != nil || validation.Value().ReasonCodes[0] != "querydsl_schema_field_mismatch" {
		t.Fatal("schema drift accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := compiler.Validate(canceled, testQuery(t, `{"match_all":{}}`), testSchema(t)); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("cancel err=%v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, _, err := compiler.Validate(deadline, testQuery(t, `{"match_all":{}}`), testSchema(t)); queryconnector.Code(err) != queryconnector.Timeout {
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
	return Definition{SourceID: "elastic-prod", Resources: []string{"securityevent"}, Fields: []FieldRule{
		{Name: "enabled", VendorName: "enabled", Type: "boolean", Projectable: true, Exact: true, Exists: true},
		{Name: "event_id", VendorName: "event.id", Type: "string", Projectable: true, Exact: true, Sortable: true},
		{Name: "event_sequence", VendorName: "event.sequence", Type: "integer", Projectable: true, Exact: true, Range: true, Exists: true},
		{Name: "event_timestamp", VendorName: "@timestamp", Type: "timestamp", Projectable: true, Exact: true, Range: true, Exists: true, Sortable: true},
		{Name: "message", VendorName: "message", Type: "string", Projectable: true, Exists: true, TextSearchable: true},
		{Name: "source_ip", VendorName: "source.ip", Type: "ip", Projectable: true, Exact: true, Range: true, Exists: true},
		{Name: "tenant_id", VendorName: "tenant.id", Type: "string", Exact: true},
	}, Projection: []string{"event_timestamp", "event_id", "message"},
		StableSort:     []SortField{{Name: "event_timestamp", Direction: "ASC"}, {Name: "event_id", Direction: "ASC"}},
		TimestampField: "event_timestamp", TenantField: "tenant_id", HardMaximumRows: 1000,
		HardMaximumPages: 20, HardPageRows: 25}
}

func testQuery(t testing.TB, native string) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: testID("5"), Scope: queryconnector.Scope{OrganizationID: testID("1"), TenantID: testID("2"), CaseID: testID("3"), SourceID: "elastic-prod", ResourceIDs: []string{"securityevent"}},
		Authority:        queryconnector.AuthorityBinding{ActorID: testID("4"), AuthorizationDigest: testDigest("1"), PolicyDecisionDigest: testDigest("2"), AuditReservationDigest: testDigest("3")},
		CapabilityDigest: testDigest("4"), SchemaDigest: testDigest("5"), Language: "elastic-query-dsl", NativeText: native,
		TimeRange:   queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits:      queryconnector.Limits{MaximumRows: 100, MaximumBytes: 100000, MaximumDurationMillis: 5000, MaximumPages: 2, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2},
		RequestedAt: "2026-08-27T16:59:00.000000000Z", Deadline: "2026-08-27T18:01:00.000000000Z"}
	return decodeQuery(t, value)
}

func testSchema(t testing.TB) queryconnector.ValidatedSchemaPage {
	t.Helper()
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		RequestID: testID("6"), SchemaDigest: testDigest("5"), Entries: []queryconnector.SchemaEntry{
			{ResourceID: "securityevent", Name: "enabled", Type: "boolean"}, {ResourceID: "securityevent", Name: "event_id", Type: "string"},
			{ResourceID: "securityevent", Name: "event_sequence", Type: "integer"}, {ResourceID: "securityevent", Name: "event_timestamp", Type: "timestamp"},
			{ResourceID: "securityevent", Name: "message", Type: "string"}, {ResourceID: "securityevent", Name: "source_ip", Type: "ip"},
			{ResourceID: "securityevent", Name: "tenant_id", Type: "string"}}, Complete: true, ProvenanceDigest: testDigest("6")}
	return decodeSchema(t, value)
}

func decodeQuery(t testing.TB, value queryconnector.Query) queryconnector.ValidatedQuery {
	t.Helper()
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func decodeSchema(t testing.TB, value queryconnector.SchemaPage) queryconnector.ValidatedSchemaPage {
	t.Helper()
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeSchemaPage(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func testID(value string) string     { return "018f1f2e-7a6b-7c8d-8e9f-00000000000" + value }
func testDigest(value string) string { return "sha256:" + strings.Repeat("0", 63) + value }
