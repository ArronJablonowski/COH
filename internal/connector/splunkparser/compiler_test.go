package splunkparser

import (
	"context"
	"strings"
	"testing"
)

func TestCompileBindsTypedCanonicalPlan(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	request.Query = `search resource=endpoint action="blocked" AND event_time >= "2026-08-27T05:00:00-06:00" AND ip_address="2001:0db8::1" | fields action,event_time,host,source | head 200`
	request.MandatoryTenantValue = `tenant"alpha`
	plan, err := Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if plan.MaximumRows != 100 || plan.Earliest != request.Earliest || plan.Latest != request.Latest || plan.ResourceIDs[0] != "endpoint" {
		t.Fatalf("unexpected bounds: %#v", plan)
	}
	wants := []string{
		`search index=endpoint_security`, `tenant_id="tenant\"alpha"`, `source="edr"`,
		`action = "blocked"`, `_time >= "2026-08-27T11:00:00.000000000Z"`, `src_ip = "2001:db8::1"`,
		`| fields action, _time, host, source`, `| sort 0 -_time, +host`, `| head 100`,
	}
	for _, want := range wants {
		if !strings.Contains(plan.CanonicalSPL, want) {
			t.Fatalf("canonical SPL missing %q: %s", want, plan.CanonicalSPL)
		}
	}
	if plan.PlanDigest != PlanDigest(plan) || plan.RegistryDigest != builtinRegistry().Digest || plan.CommandCount != 4 {
		t.Fatalf("plan integrity fields invalid: %#v", plan)
	}
	if _, err := DecodePlan(marshal(t, plan)); err != nil {
		t.Fatalf("compiled plan does not satisfy public contract: %v", err)
	}
}

func TestCompileCanonicalValidQueryFixture(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	request.Query = strings.TrimSpace(string(readFixture(t, "query.valid.spl")))
	plan, err := Compile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.QueryDigest == "" || plan.PlanDigest != PlanDigest(plan) || plan.MaximumRows != 100 {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestCompileCanonicalizesEquivalentLogicalQueries(t *testing.T) {
	t.Parallel()
	first := validCompileRequest(t)
	first.Query = `search resource=network bytes >= 0010 AND enabled=true | stats COUNT AS events,sum(bytes) AS total_bytes BY action | sort -events | head 25`
	second := first
	second.Query = `SEARCH RESOURCE=network bytes>=10 and enabled=TRUE|STATS count AS events, SUM(bytes) AS total_bytes BY action|SORT -events|HEAD 25`
	left, err := Compile(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Compile(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if left.QueryDigest != right.QueryDigest || left.PlanDigest != right.PlanDigest || left.CanonicalSPL != right.CanonicalSPL {
		t.Fatalf("equivalent queries diverged:\n%#v\n%#v", left, right)
	}
	if len(left.Aggregations) != 2 || left.Aggregations[1].OutputType != "bytes" || len(left.Columns) != 3 {
		t.Fatalf("aggregate output contract invalid: %#v", left)
	}
}

func TestCompileRecursivelyBindsSubsearch(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	request.Query = `search resource=endpoint host IN ([ search resource=endpoint action="blocked" | table host | head 5 ]) | fields host,event_time | sort -event_time | head 10`
	plan, err := Compile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SubsearchCount != 1 || plan.CommandCount != 8 {
		t.Fatalf("recursive counts invalid: %#v", plan)
	}
	if strings.Count(plan.CanonicalSPL, `tenant_id="tenant_alpha"`) != 2 || !strings.Contains(plan.CanonicalSPL, `host IN ([ search index=endpoint_security`) {
		t.Fatalf("subsearch did not inherit mandatory scope: %s", plan.CanonicalSPL)
	}
}

func TestCompileRejectsTypeScopeAndOutputWidening(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, query, reason string }{
		{"unknown resource", `search resource=secret | fields host`, "resource_unknown"},
		{"native resource", `search resource=endpoint_security | fields host`, "resource_unknown"},
		{"unknown field", `search resource=endpoint secret="x" | fields host`, "field_unknown"},
		{"inline earliest", `search resource=endpoint earliest="-24h" | fields host`, "inline_time_not_allowed"},
		{"string ordering", `search resource=endpoint host > "a" | fields host`, "comparison_operator_invalid"},
		{"string type", `search resource=endpoint host=10 | fields host`, "literal_type_invalid"},
		{"negative bytes", `search resource=endpoint bytes=-1 | fields bytes,event_time,host`, "integer_literal_invalid"},
		{"bad timestamp", `search resource=endpoint event_time="yesterday" | fields event_time,host`, "timestamp_literal_invalid"},
		{"bad ip", `search resource=endpoint ip_address="999.1.1.1" | fields event_time,host,ip_address`, "ip_literal_invalid"},
		{"tenant projection", `search resource=endpoint | fields tenant,event_time,host`, "field_not_projectable"},
		{"aggregate type", `search resource=endpoint | stats sum(action) AS total`, "aggregation_type_invalid"},
		{"sort hidden field", `search resource=endpoint | fields action,event_time,host | sort +source`, "sort_field_not_output_or_sortable"},
		{"stable sort hidden", `search resource=endpoint | fields action`, "stable_sort_not_output"},
		{"subsearch type", `search resource=endpoint host IN ([ search resource=endpoint | table event_time | head 5 ]) | fields event_time,host`, "subsearch_type_mismatch"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validCompileRequest(t)
			request.Query = test.query
			_, err := Compile(context.Background(), request)
			if err == nil || parseReason(err) != test.reason {
				t.Fatalf("reason = %q (%v), want %q", parseReason(err), err, test.reason)
			}
		})
	}
}

func TestCompileRejectsInvalidAuthorityAndDefinition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*CompileRequest)
		reason string
	}{
		{"time order", func(value *CompileRequest) { value.Latest = value.Earliest }, "compile_authority_invalid"},
		{"missing actor", func(value *CompileRequest) { value.ActorID = "" }, "compile_authority_invalid"},
		{"row widening", func(value *CompileRequest) { value.MaximumRows = value.Definition.HardMaximumRows + 1 }, "compile_authority_invalid"},
		{"tenant newline", func(value *CompileRequest) { value.MandatoryTenantValue = "tenant\nother" }, "mandatory_tenant_invalid"},
		{"unsafe index", func(value *CompileRequest) { value.Definition.Resources[0].VendorIndex = "*" }, "definition_invalid"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validCompileRequest(t)
			test.mutate(&request)
			_, err := Compile(context.Background(), request)
			if err == nil || parseReason(err) != test.reason {
				t.Fatalf("reason = %q (%v), want %q", parseReason(err), err, test.reason)
			}
		})
	}
}

func TestPlanDigestRejectsMutation(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	request.Query = `search resource=endpoint | fields action,event_time,host,source`
	plan, err := Compile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	plan.MaximumRows++
	if _, err := DecodePlan(marshal(t, plan)); err == nil {
		t.Fatal("mutated plan accepted")
	}
}

func TestBindParserReceiptFinalizesPlanDigest(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	request.Query = `search resource=endpoint | fields action,event_time,host,source`
	candidate, err := Compile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	finalized, err := BindParserReceipt(candidate, digestForTest("9"))
	if err != nil || finalized.ParserReceiptDigest != digestForTest("9") || finalized.PlanDigest == candidate.PlanDigest || finalized.PlanDigest != PlanDigest(finalized) {
		t.Fatalf("finalized=%+v err=%v", finalized, err)
	}
	if _, err := BindParserReceipt(candidate, zeroDigest()); err == nil {
		t.Fatal("zero parser receipt accepted")
	}
}

func validCompileRequest(t *testing.T) CompileRequest {
	t.Helper()
	definition, err := DecodeDefinition(readFixture(t, "definition.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return CompileRequest{
		Query:   `search resource=endpoint | fields action,event_time,host,source`,
		QueryID: "018f0000-0000-7000-8000-000000000011", Definition: definition,
		ActorID:             "018f0000-0000-7000-8000-000000000012",
		AuthorizationDigest: digestForTest("1"), PolicyDecisionDigest: digestForTest("2"),
		AuditReservationDigest: digestForTest("3"), CapabilityDigest: digestForTest("4"), SchemaDigest: digestForTest("5"),
		ScopeDigest: digestForTest("6"),
		Earliest:    "2026-08-27T11:00:00.000000000Z", Latest: "2026-08-27T12:00:00.000000000Z",
		MaximumRows: 100, MaximumBytes: MaximumDocumentBytes, MaximumDurationMillis: 30000,
		MandatoryTenantValue: "tenant_alpha", MandatorySourceValue: "edr",
	}
}

func digestForTest(prefix string) string {
	return "sha256:" + prefix + strings.Repeat("0", 63)
}
