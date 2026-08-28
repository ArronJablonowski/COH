package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const lifecycleTestSID = "coh_1724803200.42"

func TestHTTPLifecycleUsesOnlyTypedBoundedOperations(t *testing.T) {
	var calls []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.EscapedPath()+"?"+request.URL.RawQuery)
		if request.Header.Get("Authorization") != "Splunk broker-token" {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/services/search/jobs":
			assertLifecycleForm(t, request, map[string]string{
				"search":         `search index=security | fields _time, src_ip | sort 0 -_time | head 2`,
				"exec_mode":      "normal",
				"earliest_time":  "2026-08-27T23:00:00.000000000Z",
				"latest_time":    "2026-08-28T00:00:00.000000000Z",
				"max_count":      "2",
				"max_time":       "2",
				"auto_cancel":    "2",
				"timeout":        "2",
				"enable_preview": "false",
				"status_buckets": "0",
				"output_mode":    "json",
			})
			writer.WriteHeader(http.StatusCreated)
			writeJSON(t, writer, map[string]any{"sid": lifecycleTestSID})
		case "/services/search/jobs/" + lifecycleTestSID:
			writeJSON(t, writer, lifecycleStatusResponse("DONE", false, false))
		case "/services/search/jobs/" + lifecycleTestSID + "/results":
			writeJSON(t, writer, map[string]any{"preview": false, "init_offset": 0, "messages": []any{},
				"fields": []any{map[string]any{"name": "_time"}, map[string]any{"name": "src_ip"}},
				"results": []any{map[string]any{"_time": "2026-08-27T23:59:00Z", "src_ip": "192.0.2.1"},
					map[string]any{"_time": "2026-08-27T23:59:30Z", "src_ip": "192.0.2.2"}}})
		case "/services/search/jobs/" + lifecycleTestSID + "/control":
			assertLifecycleForm(t, request, map[string]string{"action": "cancel", "output_mode": "json"})
			writeJSON(t, writer, struct{}{})
		default:
			http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	config, roots := splunkHTTPTestConfig(t, server)
	credentials := &splunkCredentialStub{token: []byte("broker-token"), decision: splunkTestDigest("8")}
	client, err := NewHTTPClient(config, credentials, roots)
	if err != nil {
		t.Fatal(err)
	}
	plan := lifecycleTestPlan(t)
	create, receipt, err := client.CreateSearch(context.Background(), SearchCreateRequest{
		Binding: splunkTestBinding("splunk.search.create"), Plan: plan})
	if err != nil || create.SID != lifecycleTestSID || !digestPattern.MatchString(create.SIDDigest) ||
		receipt.TransportDigest != config.TransportIdentityDigest {
		t.Fatalf("create=%+v receipt=%+v err=%v", create, receipt, err)
	}
	statusRequest := SearchStatusRequest{Binding: splunkTestBinding("splunk.search.status"), SID: create.SID}
	status, _, err := client.SearchStatus(context.Background(), statusRequest)
	if err != nil || status.State != "DONE" || !status.Done || status.Finalized || status.ResultCount != 2 || status.DurationMillis != 125 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	result, _, err := client.SearchResults(context.Background(), SearchResultsRequest{
		Binding: splunkTestBinding("splunk.search.results"), SID: create.SID, Count: 2, Total: 2, Plan: plan})
	if err != nil || len(result.Results) != 2 || result.Results[0]["source.ip"] != "192.0.2.1" ||
		!digestPattern.MatchString(result.ResultDigest) || !slices.Equal(result.Fields, []string{"event.time", "source.ip"}) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	canceled, _, err := client.CancelSearch(context.Background(), SearchCancelRequest{
		Binding: splunkTestBinding("splunk.search.cancel"), SID: create.SID})
	if err != nil || !canceled.Acknowledged || credentials.uses != 4 {
		t.Fatalf("cancel=%+v uses=%d err=%v", canceled, credentials.uses, err)
	}
	want := []string{
		"POST /services/search/jobs?",
		"GET /services/search/jobs/coh_1724803200.42?count=1&output_mode=json",
		"GET /services/search/jobs/coh_1724803200.42/results?count=2&offset=0&output_mode=json",
		"POST /services/search/jobs/coh_1724803200.42/control?",
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls=%v", calls)
	}
}

func TestHTTPLifecycleRejectsUnsafeRequestsBeforeCredentialUse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unsafe request reached transport")
	}))
	defer server.Close()
	config, roots := splunkHTTPTestConfig(t, server)
	credentials := &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}
	client, _ := NewHTTPClient(config, credentials, roots)

	plan := lifecycleTestPlan(t)
	plan.CanonicalSPL = "search index=security\n| collect"
	if _, _, err := client.CreateSearch(context.Background(), SearchCreateRequest{
		Binding: splunkTestBinding("splunk.search.create"), Plan: plan}); queryconnector.Reason(err) != "splunk_lifecycle_plan_invalid" {
		t.Fatalf("create err=%v", err)
	}
	if _, _, err := client.SearchStatus(context.Background(), SearchStatusRequest{
		Binding: splunkTestBinding("splunk.search.status"), SID: "../../server/info"}); queryconnector.Reason(err) != "splunk_search_status_request_invalid" {
		t.Fatalf("status err=%v", err)
	}
	if _, _, err := client.SearchResults(context.Background(), SearchResultsRequest{
		Binding: splunkTestBinding("splunk.search.results"), SID: lifecycleTestSID, Count: 10001, Total: 10001,
		Plan: plan}); queryconnector.Reason(err) != "splunk_search_results_request_invalid" {
		t.Fatalf("results err=%v", err)
	}
	if _, _, err := client.CancelSearch(context.Background(), SearchCancelRequest{
		Binding: splunkTestBinding("splunk.search.cancel"), SID: "bad%2fsid"}); queryconnector.Reason(err) != "splunk_search_cancel_request_invalid" {
		t.Fatalf("cancel err=%v", err)
	}
	if credentials.uses != 0 {
		t.Fatalf("credentials used=%d", credentials.uses)
	}
}

func TestHTTPLifecycleRejectsHostileVendorResponses(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		response  func(http.ResponseWriter)
		reason    string
	}{
		{"unsafe SID", "create", func(w http.ResponseWriter) { writeJSON(t, w, map[string]any{"sid": "../../stolen"}) }, "splunk_search_create_response_invalid"},
		{"unknown create field", "create", func(w http.ResponseWriter) {
			writeJSON(t, w, map[string]any{"sid": lifecycleTestSID, "token": "secret"})
		}, "splunk_search_create_response_invalid"},
		{"unknown state", "status", func(w http.ResponseWriter) { writeJSON(t, w, lifecycleStatusResponse("MYSTERY", false, false)) }, "splunk_search_status_response_invalid"},
		{"manual finalize", "status", func(w http.ResponseWriter) { writeJSON(t, w, lifecycleStatusResponse("DONE", true, false)) }, "splunk_search_status_response_invalid"},
		{"real time", "status", func(w http.ResponseWriter) { writeJSON(t, w, lifecycleStatusResponse("DONE", false, true)) }, "splunk_search_status_response_invalid"},
		{"preview", "results", func(w http.ResponseWriter) { writeJSON(t, w, lifecycleResultsResponse(true, false, false)) }, "splunk_search_results_response_invalid"},
		{"message", "results", func(w http.ResponseWriter) { writeJSON(t, w, lifecycleResultsResponse(false, true, false)) }, "splunk_search_results_response_invalid"},
		{"multivalue", "results", func(w http.ResponseWriter) { writeJSON(t, w, lifecycleResultsResponse(false, false, true)) }, "splunk_search_results_response_invalid"},
		{"cancel body", "cancel", func(w http.ResponseWriter) { writeJSON(t, w, map[string]any{"sid": lifecycleTestSID}) }, "splunk_search_cancel_response_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { test.response(writer) }))
			defer server.Close()
			config, roots := splunkHTTPTestConfig(t, server)
			client, _ := NewHTTPClient(config, &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}, roots)
			var err error
			switch test.operation {
			case "create":
				_, _, err = client.CreateSearch(context.Background(), SearchCreateRequest{
					Binding: splunkTestBinding("splunk.search.create"), Plan: lifecycleTestPlan(t)})
			case "status":
				_, _, err = client.SearchStatus(context.Background(), SearchStatusRequest{
					Binding: splunkTestBinding("splunk.search.status"), SID: lifecycleTestSID})
			case "results":
				_, _, err = client.SearchResults(context.Background(), SearchResultsRequest{
					Binding: splunkTestBinding("splunk.search.results"), SID: lifecycleTestSID, Count: 1, Total: 1,
					Plan: lifecycleTestPlan(t)})
			case "cancel":
				_, _, err = client.CancelSearch(context.Background(), SearchCancelRequest{
					Binding: splunkTestBinding("splunk.search.cancel"), SID: lifecycleTestSID})
			}
			if queryconnector.Reason(err) != test.reason || strings.Contains(err.Error(), lifecycleTestSID) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func lifecycleTestPlan(t *testing.T) splunkparser.Plan {
	t.Helper()
	input, err := os.ReadFile("../../../contracts/splunk-parser/v1/fixtures/plan.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := splunkparser.DecodePlan(input)
	if err != nil {
		t.Fatal(err)
	}
	binding := splunkTestBinding("splunk.search.create")
	plan.SourceID = binding.Scope.SourceID
	plan.ResourceIDs = append([]string(nil), binding.Scope.ResourceIDs...)
	plan.CanonicalSPL = `search index=security | fields _time, src_ip | sort 0 -_time | head 2`
	plan.Columns = []splunkparser.Column{{LogicalName: "event.time", VendorName: "_time", Type: "timestamp"},
		{LogicalName: "source.ip", VendorName: "src_ip", Type: "ip", Nullable: true}}
	plan.Sort = []splunkparser.SortRule{{Name: "event.time", Direction: "desc"}}
	plan.Earliest, plan.Latest = "2026-08-27T23:00:00.000000000Z", "2026-08-28T00:00:00.000000000Z"
	plan.MaximumRows, plan.MaximumDurationMillis = 2, 1250
	plan.Authority = splunkparser.AuthorityBinding{ActorID: binding.Authority.ActorID,
		AuthorizationDigest:    binding.Authority.AuthorizationDigest,
		PolicyDecisionDigest:   binding.Authority.PolicyDecisionDigest,
		AuditReservationDigest: binding.Authority.AuditReservationDigest}
	plan.PlanDigest = splunkparser.PlanDigest(plan)
	encoded, _ := json.Marshal(plan)
	validated, err := splunkparser.DecodePlan(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func lifecycleStatusResponse(state string, finalized, realTime bool) map[string]any {
	return map[string]any{"entry": []any{map[string]any{"name": lifecycleTestSID, "content": map[string]any{
		"dispatchState": state, "doneProgress": 1.0, "scanCount": 40, "eventCount": 20, "resultCount": 2,
		"runDuration": 0.125, "isDone": true, "isFailed": false, "isFinalized": finalized,
		"isRealTimeSearch": realTime, "isZombie": false}}}}
}

func lifecycleResultsResponse(preview, message, multivalue bool) map[string]any {
	messages := []any{}
	if message {
		messages = append(messages, map[string]any{"type": "WARN", "text": "partial"})
	}
	cell := any("2026-08-27T23:59:00Z")
	if multivalue {
		cell = []any{"2026-08-27T23:59:00Z"}
	}
	return map[string]any{"preview": preview, "init_offset": 0, "messages": messages,
		"fields":  []any{map[string]any{"name": "_time"}, map[string]any{"name": "src_ip"}},
		"results": []any{map[string]any{"_time": cell, "src_ip": "192.0.2.1"}}}
}

func assertLifecycleForm(t *testing.T, request *http.Request, want map[string]string) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.ParseForm() != nil || len(request.PostForm) != len(want) {
		t.Fatalf("request=%s %s form=%v", request.Method, request.URL.String(), request.PostForm)
	}
	for key, value := range want {
		if request.PostForm.Get(key) != value || len(request.PostForm[key]) != 1 {
			t.Fatalf("%s=%v want=%q", key, request.PostForm[key], value)
		}
	}
}
