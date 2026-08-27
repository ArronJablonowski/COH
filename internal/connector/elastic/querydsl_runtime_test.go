package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticquerydsl"
	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
)

type queryDSLClientStub struct {
	mu                                                  sync.Mutex
	validationCalls, openCalls, searchCalls, closeCalls int
	validationErr, openErr, searchErr, closeErr         error
	pages                                               [][]SearchHit
}

func (client *queryDSLClientStub) ValidateQuery(context.Context, QueryValidationRequest) (QueryValidationResult, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.validationCalls++
	if client.validationErr != nil {
		return QueryValidationResult{}, CallReceipt{}, client.validationErr
	}
	return QueryValidationResult{Valid: true, TotalShards: 1, ResultDigest: testDigest("9")}, runtimeReceipt(), nil
}
func (client *queryDSLClientStub) OpenPIT(context.Context, OpenPITRequest) (PITResult, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.openCalls++
	if client.openErr != nil {
		return PITResult{}, CallReceipt{}, client.openErr
	}
	return PITResult{ID: "pit-1", TotalShards: 1, PITDigest: testDigest("a")}, runtimeReceipt(), nil
}
func (client *queryDSLClientStub) SearchPIT(_ context.Context, request SearchPITRequest) (SearchPITResult, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.searchCalls++
	if client.searchErr != nil {
		return SearchPITResult{}, CallReceipt{}, client.searchErr
	}
	index := client.searchCalls - 1
	var hits []SearchHit
	if index < len(client.pages) {
		hits = cloneSearchHits(client.pages[index])
	}
	return SearchPITResult{PITID: "pit-" + string(rune('2'+index)), PITDigest: testDigest(string(rune('b' + index))),
		Hits: hits, TookMillis: 2, TotalShards: 1, ResultDigest: testDigest(string(rune('d' + index)))}, runtimeReceipt(), nil
}
func (client *queryDSLClientStub) ClosePIT(context.Context, ClosePITRequest) (ClosePITResult, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closeCalls++
	if client.closeErr != nil {
		return ClosePITResult{}, CallReceipt{}, client.closeErr
	}
	return ClosePITResult{Succeeded: true, Freed: 1, ResultDigest: testDigest("f")}, runtimeReceipt(), nil
}

func (client *queryDSLClientStub) counts() (int, int, int, int) {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.validationCalls, client.openCalls, client.searchCalls, client.closeCalls
}

func runtimeReceipt() CallReceipt {
	return CallReceipt{RequestDigest: testDigest("1"), ResponseDigest: testDigest("2"), LeaseDecisionDigest: testDigest("3"), TransportDigest: testDigest("4")}
}

func TestQueryDSLRuntimeCompletesBoundedReplayableExport(t *testing.T) {
	runtime, capability, client := testQueryDSLRuntime(t)
	query := queryDSLRuntimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil || validation.Value().Outcome != "accepted" {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	runtime.mu.Lock()
	prepared := runtime.validated[query.Digest()]
	runtime.mu.Unlock()
	if prepared.query.NativeText != "" || len(prepared.indices) != 1 {
		t.Fatal("runtime retained native text or lost target binding")
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || execution.Value().Handle.Kind != "query_job" {
		t.Fatalf("execution=%+v err=%v", execution.Value(), err)
	}
	pollRequest := queryconnector.PollRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: execution.Value().Handle, Authority: query.Value().Authority}
	poll, err := runtime.Poll(context.Background(), pollRequest)
	if err != nil || poll.Value().Page == nil || len(poll.Value().Page.Rows) != 2 || poll.Value().Page.NextPage == nil ||
		poll.Value().Page.Rows[0]["event_id"] != "event-1" {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
	replayedPoll, err := runtime.Poll(context.Background(), pollRequest)
	if err != nil || replayedPoll.Digest() != poll.Digest() {
		t.Fatalf("poll replay=%+v err=%v", replayedPoll.Value(), err)
	}
	pageRequest := queryconnector.PageRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: *poll.Value().Page.NextPage, Authority: query.Value().Authority, Limits: query.Value().Limits}
	page, err := runtime.NextPage(context.Background(), pageRequest)
	if err != nil || len(page.Value().Rows) != 1 || page.Value().NextPage != nil || page.Value().Completeness.Status != "complete" {
		t.Fatalf("page=%+v err=%v", page.Value(), err)
	}
	replayedPage, err := runtime.NextPage(context.Background(), pageRequest)
	if err != nil || replayedPage.Digest() != page.Digest() {
		t.Fatalf("page replay=%+v err=%v", replayedPage.Value(), err)
	}
	cancellation, err := runtime.Cancel(context.Background(), queryconnector.CancelRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority,
		RequestedAt: "2026-08-27T18:00:01.000000000Z"})
	if err != nil || cancellation.Value().Outcome != "confirmed" {
		t.Fatalf("cancel=%+v err=%v", cancellation.Value(), err)
	}
	validateCalls, openCalls, searchCalls, closeCalls := client.counts()
	if validateCalls != 1 || openCalls != 1 || searchCalls != 2 || closeCalls != 1 {
		t.Fatalf("calls validate=%d open=%d search=%d close=%d", validateCalls, openCalls, searchCalls, closeCalls)
	}
	runtime.mu.Lock()
	job := runtime.jobs[execution.Value().Handle.HandleID]
	runtime.mu.Unlock()
	job.mu.Lock()
	defer job.mu.Unlock()
	if !job.closed || job.pitID != "" {
		t.Fatal("terminal PIT ID retained")
	}
}

func TestQueryDSLRuntimeCoalescesConcurrentPollReplay(t *testing.T) {
	runtime, capability, client := testQueryDSLRuntime(t)
	query := queryDSLRuntimeQuery(t, capability.Digest())
	validation, _ := runtime.Validate(context.Background(), query)
	execution, _ := runtime.Execute(context.Background(), query, validation)
	request := queryconnector.PollRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: execution.Value().Handle, Authority: query.Value().Authority}
	const workers = 24
	results, failures := make(chan string, workers), make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := runtime.Poll(context.Background(), request)
			if err != nil {
				failures <- err
				return
			}
			results <- result.Digest()
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	want := ""
	for value := range results {
		if want == "" {
			want = value
		}
		if value != want {
			t.Fatal("poll replay changed")
		}
	}
	_, _, searchCalls, _ := client.counts()
	if searchCalls != 1 {
		t.Fatalf("search calls=%d", searchCalls)
	}
}

func TestQueryDSLRuntimeReportsTruncationAndClosesPIT(t *testing.T) {
	runtime, capability, client := testQueryDSLRuntime(t)
	client.pages = [][]SearchHit{runtimeHits(3), runtimeHits(2)}
	queryValue := queryDSLRuntimeQuery(t, capability.Digest()).Value()
	queryValue.Limits.MaximumRows = 3
	query := decodeRuntimeQuery(t, queryValue)
	validation, _ := runtime.Validate(context.Background(), query)
	execution, _ := runtime.Execute(context.Background(), query, validation)
	poll, err := runtime.Poll(context.Background(), queryconnector.PollRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority})
	if err != nil || poll.Value().Page.NextPage == nil {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
	page, err := runtime.NextPage(context.Background(), queryconnector.PageRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: *poll.Value().Page.NextPage, Authority: query.Value().Authority, Limits: query.Value().Limits})
	if err != nil || !page.Value().Completeness.Truncated || page.Value().Completeness.ReasonCodes[0] != "row_limit_reached" || page.Value().NextPage != nil {
		t.Fatalf("page=%+v err=%v", page.Value(), err)
	}
	_, _, _, closeCalls := client.counts()
	if closeCalls != 1 {
		t.Fatalf("close calls=%d", closeCalls)
	}
}

func TestQueryDSLRuntimeRejectsJobAndPageHandleTheft(t *testing.T) {
	runtime, capability, client := testQueryDSLRuntime(t)
	query := queryDSLRuntimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	jobRequest := queryconnector.PollRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: execution.Value().Handle, Authority: query.Value().Authority}
	stolenJob := jobRequest
	stolenJob.Authority.ActorID = testID("9")
	if _, err := runtime.Poll(context.Background(), stolenJob); queryconnector.Reason(err) != "elastic_querydsl_job_mismatch" {
		t.Fatalf("stolen job err=%v", err)
	}
	poll, err := runtime.Poll(context.Background(), jobRequest)
	if err != nil || poll.Value().Page == nil || poll.Value().Page.NextPage == nil {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
	pageRequest := queryconnector.PageRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: *poll.Value().Page.NextPage, Authority: query.Value().Authority, Limits: query.Value().Limits}
	stolenPage := pageRequest
	stolenPage.Handle.OpaqueDigest = testDigest("9")
	if _, err := runtime.NextPage(context.Background(), stolenPage); queryconnector.Reason(err) != "elastic_querydsl_page_handle_mismatch" {
		t.Fatalf("stolen page err=%v", err)
	}
	_, _, searchCalls, _ := client.counts()
	if searchCalls != 1 {
		t.Fatalf("handle theft reached vendor: search calls=%d", searchCalls)
	}
}

func TestQueryDSLRuntimeRetriesOpenAndReportsUncertainClose(t *testing.T) {
	runtime, capability, client := testQueryDSLRuntime(t)
	query := queryDSLRuntimeQuery(t, capability.Digest())
	validation, _ := runtime.Validate(context.Background(), query)
	client.openErr = errors.New("outage")
	if _, err := runtime.Execute(context.Background(), query, validation); err == nil {
		t.Fatal("open outage accepted")
	}
	client.openErr = nil
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	client.closeErr = errors.New("close outage")
	cancellation, err := runtime.Cancel(context.Background(), queryconnector.CancelRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority,
		RequestedAt: "2026-08-27T18:00:01.000000000Z"})
	if err != nil || cancellation.Value().Outcome != "uncertain" {
		t.Fatalf("cancel=%+v err=%v", cancellation.Value(), err)
	}
}

func TestQueryDSLRuntimeFeedsSharedExportRuntimeEvidence(t *testing.T) {
	runtime, capability, _ := testQueryDSLRuntime(t)
	query := queryDSLRuntimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	audit := &esqlBoundsAudit{}
	bounds, _ := querybounds.New(audit, runtime.clock, esqlReplayGuard{})
	queryValue := query.Value()
	authority := querybounds.AuthoritySnapshot{OrganizationID: queryValue.Scope.OrganizationID, TenantID: queryValue.Scope.TenantID,
		CaseID: queryValue.Scope.CaseID, ActorID: queryValue.Authority.ActorID, ActorRevision: 1, ActorActive: true,
		SourceID: queryValue.Scope.SourceID, SourceRevision: 1, SourceActive: true, ResourceIDs: queryValue.Scope.ResourceIDs,
		AllowlistRevision: 1, AllowlistActive: true, CapabilityDigest: queryValue.CapabilityDigest, CapabilityRevision: 1,
		CapabilityActive: true, AuthorizationAllowed: true, AuthorizationDecisionDigest: queryValue.Authority.AuthorizationDigest,
		PolicyAllowed: true, PolicyDecisionDigest: queryValue.Authority.PolicyDecisionDigest, PolicyRevision: 1,
		AuditReservationDigest: queryValue.Authority.AuditReservationDigest, RevocationRevision: 1,
		MaximumInterval: 2 * time.Hour, MaximumLimits: queryValue.Limits, ObservedAt: runtime.clock.Now()}
	admission, err := bounds.Admit(context.Background(), query, authority)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &esqlRuntimeRecorder{}
	profile := queryruntime.Profile{Limits: queryValue.Limits, MinimumPollInterval: time.Millisecond, MaximumPollInterval: time.Second}
	controller, err := queryruntime.New(queryruntime.Config{Interactive: queryruntime.Profile{Mode: "interactive", Limits: profile.Limits,
		MinimumPollInterval: profile.MinimumPollInterval, MaximumPollInterval: profile.MaximumPollInterval}, Export: queryruntime.Profile{Mode: "export",
		Limits: profile.Limits, MinimumPollInterval: profile.MinimumPollInterval, MaximumPollInterval: profile.MaximumPollInterval},
		MaximumSessions: 10, CancellationWait: time.Second, RecordWait: time.Second}, runtime, &esqlRateGate{}, recorder, runtime.clock)
	if err != nil {
		t.Fatal(err)
	}
	session, err := controller.Start(context.Background(), queryruntime.StartRequest{Mode: "export", Admission: admission, Execution: execution})
	if err != nil {
		t.Fatal(err)
	}
	first, err := controller.Poll(context.Background(), queryruntime.SessionRef{SessionID: session.SessionID, SessionDigest: session.SessionDigest})
	if err != nil || first.Session.Status != "running" || !first.HasPage {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := controller.NextPage(context.Background(), queryruntime.SessionRef{SessionID: first.Session.SessionID, SessionDigest: first.Session.SessionDigest})
	if err != nil || second.Session.Status != "complete" || !second.HasPage || len(recorder.sessions) != 3 ||
		second.Session.BoundsDecisionDigest != admission.Decision.DecisionDigest || second.Session.ExecutionDigest != execution.Digest() {
		t.Fatalf("second=%+v records=%d err=%v", second, len(recorder.sessions), err)
	}
}

func testQueryDSLRuntime(t testing.TB) (*QueryDSLRuntime, queryconnector.ValidatedCapability, *queryDSLClientStub) {
	t.Helper()
	discovery, _, clock := testAdapter(t)
	capability, err := discovery.Probe(context.Background(), testScope(), testAuthority())
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := elasticquerydsl.New(runtimeQueryDSLDefinition())
	if err != nil {
		t.Fatal(err)
	}
	client := &queryDSLClientStub{pages: [][]SearchHit{runtimeHits(3), runtimeHits(1)}}
	runtime, err := NewQueryDSLRuntime(discovery, compiler, &schemaResolverStub{page: queryDSLRuntimeSchema(t)}, client, clock)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, capability, client
}

func runtimeQueryDSLDefinition() elasticquerydsl.Definition {
	return elasticquerydsl.Definition{SourceID: "elastic-prod", Resources: []string{"securityevent"}, Fields: []elasticquerydsl.FieldRule{
		{Name: "event_id", VendorName: "event.id", Type: "string", Projectable: true, Exact: true, Sortable: true},
		{Name: "event_timestamp", VendorName: "@timestamp", Type: "timestamp", Projectable: true, Exact: true, Range: true, Sortable: true},
		{Name: "message", VendorName: "message", Type: "string", Projectable: true, TextSearchable: true}},
		Projection: []string{"event_timestamp", "event_id", "message"}, StableSort: []elasticquerydsl.SortField{{Name: "event_timestamp", Direction: "ASC"}, {Name: "event_id", Direction: "ASC"}},
		TimestampField: "event_timestamp", HardMaximumRows: 10, HardMaximumPages: 3, HardPageRows: 2}
}

func queryDSLRuntimeQuery(t testing.TB, capability string) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: testID("5"), Scope: testScope(), Authority: testAuthority(), CapabilityDigest: capability, SchemaDigest: testDigest("6"),
		Language: "elastic-query-dsl", NativeText: `{"match_all":{}}`, TimeRange: queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits:      queryconnector.Limits{MaximumRows: 10, MaximumBytes: 100000, MaximumDurationMillis: 5000, MaximumPages: 3, MaximumSlices: 3, MaximumCostMillionths: 1000, RequestsPerMinute: 3},
		RequestedAt: "2026-08-27T17:59:00.000000000Z", Deadline: "2026-08-27T18:10:00.000000000Z"}
	return decodeRuntimeQuery(t, value)
}

func decodeRuntimeQuery(t testing.TB, value queryconnector.Query) queryconnector.ValidatedQuery {
	t.Helper()
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func queryDSLRuntimeSchema(t testing.TB) queryconnector.ValidatedSchemaPage {
	t.Helper()
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		RequestID: testID("6"), SchemaDigest: testDigest("6"), Entries: []queryconnector.SchemaEntry{
			{ResourceID: "securityevent", Name: "event_id", Type: "string"}, {ResourceID: "securityevent", Name: "event_timestamp", Type: "timestamp"},
			{ResourceID: "securityevent", Name: "message", Type: "string"}}, Complete: true, ProvenanceDigest: testDigest("7")}
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeSchemaPage(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func runtimeHits(count int) []SearchHit {
	result := make([]SearchHit, count)
	for index := range count {
		identifier := string(rune('1' + index))
		result[index] = SearchHit{Row: map[string]any{"event_id": "event-" + identifier, "event_timestamp": "2026-08-27T17:10:00Z", "message": "row-" + identifier},
			Sort: []any{"2026-08-27T17:10:00Z", "event-" + identifier, int64(index + 1)}}
	}
	return result
}

func cloneSearchHits(values []SearchHit) []SearchHit {
	result := make([]SearchHit, len(values))
	for index, hit := range values {
		result[index] = SearchHit{Row: cloneRows([]map[string]any{hit.Row})[0], Sort: append([]any(nil), hit.Sort...)}
	}
	return result
}
