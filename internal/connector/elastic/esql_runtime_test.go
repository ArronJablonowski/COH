package elastic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticesql"
	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type schemaResolverStub struct {
	page queryconnector.ValidatedSchemaPage
	err  error
}

func (resolver *schemaResolverStub) ResolveSchema(context.Context,
	queryconnector.ValidatedQuery) (queryconnector.ValidatedSchemaPage, error) {
	return resolver.page, resolver.err
}

type esqlClientStub struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (client *esqlClientStub) ExecuteESQL(_ context.Context, request ESQLRequest) (ESQLResult, CallReceipt, error) {
	client.mu.Lock()
	client.calls++
	client.mu.Unlock()
	if client.err != nil {
		return ESQLResult{}, CallReceipt{}, client.err
	}
	plan := request.Plan.Value()
	return ESQLResult{Columns: plan.Columns, Rows: []map[string]any{{"event_id": "event-1",
			"event_timestamp": "2026-08-27T17:30:00Z"}}, TookMillis: 4, DocumentsFound: 1,
			ValuesLoaded: 2, ResultDigest: testDigest("9")}, CallReceipt{RequestDigest: testDigest("1"),
			ResponseDigest: testDigest("2"), LeaseDecisionDigest: testDigest("3"), TransportDigest: testDigest("4")}, nil
}

func (client *esqlClientStub) count() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.calls
}

func TestESQLRuntimeCompletesSharedConnectorLifecycle(t *testing.T) {
	runtime, capability, client := testESQLRuntime(t)
	query := runtimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil || validation.Value().Outcome != "accepted" {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	runtime.mu.Lock()
	prepared := runtime.validated[query.Digest()]
	runtime.mu.Unlock()
	if prepared.query.NativeText != "" {
		t.Fatal("runtime retained native query text after compilation")
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || execution.Value().Outcome != "running" || execution.Value().Handle.Kind != "query_job" {
		t.Fatalf("execution=%+v err=%v", execution.Value(), err)
	}
	runtime.mu.Lock()
	_, retained := runtime.validated[query.Digest()]
	runtime.mu.Unlock()
	if retained {
		t.Fatal("runtime retained parameterized plan after successful execution")
	}
	poll, err := runtime.Poll(context.Background(), queryconnector.PollRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority})
	if err != nil || poll.Value().Outcome != "completed" || poll.Value().Page == nil ||
		poll.Value().Completeness.Status != "complete" || !poll.Value().Completeness.VendorConfirmed ||
		poll.Value().Page.Rows[0]["event_id"] != "event-1" {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
	cancellation, err := runtime.Cancel(context.Background(), queryconnector.CancelRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority,
		RequestedAt: "2026-08-27T18:00:01.000000000Z"})
	if err != nil || cancellation.Value().Outcome != "confirmed" {
		t.Fatalf("cancellation=%+v err=%v", cancellation.Value(), err)
	}
	if _, err := runtime.NextPage(context.Background(), queryconnector.PageRequest{}); queryconnector.Code(err) != queryconnector.Unsupported {
		t.Fatalf("next page err=%v", err)
	}
	if client.count() != 1 {
		t.Fatalf("execute calls=%d", client.count())
	}
}

func TestESQLRuntimeCoalescesConcurrentExecutionReplay(t *testing.T) {
	runtime, capability, client := testESQLRuntime(t)
	query := runtimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	results := make(chan queryconnector.ValidatedExecution, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			execution, executeErr := runtime.Execute(context.Background(), query, validation)
			if executeErr != nil {
				errors <- executeErr
				return
			}
			results <- execution
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for executeErr := range errors {
		t.Fatal(executeErr)
	}
	want := ""
	for execution := range results {
		if want == "" {
			want = execution.Digest()
		}
		if execution.Digest() != want {
			t.Fatalf("execution digest=%s want=%s", execution.Digest(), want)
		}
	}
	if client.count() != 1 {
		t.Fatalf("execute calls=%d", client.count())
	}
}

func TestESQLRuntimeRejectsValidationAndHandleSubstitution(t *testing.T) {
	runtime, capability, _ := testESQLRuntime(t)
	query := runtimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	denialValue := validation.Value()
	denialValue.Outcome, denialValue.ReasonCodes = "denied", []string{"policy_denied"}
	denialBytes, _ := json.Marshal(denialValue)
	denial, err := queryconnector.DecodeValidation(context.Background(), denialBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Execute(context.Background(), query, denial); queryconnector.Code(err) != queryconnector.Denied {
		t.Fatalf("denial err=%v", err)
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	request := queryconnector.PollRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: execution.Value().Handle, Authority: query.Value().Authority}
	request.Handle.OpaqueDigest = testDigest("8")
	if _, err := runtime.Poll(context.Background(), request); queryconnector.Code(err) != queryconnector.Conflict {
		t.Fatalf("substitution err=%v", err)
	}
}

func TestESQLRuntimeReportsLostAdapterStateAsUnknown(t *testing.T) {
	runtime, capability, _ := testESQLRuntime(t)
	query := runtimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	delete(runtime.jobs, execution.Value().Handle.HandleID)
	runtime.mu.Unlock()
	pollRequest := queryconnector.PollRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: execution.Value().Handle, Authority: query.Value().Authority}
	if _, err := runtime.Poll(context.Background(), pollRequest); queryconnector.Code(err) != queryconnector.Unavailable ||
		queryconnector.Reason(err) != "elastic_esql_job_unavailable" {
		t.Fatalf("poll err=%v", err)
	}
	cancellation, err := runtime.Cancel(context.Background(), queryconnector.CancelRequest{QueryID: pollRequest.QueryID,
		AttemptID: pollRequest.AttemptID, Handle: pollRequest.Handle, Authority: pollRequest.Authority,
		RequestedAt: "2026-08-27T18:00:01.000000000Z"})
	if err != nil || cancellation.Value().Outcome != "uncertain" || cancellation.Value().ConfirmedAt != nil {
		t.Fatalf("cancellation=%+v err=%v", cancellation.Value(), err)
	}
}

func TestESQLRuntimeRetriesFailedExecutionAndExpiresAllState(t *testing.T) {
	runtime, capability, client := testESQLRuntime(t)
	query := runtimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	client.err = errors.New("temporary vendor outage")
	if _, err := runtime.Execute(context.Background(), query, validation); err == nil {
		t.Fatal("vendor outage was accepted")
	}
	client.err = nil
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || client.count() != 2 {
		t.Fatalf("execution=%+v calls=%d err=%v", execution.Value(), client.count(), err)
	}
	runtime.clock.(*fixedClock).now = testNow.Add(11 * time.Minute)
	if _, err := runtime.Poll(context.Background(), queryconnector.PollRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority}); queryconnector.Reason(err) != "elastic_esql_job_unavailable" {
		t.Fatalf("expired poll err=%v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.validated) != 0 || len(runtime.executions) != 0 || len(runtime.jobs) != 0 {
		t.Fatalf("expired state retained: validated=%d executions=%d jobs=%d",
			len(runtime.validated), len(runtime.executions), len(runtime.jobs))
	}
}

func TestESQLRuntimeFailsClosedAtProcessLocalCapacity(t *testing.T) {
	runtime, capability, _ := testESQLRuntime(t)
	query := runtimeQuery(t, capability.Digest())
	runtime.mu.Lock()
	for index := range maximumESQLRuntimeEntries {
		runtime.validated[fmt.Sprintf("entry-%d", index)] = validatedESQL{expiresAt: testNow.Add(time.Hour)}
	}
	runtime.mu.Unlock()
	if _, err := runtime.Validate(context.Background(), query); queryconnector.Code(err) != queryconnector.Denied ||
		queryconnector.Reason(err) != "elastic_esql_runtime_capacity_reached" {
		t.Fatalf("capacity err=%v", err)
	}
}

type esqlBoundsAudit struct{ decisions []querybounds.Decision }

func (audit *esqlBoundsAudit) AppendQueryBoundDecision(_ context.Context, decision querybounds.Decision) error {
	audit.decisions = append(audit.decisions, decision)
	return nil
}

type esqlReplayGuard struct{}

func (esqlReplayGuard) Observe(context.Context, string, string) (bool, error) { return false, nil }

type esqlRuntimeRecorder struct{ sessions []queryruntime.Session }

func (recorder *esqlRuntimeRecorder) RecordQuerySession(_ context.Context, session queryruntime.Session) error {
	recorder.sessions = append(recorder.sessions, session)
	return nil
}

type esqlRateGate struct{ sequence uint64 }

func (gate *esqlRateGate) Reserve(_ context.Context, request queryruntime.RateRequest) (queryruntime.RateReservation, error) {
	gate.sequence++
	keyDigest := esqlRateKeyDigest(request)
	requested, _ := time.Parse(timestampLayout, request.RequestedAt)
	return queryruntime.FinalizeRateReservation(queryruntime.RateReservation{SchemaVersion: queryruntime.RateSchemaVersion,
		ContractVersion: queryruntime.ContractVersion, KeyDigest: keyDigest, SessionID: request.SessionID,
		Operation: request.Operation, Sequence: gate.sequence, ReservedAt: request.RequestedAt,
		ValidUntil: requested.Add(time.Minute).Format(timestampLayout)})
}

func TestESQLRuntimeFeedsBoundedSharedRuntimeEvidence(t *testing.T) {
	runtime, capability, _ := testESQLRuntime(t)
	query := runtimeQuery(t, capability.Digest())
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	audit := &esqlBoundsAudit{}
	bounds, err := querybounds.New(audit, runtime.clock, esqlReplayGuard{})
	if err != nil {
		t.Fatal(err)
	}
	queryValue := query.Value()
	authority := querybounds.AuthoritySnapshot{OrganizationID: queryValue.Scope.OrganizationID,
		TenantID: queryValue.Scope.TenantID, CaseID: queryValue.Scope.CaseID, ActorID: queryValue.Authority.ActorID,
		ActorRevision: 1, ActorActive: true, SourceID: queryValue.Scope.SourceID, SourceRevision: 1, SourceActive: true,
		ResourceIDs: queryValue.Scope.ResourceIDs, AllowlistRevision: 1, AllowlistActive: true,
		CapabilityDigest: queryValue.CapabilityDigest, CapabilityRevision: 1, CapabilityActive: true,
		AuthorizationAllowed: true, AuthorizationDecisionDigest: queryValue.Authority.AuthorizationDigest,
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
	profile := queryruntime.Profile{Limits: queryValue.Limits, MinimumPollInterval: time.Millisecond,
		MaximumPollInterval: time.Second}
	controller, err := queryruntime.New(queryruntime.Config{Interactive: queryruntime.Profile{Mode: "interactive",
		Limits: profile.Limits, MinimumPollInterval: profile.MinimumPollInterval, MaximumPollInterval: profile.MaximumPollInterval},
		Export: queryruntime.Profile{Mode: "export", Limits: profile.Limits, MinimumPollInterval: profile.MinimumPollInterval,
			MaximumPollInterval: profile.MaximumPollInterval}, MaximumSessions: 10, CancellationWait: time.Second,
		RecordWait: time.Second}, runtime, &esqlRateGate{}, recorder, runtime.clock)
	if err != nil {
		t.Fatal(err)
	}
	session, err := controller.Start(context.Background(), queryruntime.StartRequest{Mode: "interactive",
		Admission: admission, Execution: execution})
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Poll(context.Background(), queryruntime.SessionRef{SessionID: session.SessionID,
		SessionDigest: session.SessionDigest})
	if err != nil || result.Session.Status != "complete" || !result.HasPage ||
		result.Session.BoundsDecisionDigest != admission.Decision.DecisionDigest ||
		result.Session.ExecutionDigest != execution.Digest() || result.Session.LastPageDigest != result.Page.Digest() ||
		len(audit.decisions) != 1 || len(recorder.sessions) != 2 {
		t.Fatalf("session=%+v audit=%d records=%d err=%v", result.Session, len(audit.decisions), len(recorder.sessions), err)
	}
}

func esqlRateKeyDigest(request queryruntime.RateRequest) string {
	encoded, _ := json.Marshal(request)
	canonical, _ := domaincontract.Canonicalize(encoded)
	sum := sha256.Sum256(append([]byte("COH-QUERY-RATE-KEY-V1\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testESQLRuntime(t testing.TB) (*ESQLRuntime, queryconnector.ValidatedCapability, *esqlClientStub) {
	t.Helper()
	discovery, _, clock := testAdapter(t)
	capability, err := discovery.Probe(context.Background(), testScope(), testAuthority())
	if err != nil {
		t.Fatal(err)
	}
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
	client := &esqlClientStub{}
	runtime, err := NewESQLRuntime(discovery, compiler, &schemaResolverStub{page: runtimeSchema(t)}, client, clock)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, capability, client
}

func runtimeQuery(t testing.TB, capability string) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: testID("5"), Scope: testScope(), Authority: testAuthority(),
		CapabilityDigest: capability, SchemaDigest: testDigest("6"), Language: "esql", NativeText: "FROM securityevent",
		TimeRange: queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits: queryconnector.Limits{MaximumRows: 10, MaximumBytes: 100000, MaximumDurationMillis: 5000,
			MaximumPages: 1, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2},
		RequestedAt: "2026-08-27T17:59:00.000000000Z", Deadline: "2026-08-27T18:10:00.000000000Z"}
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func runtimeSchema(t testing.TB) queryconnector.ValidatedSchemaPage {
	t.Helper()
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, RequestID: testID("6"), SchemaDigest: testDigest("6"),
		Entries: []queryconnector.SchemaEntry{{ResourceID: "securityevent", Name: "event_id", Type: "string"},
			{ResourceID: "securityevent", Name: "event_timestamp", Type: "timestamp"}},
		Complete: true, ProvenanceDigest: testDigest("7")}
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeSchemaPage(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}
