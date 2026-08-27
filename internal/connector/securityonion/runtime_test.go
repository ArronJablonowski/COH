package securityonion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type mutableOnionClock struct{ now time.Time }

func (clock *mutableOnionClock) Now() time.Time { return clock.now }

type runtimeClientStub struct {
	mu      sync.Mutex
	calls   []string
	info    InfoResult
	result  EventQueryResult
	receipt CallReceipt
	err     error
}

func (client *runtimeClientStub) Inspect(_ context.Context, request InfoRequest) (InfoResult, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.calls = append(client.calls, request.Binding.Operation)
	return client.info, client.receipt, client.err
}

func (client *runtimeClientStub) QueryEvents(_ context.Context,
	request EventQueryRequest) (EventQueryResult, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.calls = append(client.calls, request.Binding.Operation)
	return client.result, client.receipt, client.err
}

func (client *runtimeClientStub) callCount(operation string) int {
	client.mu.Lock()
	defer client.mu.Unlock()
	count := 0
	for _, value := range client.calls {
		if value == operation {
			count++
		}
	}
	return count
}

func TestOQLRuntimeCompletesSharedConnectorAndEvidenceLifecycle(t *testing.T) {
	runtime, client, capability, schema := testOQLRuntime(t)
	query := runtimeOQLQuery(t, capability.Digest(), schema.Value().SchemaDigest)
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil || validation.Value().Outcome != "accepted" {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	runtime.mu.Lock()
	prepared := runtime.validated[query.Digest()]
	runtime.mu.Unlock()
	if prepared.query.NativeText != "" {
		t.Fatal("runtime retained caller OQL after compilation")
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || execution.Value().Outcome != "running" || execution.Value().Handle.Kind != "query_job" {
		t.Fatalf("execution=%+v err=%v", execution.Value(), err)
	}
	pollRequest := queryconnector.PollRequest{QueryID: query.Value().QueryID, AttemptID: execution.Value().AttemptID,
		Handle: execution.Value().Handle, Authority: query.Value().Authority}
	poll, err := runtime.Poll(context.Background(), pollRequest)
	if err != nil || poll.Value().Outcome != "completed" || poll.Value().Page == nil ||
		poll.Value().Completeness.Status != "complete" || !poll.Value().Completeness.VendorConfirmed ||
		poll.Value().Page.Rows[0]["event_id"] != "event-1" || client.callCount("securityonion.query_events") != 1 {
		t.Fatalf("poll=%+v calls=%v err=%v", poll.Value(), client.calls, err)
	}
	if _, err := runtime.NextPage(context.Background(), queryconnector.PageRequest{}); queryconnector.Code(err) != queryconnector.Unsupported {
		t.Fatalf("next page err=%v", err)
	}
	cancellation, err := runtime.Cancel(context.Background(), queryconnector.CancelRequest{QueryID: pollRequest.QueryID,
		AttemptID: pollRequest.AttemptID, Handle: pollRequest.Handle, Authority: pollRequest.Authority,
		RequestedAt: "2026-08-27T18:00:01.000000000Z"})
	if err != nil || cancellation.Value().Outcome != "confirmed" {
		t.Fatalf("cancellation=%+v err=%v", cancellation.Value(), err)
	}

	audit := &runtimeBoundsAudit{}
	bounds, err := querybounds.New(audit, runtime.clock, runtimeReplayGuard{})
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
	recorder := &runtimeRecorder{}
	profile := queryruntime.Profile{Limits: queryValue.Limits, MinimumPollInterval: time.Millisecond,
		MaximumPollInterval: time.Second}
	controller, err := queryruntime.New(queryruntime.Config{Interactive: queryruntime.Profile{Mode: "interactive",
		Limits: profile.Limits, MinimumPollInterval: profile.MinimumPollInterval, MaximumPollInterval: profile.MaximumPollInterval},
		Export: queryruntime.Profile{Mode: "export", Limits: profile.Limits, MinimumPollInterval: profile.MinimumPollInterval,
			MaximumPollInterval: profile.MaximumPollInterval}, MaximumSessions: 10, CancellationWait: time.Second,
		RecordWait: time.Second}, runtime, &runtimeRateGate{}, recorder, runtime.clock)
	if err != nil {
		t.Fatal(err)
	}
	session, err := controller.Start(context.Background(), queryruntime.StartRequest{Mode: "interactive",
		Admission: admission, Execution: execution})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := controller.Poll(context.Background(), queryruntime.SessionRef{SessionID: session.SessionID,
		SessionDigest: session.SessionDigest})
	if err != nil || shared.Session.Status != "complete" || !shared.HasPage || len(recorder.sessions) != 2 ||
		shared.Session.BoundsDecisionDigest != admission.Decision.DecisionDigest ||
		shared.Session.ExecutionDigest != execution.Digest() || shared.Session.LastPageDigest != shared.Page.Digest() {
		t.Fatalf("shared=%+v records=%d err=%v", shared.Session, len(recorder.sessions), err)
	}
}

func TestOQLRuntimeReportsCapFilledAndUnconfirmedResults(t *testing.T) {
	runtime, client, capability, schema := testOQLRuntime(t)
	client.result.EventCapHit = true
	client.result.TotalEvents = 100
	query := runtimeOQLQuery(t, capability.Digest(), schema.Value().SchemaDigest)
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	poll, err := runtime.Poll(context.Background(), queryconnector.PollRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority})
	if err != nil || poll.Value().Outcome != "partial" || !poll.Value().Completeness.Truncated ||
		!poll.Value().Completeness.Partial || poll.Value().Completeness.ReasonCodes[0] != "securityonion_event_limit_reached" {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
	metric := runtimeCompleteness(EventQueryResult{Metrics: []MetricRecord{{Keys: []string{"10.0.0.1"}, Value: 2}},
		TotalEvents: 2})
	if metric.Status != "partial" || metric.Truncated || metric.ReasonCodes[0] != "securityonion_completion_unconfirmed" {
		t.Fatalf("metric=%+v", metric)
	}
}

func TestOQLRuntimeCoalescesConcurrentExecution(t *testing.T) {
	runtime, client, capability, schema := testOQLRuntime(t)
	query := runtimeOQLQuery(t, capability.Digest(), schema.Value().SchemaDigest)
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 24
	var group sync.WaitGroup
	digests := make(chan string, workers)
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			execution, executeErr := runtime.Execute(context.Background(), query, validation)
			if executeErr != nil {
				digests <- "error"
				return
			}
			digests <- execution.Digest()
		}()
	}
	group.Wait()
	close(digests)
	want := ""
	for digest := range digests {
		if want == "" {
			want = digest
		}
		if digest == "error" || digest != want {
			t.Fatalf("digest=%s want=%s", digest, want)
		}
	}
	if client.callCount("securityonion.query_events") != 1 {
		t.Fatalf("query calls=%d", client.callCount("securityonion.query_events"))
	}
}

func testOQLRuntime(t testing.TB) (*OQLRuntime, *runtimeClientStub,
	queryconnector.ValidatedCapability, queryconnector.ValidatedSchemaPage) {
	t.Helper()
	config := testConfig()
	clock := &mutableOnionClock{now: time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)}
	qualifier, _ := NewQualifier(config, clock)
	qualification, err := qualifier.Qualify(context.Background(), testOpenAPI(t))
	if err != nil {
		t.Fatal(err)
	}
	client := &runtimeClientStub{info: InfoResult{Version: "3.2.1", ElasticVersion: "9.1.0", ResultDigest: testDigest("8")},
		result: EventQueryResult{Events: []EventRecord{{ID: "event-1", Timestamp: "2026-08-27T17:30:00.000Z",
			Payload: map[string]any{"event_timestamp": "2026-08-27T17:30:00.000Z", "event_id": "event-1",
				"message": "allowed", "source_ip": "10.0.0.1"}}}, TotalEvents: 1, ElapsedMillis: 4,
			ResultDigest: testDigest("9")}, receipt: CallReceipt{RequestDigest: testDigest("1"),
			ResponseDigest: testDigest("2"), LeaseDecisionDigest: testDigest("3"), TransportDigest: config.TransportIdentityDigest}}
	adapter, err := NewAdapter(config, client, qualification, clock)
	if err != nil {
		t.Fatal(err)
	}
	compiler, _ := NewOQLCompiler(config, clock)
	runtime, err := NewOQLRuntime(adapter, compiler, clock)
	if err != nil {
		t.Fatal(err)
	}
	base := testOQLQuery(t, `{"mode":"events","filter":{"match_all":{}}}`).Value()
	capability, err := runtime.Probe(context.Background(), base.Scope, base.Authority)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := runtime.DiscoverSchema(context.Background(), queryconnector.SchemaRequest{RequestID: testID("6"),
		Scope: base.Scope, Authority: base.Authority, CapabilityDigest: capability.Digest(), Limits: base.Limits})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, client, capability, schema
}

func runtimeOQLQuery(t testing.TB, capability, schema string) queryconnector.ValidatedQuery {
	t.Helper()
	value := testOQLQuery(t, `{"mode":"events","filter":{"match_all":{}}}`).Value()
	value.CapabilityDigest, value.SchemaDigest = capability, schema
	return decodeOQLQuery(t, value)
}

type runtimeBoundsAudit struct{ decisions []querybounds.Decision }

func (audit *runtimeBoundsAudit) AppendQueryBoundDecision(_ context.Context, decision querybounds.Decision) error {
	audit.decisions = append(audit.decisions, decision)
	return nil
}

type runtimeReplayGuard struct{}

func (runtimeReplayGuard) Observe(context.Context, string, string) (bool, error) { return false, nil }

type runtimeRecorder struct{ sessions []queryruntime.Session }

func (recorder *runtimeRecorder) RecordQuerySession(_ context.Context, session queryruntime.Session) error {
	recorder.sessions = append(recorder.sessions, session)
	return nil
}

type runtimeRateGate struct{ sequence uint64 }

func (gate *runtimeRateGate) Reserve(_ context.Context,
	request queryruntime.RateRequest) (queryruntime.RateReservation, error) {
	gate.sequence++
	requested, _ := time.Parse(timestampLayout, request.RequestedAt)
	return queryruntime.FinalizeRateReservation(queryruntime.RateReservation{SchemaVersion: queryruntime.RateSchemaVersion,
		ContractVersion: queryruntime.ContractVersion, KeyDigest: runtimeRateKeyDigest(request), SessionID: request.SessionID,
		Operation: request.Operation, Sequence: gate.sequence, ReservedAt: request.RequestedAt,
		ValidUntil: requested.Add(time.Minute).Format(timestampLayout)})
}

func runtimeRateKeyDigest(request queryruntime.RateRequest) string {
	encoded, _ := json.Marshal(request)
	canonical, _ := domaincontract.Canonicalize(encoded)
	sum := sha256.Sum256(append([]byte("COH-QUERY-RATE-KEY-V1\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
