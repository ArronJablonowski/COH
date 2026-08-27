package queryruntime

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestCanonicalSessionFixtureAndStrictDecoder(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/query-runtime/v1/fixtures/session.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	session, canonical, err := DecodeSession(context.Background(), input)
	if err != nil || session.SessionDigest != "sha256:159644d34412244c8e04de04aef71dc7d64f7adcda7ca14d3a6301c124622332" ||
		!bytes.Equal(bytes.TrimSpace(input), canonical) {
		t.Fatalf("digest=%s canonical=%t err=%v", session.SessionDigest, bytes.Equal(bytes.TrimSpace(input), canonical), err)
	}
	unknown := append([]byte(`{"unexpected":true,`), bytes.TrimSpace(input)[1:]...)
	if _, _, err := DecodeSession(context.Background(), unknown); Code(err) != InvalidInput || Reason(err) != "document_decoding" {
		t.Fatalf("unknown field err=%v", err)
	}
	mutated := bytes.Replace(input, []byte(`"rows_returned":0`), []byte(`"rows_returned":1`), 1)
	if _, _, err := DecodeSession(context.Background(), mutated); Code(err) != Conflict || Reason(err) != "session_integrity" {
		t.Fatalf("mutated fixture err=%v", err)
	}
}

func TestStartBindsAdmissionExecutionAndNarrowProfile(t *testing.T) {
	controller, _, _, recorder, request := testController(t, &adapterStub{})
	session, err := controller.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != "running" || session.Revision != 1 || session.QueryDigest != request.Admission.Query.Digest() ||
		session.BoundsDecisionDigest != request.Admission.Decision.DecisionDigest ||
		session.ExecutionDigest != request.Execution.Digest() || session.EffectiveLimits != testConfig().Interactive.Limits ||
		len(recorder.sessions) != 1 || VerifySession(session) != nil {
		t.Fatalf("session=%+v records=%d", session, len(recorder.sessions))
	}
	again, err := controller.Start(context.Background(), request)
	if err != nil || again.SessionDigest != session.SessionDigest || len(recorder.sessions) != 1 {
		t.Fatalf("idempotent start=%+v records=%d err=%v", again, len(recorder.sessions), err)
	}
	changed := session
	changed.Usage.RowsReturned++
	if Code(VerifySession(changed)) != Conflict {
		t.Fatal("mutated session passed integrity verification")
	}
}

func TestSlicePlanIsExactDeterministicAndNonAuthoritative(t *testing.T) {
	request := validStart(t)
	queryValue := request.Admission.Query.Value()
	queryValue.TimeRange.Start = testNow.Add(-time.Hour - time.Nanosecond).Format(timestampLayout)
	queryValue.Deadline = testNow.Add(5 * time.Minute).Format(timestampLayout)
	query := decodeQuery(t, queryValue)
	request = validStartForQuery(t, query)
	plan, err := PlanSlices(context.Background(), request.Admission.Query, request.Admission.Decision, 3)
	if err != nil || len(plan.Slices) != 3 || VerifySlicePlan(plan) != nil {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if plan.Slices[0].Start != queryValue.TimeRange.Start || plan.Slices[2].End != queryValue.TimeRange.End ||
		plan.Slices[0].End != plan.Slices[1].Start || plan.Slices[1].End != plan.Slices[2].Start {
		t.Fatalf("non-contiguous plan=%+v", plan.Slices)
	}
	again, err := PlanSlices(context.Background(), request.Admission.Query, request.Admission.Decision, 3)
	if err != nil || again.PlanDigest != plan.PlanDigest {
		t.Fatalf("nondeterministic plan err=%v", err)
	}
	plan.Slices[1].End = plan.Slices[1].End[:len(plan.Slices[1].End)-2] + "2Z"
	if Code(VerifySlicePlan(plan)) != Conflict {
		t.Fatal("mutated slice plan passed")
	}
	if _, err := PlanSlices(context.Background(), request.Admission.Query, request.Admission.Decision, 5); Code(err) != Denied || Reason(err) != "slice_limit_exceeded" {
		t.Fatalf("slice cap err=%v", err)
	}
}

func TestPollPageNextPageAndExactReplay(t *testing.T) {
	firstPage := pageRecord(t, 1, stats(1, 1, 1), complete(), true)
	secondPage := pageRecord(t, 2, stats(2, 2, 1), complete(), false)
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "completed", stats(1, 1, 1), complete(), &firstPage)}, pages: []queryconnector.ValidatedPage{secondPage}}
	controller, _, rate, recorder, request := testController(t, adapter)
	started, err := controller.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	ref := SessionRef{SessionID: started.SessionID, SessionDigest: started.SessionDigest}
	first, err := controller.Poll(context.Background(), ref)
	if err != nil || !first.HasPage || first.Session.Status != "running" || first.Session.NextPageNumber != 2 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	replayed, err := controller.Poll(context.Background(), ref)
	if err != nil || replayed.Session.SessionDigest != first.Session.SessionDigest || adapter.pollCalls != 1 {
		t.Fatalf("replay=%+v calls=%d err=%v", replayed, adapter.pollCalls, err)
	}
	final, err := controller.NextPage(context.Background(), SessionRef{SessionID: started.SessionID,
		SessionDigest: first.Session.SessionDigest})
	if err != nil || !final.HasPage || final.Session.Status != "complete" || final.Session.Usage.RowsReturned != 2 ||
		adapter.pageCalls != 1 || rate.calls != 2 || len(recorder.sessions) != 3 {
		t.Fatalf("final=%+v rate=%d records=%d err=%v", final, rate.calls, len(recorder.sessions), err)
	}
}

func TestPartialCompletenessCannotBeUpgraded(t *testing.T) {
	firstPage := pageRecord(t, 1, stats(1, 1, 1), partial("vendor_partial"), true)
	secondPage := pageRecord(t, 2, stats(2, 2, 1), complete(), false)
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "partial", stats(1, 1, 1), partial("vendor_partial"), &firstPage)},
		pages: []queryconnector.ValidatedPage{secondPage}}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	first, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
	if err != nil || first.Session.Status != "running" {
		t.Fatalf("partial first=%+v err=%v", first, err)
	}
	final, err := controller.NextPage(context.Background(), SessionRef{started.SessionID, first.Session.SessionDigest})
	if err != nil || final.Session.Status != "partial" || final.Session.ReasonCode != "vendor_partial" {
		t.Fatalf("partial final=%+v err=%v", final, err)
	}
}

func TestCancellationIsBoundAndIdempotent(t *testing.T) {
	adapter := &adapterStub{cancellations: []queryconnector.ValidatedCancellation{cancellationRecord(t, "confirmed")}}
	controller, _, rate, recorder, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	intent := CancelIntent{SessionID: started.SessionID, SessionDigest: started.SessionDigest,
		IdempotencyKey: id("9"), ReasonCode: "user_requested"}
	canceled, err := controller.Cancel(context.Background(), intent)
	if err != nil || canceled.Status != "canceled" || canceled.CancellationIntentDigest == "" ||
		adapter.cancelCalls != 1 || rate.calls != 1 || len(recorder.sessions) != 2 {
		t.Fatalf("canceled=%+v calls=%d rate=%d err=%v", canceled, adapter.cancelCalls, rate.calls, err)
	}
	again, err := controller.Cancel(context.Background(), intent)
	if err != nil || again.SessionDigest != canceled.SessionDigest || adapter.cancelCalls != 1 {
		t.Fatalf("cancel replay=%+v calls=%d err=%v", again, adapter.cancelCalls, err)
	}
	intent.IdempotencyKey = id("a")
	if _, err := controller.Cancel(context.Background(), intent); Code(err) != Conflict || Reason(err) != "cancellation_changed" {
		t.Fatalf("changed cancellation err=%v", err)
	}
}

func TestConcurrentExactPollCoalescesByTransitionReplay(t *testing.T) {
	page := pageRecord(t, 1, stats(1, 1, 1), complete(), false)
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "completed", stats(1, 1, 1), complete(), &page)}}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	ref := SessionRef{started.SessionID, started.SessionDigest}
	results := make(chan Result, 16)
	errors := make(chan error, 16)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := controller.Poll(context.Background(), ref)
			results <- result
			errors <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errors)
	var digestValue string
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if digestValue == "" {
			digestValue = result.Session.SessionDigest
		} else if result.Session.SessionDigest != digestValue {
			t.Fatal("concurrent replay diverged")
		}
	}
	if adapter.pollCalls != 1 {
		t.Fatalf("poll calls=%d", adapter.pollCalls)
	}
}

func validStartForQuery(t testing.TB, query queryconnector.ValidatedQuery) StartRequest {
	t.Helper()
	engine, err := querybounds.New(boundsAudit{}, queryboundsClock{testNow}, replayStub{})
	if err != nil {
		t.Fatal(err)
	}
	authority := validAuthority(query)
	authority.MaximumLimits = query.Value().Limits
	authority.MaximumInterval = 2 * time.Hour
	admission, err := engine.Admit(context.Background(), query, authority)
	if err != nil {
		t.Fatal(err)
	}
	execution := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, AttemptID: id("6"),
		Handle: jobHandle(), Outcome: "running", StartedAt: testNow.Format(timestampLayout), ProvenanceDigest: digest("6")}
	return StartRequest{Mode: "interactive", Admission: admission, Execution: decodeExecution(t, execution)}
}
