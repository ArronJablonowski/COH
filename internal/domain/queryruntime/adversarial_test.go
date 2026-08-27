package queryruntime

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestEveryBudgetOverflowWithholdsPageAndCancels(t *testing.T) {
	base := stats(1, 1, 1)
	tests := []struct {
		name   string
		reason string
		mutate func(*queryconnector.Statistics)
	}{
		{"rows", "row_limit_exceeded", func(value *queryconnector.Statistics) {
			value.RowsScanned, value.RowsReturned = 101, 101
		}},
		{"bytes", "byte_limit_exceeded", func(value *queryconnector.Statistics) { value.BytesReturned = 1001 }},
		{"duration", "duration_limit_exceeded", func(value *queryconnector.Statistics) { value.DurationMillis = 60001 }},
		{"pages", "page_limit_exceeded", func(value *queryconnector.Statistics) { value.PagesReturned = 4 }},
		{"slices", "slice_limit_exceeded", func(value *queryconnector.Statistics) { value.SlicesCompleted = 3 }},
		{"cost", "cost_limit_exceeded", func(value *queryconnector.Statistics) { value.CostMillionths = 101 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statistics := base
			test.mutate(&statistics)
			page := pageRecord(t, 1, statistics, complete(), false)
			adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
				pollRecord(t, "completed", statistics, complete(), &page)},
				cancellations: []queryconnector.ValidatedCancellation{cancellationRecord(t, "confirmed")}}
			controller, _, rate, recorder, request := testController(t, adapter)
			started, _ := controller.Start(context.Background(), request)
			result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
			if Code(err) != Denied || Reason(err) != test.reason || result.HasPage || result.Session.Status != "truncated" ||
				adapter.cancelCalls != 1 || rate.calls != 2 || len(recorder.sessions) != 2 {
				t.Fatalf("result=%+v cancel=%d rate=%d records=%d err=%v", result, adapter.cancelCalls,
					rate.calls, len(recorder.sessions), err)
			}
		})
	}
}

func TestExactBudgetWithMoreReleasesPageThenStops(t *testing.T) {
	statistics := stats(100, 1, 1)
	page := pageRecord(t, 1, statistics, complete(), true)
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "completed", statistics, complete(), &page)},
		cancellations: []queryconnector.ValidatedCancellation{cancellationRecord(t, "confirmed")}}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
	if err != nil || !result.HasPage || result.Session.Status != "truncated" || result.Session.ReasonCode != "budget_exhausted" ||
		adapter.cancelCalls != 1 {
		t.Fatalf("result=%+v cancel=%d err=%v", result, adapter.cancelCalls, err)
	}
}

func TestUnknownCompletenessNeverReleasesPage(t *testing.T) {
	page := pageRecord(t, 1, stats(1, 1, 1), unknown("vendor_unconfirmed"), true)
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "completed", stats(1, 1, 1), unknown("vendor_unconfirmed"), &page)}}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
	if err != nil || result.HasPage || result.Session.Status != "uncertain" ||
		result.Session.ReasonCode != "vendor_unconfirmed" {
		t.Fatalf("unknown result=%+v err=%v", result, err)
	}
}

func TestStatisticsRegressionAndPageSubstitutionConflict(t *testing.T) {
	first := pageRecord(t, 1, stats(2, 1, 1), complete(), true)
	regressed := pageRecord(t, 2, stats(1, 2, 1), complete(), false)
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "completed", stats(2, 1, 1), complete(), &first)}, pages: []queryconnector.ValidatedPage{regressed}}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	firstResult, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.NextPage(context.Background(), SessionRef{started.SessionID, firstResult.Session.SessionDigest}); Code(err) != Conflict || Reason(err) != "statistics_regressed" {
		t.Fatalf("regression err=%v", err)
	}

	wrong := pageRecord(t, 2, stats(1, 1, 1), complete(), false)
	adapter = &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "completed", stats(1, 1, 1), complete(), &wrong)}}
	controller, _, _, _, request = testController(t, adapter)
	started, _ = controller.Start(context.Background(), request)
	if _, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); Code(err) != Conflict || Reason(err) != "page_sequence_mismatch" {
		t.Fatalf("page substitution err=%v", err)
	}
}

func TestRateDenialStaleAndSubstitutionFailBeforeAdapter(t *testing.T) {
	for _, test := range []struct {
		name   string
		setup  func(*rateStub)
		code   ErrorCode
		reason string
	}{
		{"exhausted", func(rate *rateStub) { rate.err = newError(Denied, "full", nil) }, Denied, "rate_exhausted"},
		{"unavailable", func(rate *rateStub) { rate.err = errUnavailable }, Unavailable, "rate_unavailable"},
		{"stale", func(rate *rateStub) { rate.stale = true }, Denied, "rate_reservation_stale"},
		{"substituted", func(rate *rateStub) { rate.mismatch = true }, Conflict, "rate_reservation_mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := &adapterStub{}
			controller, _, rate, _, request := testController(t, adapter)
			test.setup(rate)
			started, _ := controller.Start(context.Background(), request)
			if _, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); Code(err) != test.code || Reason(err) != test.reason || adapter.pollCalls != 0 {
				t.Fatalf("calls=%d err=%v", adapter.pollCalls, err)
			}
		})
	}
}

func TestRecorderFailureWithholdsPageAndAllowsRecovery(t *testing.T) {
	page := pageRecord(t, 1, stats(1, 1, 1), complete(), false)
	poll := pollRecord(t, "completed", stats(1, 1, 1), complete(), &page)
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{poll, poll}}
	controller, _, _, recorder, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	recorder.err = errUnavailable
	if result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); Code(err) != Unavailable || Reason(err) != "record_unavailable" || result.HasPage {
		t.Fatalf("failed recording result=%+v err=%v", result, err)
	}
	recorder.err = nil
	result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
	if err != nil || !result.HasPage || result.Session.Status != "complete" || adapter.pollCalls != 2 {
		t.Fatalf("recovery result=%+v calls=%d err=%v", result, adapter.pollCalls, err)
	}
}

func TestDeadlineCancellationAndAdapterRecovery(t *testing.T) {
	adapter := &adapterStub{pollErr: queryconnector.NewError(queryconnector.Timeout, "vendor_timeout", context.DeadlineExceeded)}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	if _, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); Code(err) != Timeout || Reason(err) != "adapter_timeout" {
		t.Fatalf("adapter timeout err=%v", err)
	}
	page := pageRecord(t, 1, stats(1, 1, 1), complete(), false)
	adapter.pollErr = nil
	adapter.polls = []queryconnector.ValidatedPoll{pollRecord(t, "completed", stats(1, 1, 1), complete(), &page)}
	if result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); err != nil || !result.HasPage {
		t.Fatalf("adapter recovery result=%+v err=%v", result, err)
	}

	adapter = &adapterStub{cancellations: []queryconnector.ValidatedCancellation{cancellationRecord(t, "confirmed")}}
	controller, deadlineClock, _, _, request := testController(t, adapter)
	started, _ = controller.Start(context.Background(), request)
	deadlineClock.Add(5 * time.Minute)
	if result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); Code(err) != Denied || Reason(err) != "query_deadline_elapsed" || result.Session.Status != "truncated" || adapter.pollCalls != 0 {
		t.Fatalf("deadline result=%+v calls=%d err=%v", result, adapter.pollCalls, err)
	}

	controller, _, _, _, request = testController(t, &adapterStub{})
	started, _ = controller.Start(context.Background(), request)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.Poll(canceled, SessionRef{started.SessionID, started.SessionDigest}); Code(err) != Canceled {
		t.Fatalf("caller cancellation err=%v", err)
	}
}

func TestInvalidStartCancellationAndPublicSurfaceFailClosed(t *testing.T) {
	controller, _, _, _, request := testController(t, &adapterStub{})
	request.Admission.Decision.DecisionDigest = digest("0")
	if _, err := controller.Start(context.Background(), request); Code(err) != Denied {
		t.Fatalf("tampered admission err=%v", err)
	}
	request = validStart(t)
	execution := request.Execution.Value()
	execution.QueryID = id("a")
	request.Execution = decodeExecution(t, execution)
	if _, err := controller.Start(context.Background(), request); Code(err) != Conflict {
		t.Fatalf("substituted execution err=%v", err)
	}

	controller, _, _, _, request = testController(t, &adapterStub{})
	started, _ := controller.Start(context.Background(), request)
	invalid := CancelIntent{SessionID: started.SessionID, SessionDigest: started.SessionDigest,
		IdempotencyKey: id("9"), ReasonCode: "raw vendor secret"}
	if _, err := controller.Cancel(context.Background(), invalid); Code(err) != InvalidInput {
		t.Fatalf("invalid cancellation err=%v", err)
	}

	adapterType := reflect.TypeOf((*Adapter)(nil)).Elem()
	if adapterType.NumMethod() != 3 {
		t.Fatalf("adapter method count=%d", adapterType.NumMethod())
	}
	for _, forbidden := range []string{"Execute", "Validate", "DiscoverSchema", "DoHTTP", "FetchCredential"} {
		if _, found := adapterType.MethodByName(forbidden); found {
			t.Fatalf("forbidden adapter method %s", forbidden)
		}
	}
}

func TestUnconfirmedCancellationRemainsUncertain(t *testing.T) {
	adapter := &adapterStub{cancellations: []queryconnector.ValidatedCancellation{cancellationRecord(t, "uncertain")}}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	result, err := controller.Cancel(context.Background(), CancelIntent{SessionID: started.SessionID,
		SessionDigest: started.SessionDigest, IdempotencyKey: id("9"), ReasonCode: "operator_requested"})
	if err != nil || result.Status != "uncertain" || result.ReasonCode != "cancellation_unconfirmed" {
		t.Fatalf("cancellation=%+v err=%v", result, err)
	}
}

func TestPollPageStatisticsMismatchIsDenied(t *testing.T) {
	page := pageRecord(t, 1, stats(1, 1, 1), complete(), false)
	pollValue := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: id("1"), AttemptID: id("6"), Outcome: "completed",
		Statistics: stats(2, 1, 1), Completeness: complete(), ProvenanceDigest: digest("9")}
	pageValue := page.Value()
	pollValue.Page = &pageValue
	encoded, _ := json.Marshal(pollValue)
	poll, err := queryconnector.DecodePoll(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{poll}}
	controller, _, _, _, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	if _, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); Code(err) != Conflict || Reason(err) != "poll_page_statistics_mismatch" {
		t.Fatalf("statistics substitution err=%v", err)
	}
}

func TestSessionCapacityAndTerminalReleaseAreBounded(t *testing.T) {
	config := testConfig()
	config.MaximumSessions = 1
	adapter, rate, recorder, clock := &adapterStub{
		cancellations: []queryconnector.ValidatedCancellation{cancellationRecord(t, "confirmed")}}, &rateStub{}, &recorderStub{}, &clockStub{now: testNow}
	controller, err := New(config, adapter, rate, recorder, clock)
	if err != nil {
		t.Fatal(err)
	}
	first := validStart(t)
	started, err := controller.Start(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := validStart(t)
	execution := second.Execution.Value()
	execution.AttemptID = id("a")
	second.Execution = decodeExecution(t, execution)
	if _, err := controller.Start(context.Background(), second); Code(err) != Denied || Reason(err) != "session_capacity_reached" {
		t.Fatalf("capacity err=%v", err)
	}
	if err := controller.Release(context.Background(), SessionRef{started.SessionID, started.SessionDigest}); Code(err) != Denied || Reason(err) != "session_active" {
		t.Fatalf("active release err=%v", err)
	}
	terminal, err := controller.Cancel(context.Background(), CancelIntent{SessionID: started.SessionID,
		SessionDigest: started.SessionDigest, IdempotencyKey: id("9"), ReasonCode: "user_requested"})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Release(context.Background(), SessionRef{terminal.SessionID, terminal.SessionDigest}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Get(context.Background(), SessionRef{terminal.SessionID, terminal.SessionDigest}); Code(err) != Denied || Reason(err) != "session_not_found" {
		t.Fatalf("released lookup err=%v", err)
	}
	if _, err := controller.Start(context.Background(), second); err != nil {
		t.Fatalf("capacity did not recover: %v", err)
	}
}

func TestCancellationFailureIsRecordedAsUncertain(t *testing.T) {
	adapter := &adapterStub{cancelErr: queryconnector.NewError(queryconnector.Unavailable, "vendor_secret", errUnavailable)}
	controller, _, _, recorder, request := testController(t, adapter)
	started, _ := controller.Start(context.Background(), request)
	intent := CancelIntent{SessionID: started.SessionID, SessionDigest: started.SessionDigest,
		IdempotencyKey: id("9"), ReasonCode: "operator_requested"}
	result, err := controller.Cancel(context.Background(), intent)
	if Code(err) != Unavailable || result.Status != "uncertain" || result.ReasonCode != "cancellation_unavailable" ||
		result.CancellationIntentDigest == "" || len(recorder.sessions) != 2 {
		t.Fatalf("uncertain cancellation=%+v records=%d err=%v", result, len(recorder.sessions), err)
	}
	again, err := controller.Cancel(context.Background(), intent)
	if err != nil || again.SessionDigest != result.SessionDigest || adapter.cancelCalls != 1 {
		t.Fatalf("uncertain replay=%+v calls=%d err=%v", again, adapter.cancelCalls, err)
	}
}

func TestExpiredJobAndPageHandlesBecomeExplicitUncertainty(t *testing.T) {
	controller, clock, _, _, request := testController(t, &adapterStub{})
	execution := request.Execution.Value()
	execution.Handle.ExpiresAt = testNow.Add(100 * time.Millisecond).Format(timestampLayout)
	request.Execution = decodeExecution(t, execution)
	started, _ := controller.Start(context.Background(), request)
	clock.Add(200 * time.Millisecond)
	result, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
	if Code(err) != Denied || Reason(err) != "job_handle_expired" || result.Session.Status != "uncertain" {
		t.Fatalf("job expiry result=%+v err=%v", result, err)
	}

	page := pageRecord(t, 1, stats(1, 1, 1), complete(), true)
	pageValue := page.Value()
	pageValue.NextPage.ExpiresAt = testNow.Add(100 * time.Millisecond).Format(timestampLayout)
	encoded, _ := json.Marshal(pageValue)
	page, err = queryconnector.DecodePage(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &adapterStub{polls: []queryconnector.ValidatedPoll{
		pollRecord(t, "completed", stats(1, 1, 1), complete(), &page)}}
	controller, clock, _, _, request = testController(t, adapter)
	started, _ = controller.Start(context.Background(), request)
	first, err := controller.Poll(context.Background(), SessionRef{started.SessionID, started.SessionDigest})
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(200 * time.Millisecond)
	result, err = controller.NextPage(context.Background(), SessionRef{started.SessionID, first.Session.SessionDigest})
	if Code(err) != Denied || Reason(err) != "page_handle_expired" || result.Session.Status != "uncertain" || adapter.pageCalls != 0 {
		t.Fatalf("page expiry result=%+v calls=%d err=%v", result, adapter.pageCalls, err)
	}
}

func TestConfigurationCapsAreMandatory(t *testing.T) {
	adapter, rate, recorder, clock := &adapterStub{}, &rateStub{}, &recorderStub{}, &clockStub{now: testNow}
	for _, mutate := range []func(*Config){
		func(value *Config) { value.MaximumSessions = 0 },
		func(value *Config) { value.MaximumSessions = MaximumSessionCapacity + 1 },
		func(value *Config) { value.CancellationWait = MaximumCancellationWait + 1 },
		func(value *Config) { value.RecordWait = MaximumRecordWait + 1 },
	} {
		config := testConfig()
		mutate(&config)
		if _, err := New(config, adapter, rate, recorder, clock); Code(err) != InvalidInput {
			t.Fatalf("invalid config err=%v", err)
		}
	}
}
