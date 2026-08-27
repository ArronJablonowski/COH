package queryruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var testNow = time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)

type clockStub struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *clockStub) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *clockStub) Add(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type adapterStub struct {
	mu            sync.Mutex
	polls         []queryconnector.ValidatedPoll
	pages         []queryconnector.ValidatedPage
	cancellations []queryconnector.ValidatedCancellation
	pollErr       error
	pageErr       error
	cancelErr     error
	pollCalls     int
	pageCalls     int
	cancelCalls   int
}

func (adapter *adapterStub) Poll(context.Context, queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.pollCalls++
	if adapter.pollErr != nil {
		return queryconnector.ValidatedPoll{}, adapter.pollErr
	}
	if len(adapter.polls) == 0 {
		return queryconnector.ValidatedPoll{}, queryconnector.NewError(queryconnector.Unavailable, "empty_stub", nil)
	}
	value := adapter.polls[0]
	adapter.polls = adapter.polls[1:]
	return value, nil
}

func (adapter *adapterStub) NextPage(context.Context, queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.pageCalls++
	if adapter.pageErr != nil {
		return queryconnector.ValidatedPage{}, adapter.pageErr
	}
	if len(adapter.pages) == 0 {
		return queryconnector.ValidatedPage{}, queryconnector.NewError(queryconnector.Unavailable, "empty_stub", nil)
	}
	value := adapter.pages[0]
	adapter.pages = adapter.pages[1:]
	return value, nil
}

func (adapter *adapterStub) Cancel(context.Context, queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.cancelCalls++
	if adapter.cancelErr != nil {
		return queryconnector.ValidatedCancellation{}, adapter.cancelErr
	}
	if len(adapter.cancellations) == 0 {
		return queryconnector.ValidatedCancellation{}, queryconnector.NewError(queryconnector.Unavailable, "empty_stub", nil)
	}
	value := adapter.cancellations[0]
	adapter.cancellations = adapter.cancellations[1:]
	return value, nil
}

type rateStub struct {
	mu       sync.Mutex
	calls    int
	err      error
	stale    bool
	mismatch bool
}

func (rate *rateStub) Reserve(_ context.Context, request RateRequest) (RateReservation, error) {
	rate.mu.Lock()
	defer rate.mu.Unlock()
	rate.calls++
	if rate.err != nil {
		return RateReservation{}, rate.err
	}
	requested, _ := time.Parse(timestampLayout, request.RequestedAt)
	key, _ := canonicalDigest(rateRequestDigestDomain, request)
	reservation := RateReservation{SchemaVersion: RateSchemaVersion, ContractVersion: ContractVersion,
		KeyDigest: key, SessionID: request.SessionID, Operation: request.Operation, Sequence: uint64(rate.calls),
		ReservedAt: requested.Format(timestampLayout), ValidUntil: requested.Add(time.Minute).Format(timestampLayout)}
	if rate.stale {
		reservation.ReservedAt = requested.Add(-2 * time.Minute).Format(timestampLayout)
		reservation.ValidUntil = requested.Add(-time.Minute).Format(timestampLayout)
	}
	if rate.mismatch {
		reservation.Operation = "cancel"
	}
	return FinalizeRateReservation(reservation)
}

type recorderStub struct {
	mu       sync.Mutex
	sessions []Session
	err      error
}

func (recorder *recorderStub) RecordQuerySession(_ context.Context, session Session) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.err != nil {
		return recorder.err
	}
	recorder.sessions = append(recorder.sessions, session)
	return nil
}

type boundsAudit struct{}

func (boundsAudit) AppendQueryBoundDecision(context.Context, querybounds.Decision) error { return nil }

type replayStub struct{}

func (replayStub) Observe(context.Context, string, string) (bool, error) { return false, nil }

func testController(t testing.TB, adapter *adapterStub) (*Controller, *clockStub, *rateStub, *recorderStub, StartRequest) {
	t.Helper()
	clock, rate, recorder := &clockStub{now: testNow}, &rateStub{}, &recorderStub{}
	controller, err := New(testConfig(), adapter, rate, recorder, clock)
	if err != nil {
		t.Fatal(err)
	}
	return controller, clock, rate, recorder, validStart(t)
}

func testConfig() Config {
	return Config{Interactive: Profile{Mode: "interactive", Limits: limits(100, 1000, 60_000, 3, 2, 100, 5),
		MinimumPollInterval: 100 * time.Millisecond, MaximumPollInterval: time.Second},
		Export: Profile{Mode: "export", Limits: limits(500, 5000, 120_000, 8, 4, 1000, 10),
			MinimumPollInterval: 100 * time.Millisecond, MaximumPollInterval: 2 * time.Second},
		MaximumSessions: 100, CancellationWait: time.Second, RecordWait: time.Second}
}

func validStart(t testing.TB) StartRequest {
	t.Helper()
	query := validQuery(t)
	engine, err := querybounds.New(boundsAudit{}, queryboundsClock{testNow}, replayStub{})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := engine.Admit(context.Background(), query, validAuthority(query))
	if err != nil {
		t.Fatal(err)
	}
	executionValue := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, AttemptID: id("6"),
		Handle: jobHandle(), Outcome: "running", StartedAt: testNow.Format(timestampLayout), ProvenanceDigest: digest("6")}
	execution := decodeExecution(t, executionValue)
	return StartRequest{Mode: "interactive", Admission: admission, Execution: execution}
}

type queryboundsClock struct{ now time.Time }

func (clock queryboundsClock) Now() time.Time { return clock.now }

func validQuery(t testing.TB) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: id("1"), Scope: queryconnector.Scope{OrganizationID: id("2"), TenantID: id("3"), CaseID: id("4"),
			SourceID: "sentinel-prod", ResourceIDs: []string{"securityevent"}},
		Authority: queryconnector.AuthorityBinding{ActorID: id("5"), AuthorizationDigest: digest("b"),
			PolicyDecisionDigest: digest("c"), AuditReservationDigest: digest("d")},
		CapabilityDigest: digest("e"), SchemaDigest: digest("f"), Language: "kql", NativeText: "SecurityEvent | take 10",
		TimeRange:   queryconnector.TimeRange{Start: testNow.Add(-time.Hour).Format(timestampLayout), End: testNow.Format(timestampLayout)},
		Limits:      limits(1000, 1<<20, 120_000, 10, 4, 1_000_000, 12),
		RequestedAt: testNow.Add(-time.Second).Format(timestampLayout), Deadline: testNow.Add(5 * time.Minute).Format(timestampLayout)}
	return decodeQuery(t, value)
}

func validAuthority(query queryconnector.ValidatedQuery) querybounds.AuthoritySnapshot {
	value := query.Value()
	return querybounds.AuthoritySnapshot{OrganizationID: value.Scope.OrganizationID, TenantID: value.Scope.TenantID,
		CaseID: value.Scope.CaseID, ActorID: value.Authority.ActorID, ActorRevision: 1, ActorActive: true,
		SourceID: value.Scope.SourceID, SourceRevision: 1, SourceActive: true, ResourceIDs: value.Scope.ResourceIDs,
		AllowlistRevision: 1, AllowlistActive: true, CapabilityDigest: value.CapabilityDigest,
		CapabilityRevision: 1, CapabilityActive: true, AuthorizationAllowed: true,
		AuthorizationDecisionDigest: value.Authority.AuthorizationDigest, PolicyAllowed: true,
		PolicyDecisionDigest: value.Authority.PolicyDecisionDigest, PolicyRevision: 1,
		AuditReservationDigest: value.Authority.AuditReservationDigest, RevocationRevision: 1,
		MaximumInterval: 2 * time.Hour, MaximumLimits: value.Limits, ObservedAt: testNow.Add(-time.Second)}
}

func pageRecord(t testing.TB, number uint32, statistics queryconnector.Statistics,
	completeness queryconnector.Completeness, next bool) queryconnector.ValidatedPage {
	t.Helper()
	value := queryconnector.ResultPage{SchemaVersion: queryconnector.PageSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: id("1"), AttemptID: id("6"), PageNumber: number, Rows: []map[string]any{{"event_id": number}},
		ResultDigest: digest("7"), Completeness: completeness, Statistics: statistics, ProvenanceDigest: digest("8")}
	if next {
		handle := pageHandle()
		value.NextPage = &handle
	}
	encoded, _ := json.Marshal(value)
	page, err := queryconnector.DecodePage(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func pollRecord(t testing.TB, outcome string, statistics queryconnector.Statistics,
	completeness queryconnector.Completeness, page *queryconnector.ValidatedPage) queryconnector.ValidatedPoll {
	t.Helper()
	value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: id("1"), AttemptID: id("6"), Outcome: outcome, Statistics: statistics,
		Completeness: completeness, ProvenanceDigest: digest("9")}
	if page != nil {
		pageValue := page.Value()
		value.Page = &pageValue
	}
	encoded, _ := json.Marshal(value)
	poll, err := queryconnector.DecodePoll(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return poll
}

func cancellationRecord(t testing.TB, outcome string) queryconnector.ValidatedCancellation {
	t.Helper()
	confirmed := testNow.Format(timestampLayout)
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: id("1"), AttemptID: id("6"), Outcome: outcome,
		RequestedAt: testNow.Format(timestampLayout), ProvenanceDigest: digest("a")}
	if outcome == "confirmed" {
		value.ConfirmedAt = &confirmed
	}
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeCancellation(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
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

func decodeExecution(t testing.TB, value queryconnector.Execution) queryconnector.ValidatedExecution {
	t.Helper()
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeExecution(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func complete() queryconnector.Completeness {
	return queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
}

func partial(reason string) queryconnector.Completeness {
	return queryconnector.Completeness{Status: "partial", ReasonCodes: []string{reason}, Partial: true, VendorConfirmed: true}
}

func unknown(reason string) queryconnector.Completeness {
	return queryconnector.Completeness{Status: "unknown", ReasonCodes: []string{reason}}
}

func stats(rows uint64, pages, slices uint32) queryconnector.Statistics {
	return queryconnector.Statistics{RowsScanned: rows, RowsReturned: rows, BytesReturned: rows * 10,
		DurationMillis: uint64(pages) * 10, PagesReturned: pages, SlicesCompleted: slices, CostMillionths: rows}
}

func limits(rows, bytes, duration uint64, pages, slices uint32, cost uint64, rate uint32) queryconnector.Limits {
	return queryconnector.Limits{MaximumRows: rows, MaximumBytes: bytes, MaximumDurationMillis: duration,
		MaximumPages: pages, MaximumSlices: slices, MaximumCostMillionths: cost, RequestsPerMinute: rate}
}

func jobHandle() queryconnector.HandleRef {
	return queryconnector.HandleRef{HandleID: id("7"), Kind: "query_job", SourceID: "sentinel-prod",
		OpaqueDigest: digest("7"), IssuedAt: testNow.Format(timestampLayout), ExpiresAt: testNow.Add(time.Hour).Format(timestampLayout)}
}

func pageHandle() queryconnector.HandleRef {
	return queryconnector.HandleRef{HandleID: id("8"), Kind: "result_page", SourceID: "sentinel-prod",
		OpaqueDigest: digest("8"), IssuedAt: testNow.Format(timestampLayout), ExpiresAt: testNow.Add(time.Hour).Format(timestampLayout)}
}

func id(character string) string     { return "0198e300-1000-7000-8000-00000000000" + character }
func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

var errUnavailable = errors.New("secret dependency detail")
