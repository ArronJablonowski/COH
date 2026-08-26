package executionstop

import (
	"context"
	"sync"
	"testing"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

const (
	testOrg       = "0198d6c4-1111-7111-8111-111111111111"
	testTenant    = "0198d6c4-2222-7222-8222-222222222222"
	testCase      = "0198d6c4-3333-7333-8333-333333333333"
	testOtherCase = "0198d6c4-4444-7444-8444-444444444444"
)

type fakeStopGuard struct {
	mu       sync.Mutex
	err      error
	denyCall int
	calls    int
}

func (guard *fakeStopGuard) Allow(context.Context, string, string, string) error {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.calls++
	if guard.denyCall != 0 && guard.calls >= guard.denyCall {
		return stopcontract.NewError(stopcontract.Denied, "emergency_stop_active")
	}
	return guard.err
}

func TestTrackerCancelsOnlyAffectedScopeAndReplaysEvidence(t *testing.T) {
	tracker, err := New("native-executions", &fakeStopGuard{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := tracker.Begin(context.Background(), "target", Scope{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase})
	if err != nil {
		t.Fatal(err)
	}
	other, err := tracker.Begin(context.Background(), "other", Scope{OrganizationID: testOrg, TenantID: testTenant, CaseID: testOtherCase})
	if err != nil {
		t.Fatal(err)
	}
	targetFinished := make(chan struct{})
	go func() {
		<-target.Context.Done()
		target.Finish()
		close(targetFinished)
	}()
	request := stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case", OrganizationID: testOrg,
		TenantID: testTenant, CaseID: testCase}, Epoch: 2}
	first, err := tracker.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tracker.Apply(context.Background(), request)
	if err != nil || first == "" || second != first {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
	<-targetFinished
	select {
	case <-other.Context.Done():
		t.Fatal("other case was canceled")
	default:
	}
	other.Finish()
}

func TestTrackerClosesBeginActivationRace(t *testing.T) {
	tracker, err := New("oci-executions", &fakeStopGuard{denyCall: 2})
	if err != nil {
		t.Fatal(err)
	}
	execution, err := tracker.Begin(context.Background(), "race", Scope{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase})
	if execution != nil || stopcontract.Code(err) != stopcontract.Denied || len(tracker.active) != 0 {
		t.Fatalf("execution=%+v active=%d err=%v", execution, len(tracker.active), err)
	}
}

func TestTrackerReportsUncooperativeExecutionTimeout(t *testing.T) {
	tracker, err := New("native-executions", &fakeStopGuard{})
	if err != nil {
		t.Fatal(err)
	}
	execution, err := tracker.Begin(context.Background(), "blocked", Scope{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = tracker.Apply(ctx, stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "global",
		OrganizationID: testOrg, TenantID: testTenant}, Epoch: 3})
	execution.Finish()
	if err == nil || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("err=%v context=%v", err, ctx.Err())
	}
}
