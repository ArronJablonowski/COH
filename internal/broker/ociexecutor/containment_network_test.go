package ociexecutor

import (
	"context"
	"sync"
	"testing"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

type mutableStopGuard struct {
	mu  sync.Mutex
	err error
}

func (guard *mutableStopGuard) Allow(context.Context, string, string, string) error {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.err
}

func (guard *mutableStopGuard) set(err error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.err = err
}

func TestContainmentNetworkCutsOnlyAffectedEgressAndReplaysEvidence(t *testing.T) {
	inner := &fakeNetworkBroker{clock: fixedClock{value: testNow}}
	guard := &mutableStopGuard{}
	broker, err := NewContainmentNetworkBroker(inner, guard)
	if err != nil {
		t.Fatal(err)
	}
	target := networkContainmentRequest("attempt-target", testRequest().CaseID)
	other := networkContainmentRequest("attempt-other", "0198d6c4-9999-7999-8999-999999999999")
	targetLease, err := broker.Acquire(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	otherLease, err := broker.Acquire(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	stop := stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case", OrganizationID: target.OrganizationID,
		TenantID: target.TenantID, CaseID: target.CaseID}, Epoch: 3, ActivatedAt: testNow}
	first, err := broker.Apply(context.Background(), stop)
	if err != nil {
		t.Fatal(err)
	}
	second, err := broker.Apply(context.Background(), stop)
	if err != nil || first == "" || second != first || cleanupCount(inner) != 1 {
		t.Fatalf("first=%q second=%q cleanups=%d err=%v", first, second, cleanupCount(inner), err)
	}
	if err := targetLease.Cleanup(); err != nil || cleanupCount(inner) != 1 {
		t.Fatalf("target cleanup was not idempotent: cleanups=%d err=%v", cleanupCount(inner), err)
	}
	if err := otherLease.Cleanup(); err != nil || cleanupCount(inner) != 2 {
		t.Fatalf("other cleanup: cleanups=%d err=%v", cleanupCount(inner), err)
	}
}

func TestContainmentNetworkClosesAcquireActivationRace(t *testing.T) {
	guard := &mutableStopGuard{}
	inner := &fakeNetworkBroker{clock: fixedClock{value: testNow}}
	inner.mutate = func(*NetworkLease) {
		guard.set(stopcontract.NewError(stopcontract.Denied, "emergency_stop_active"))
	}
	broker, err := NewContainmentNetworkBroker(inner, guard)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := broker.Acquire(context.Background(), networkContainmentRequest("attempt-race", testRequest().CaseID))
	if lease.LeaseID != "" || Code(err) != Denied || Reason(err) != "emergency_stop_active" || cleanupCount(inner) != 1 {
		t.Fatalf("lease=%+v cleanups=%d err=%v", lease, cleanupCount(inner), err)
	}
}

func TestContainmentNetworkHonorsControlDeadline(t *testing.T) {
	release := make(chan struct{})
	inner := &fakeNetworkBroker{clock: fixedClock{value: testNow}}
	inner.mutate = func(lease *NetworkLease) {
		lease.Cleanup = func() error { <-release; return nil }
	}
	broker, err := NewContainmentNetworkBroker(inner, &mutableStopGuard{})
	if err != nil {
		t.Fatal(err)
	}
	request := networkContainmentRequest("attempt-blocked", testRequest().CaseID)
	lease, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = broker.Apply(ctx, stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "global",
		OrganizationID: request.OrganizationID, TenantID: request.TenantID}, Epoch: 5})
	close(release)
	if cleanupErr := lease.Cleanup(); cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	if err == nil || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("err=%v context=%v", err, ctx.Err())
	}
}

func cleanupCount(broker *fakeNetworkBroker) int {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	return broker.cleanups
}

func networkContainmentRequest(attemptID, caseID string) NetworkRequest {
	request := testRequest()
	return NetworkRequest{AttemptID: attemptID, OrganizationID: request.OrganizationID, TenantID: request.TenantID,
		CaseID: caseID, ActorID: request.ActorID, AuthorityUntil: testNow.Add(time.Minute).Format(time.RFC3339Nano)}
}
