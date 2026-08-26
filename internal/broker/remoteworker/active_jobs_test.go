package remoteworker

import (
	"context"
	"testing"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

type dispatchCompletion struct {
	decision workercontract.Decision
	err      error
}

func TestRemoteJobControlCancelsAffectedCallbackAndReplaysEvidence(t *testing.T) {
	broker, guard, handle, request, authority := activeJobFixture(t)
	started := make(chan struct{})
	completed := make(chan dispatchCompletion, 1)
	go func() {
		decision, err := broker.Use(context.Background(), handle, dispatchFixture(handle.LeaseID, request.Scope), authority,
			func(ctx context.Context, _ workercontract.DispatchEnvelope) error {
				close(started)
				<-ctx.Done()
				return ctx.Err()
			})
		completed <- dispatchCompletion{decision: decision, err: err}
	}()
	<-started
	guard.set(stopcontract.NewError(stopcontract.Denied, "emergency_stop_active"))
	control, err := NewRemoteJobControl(broker)
	if err != nil {
		t.Fatal(err)
	}
	stop := jobStopRequest(request, 11)
	first, err := control.Apply(context.Background(), stop)
	if err != nil {
		t.Fatal(err)
	}
	second, err := control.Apply(context.Background(), stop)
	if err != nil || first == "" || second != first {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
	result := <-completed
	if workercontract.Code(result.err) != workercontract.Canceled || result.decision.Outcome != "canceled" {
		t.Fatalf("decision=%+v err=%v", result.decision, result.err)
	}
	if len(broker.jobsFor(stop.Scope)) != 0 {
		t.Fatalf("active jobs remain")
	}
}

func TestCooperativeControlTimesOutForUncooperativeCallbackAndCompletionStaysDenied(t *testing.T) {
	broker, guard, handle, request, authority := activeJobFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	completed := make(chan dispatchCompletion, 1)
	go func() {
		decision, err := broker.Use(context.Background(), handle, dispatchFixture(handle.LeaseID, request.Scope), authority,
			func(context.Context, workercontract.DispatchEnvelope) error {
				close(started)
				<-release
				return nil
			})
		completed <- dispatchCompletion{decision: decision, err: err}
	}()
	<-started
	guard.set(stopcontract.NewError(stopcontract.Denied, "emergency_stop_active"))
	control, err := NewCooperativeControl(broker)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err = control.Apply(ctx, jobStopRequest(request, 12)); err == nil || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("control err=%v context=%v", err, ctx.Err())
	}
	close(release)
	result := <-completed
	if workercontract.Code(result.err) != workercontract.Denied || workercontract.Reason(result.err) != "emergency_stop_active" ||
		result.decision.Outcome != "denied" {
		t.Fatalf("decision=%+v err=%v", result.decision, result.err)
	}
}

func activeJobFixture(t *testing.T) (*Broker, *mutableStopGuard, *Handle, workercontract.LeaseRequest, workercontract.LeaseAuthority) {
	t.Helper()
	broker, _, _, clock := setupBroker(t)
	guard := &mutableStopGuard{}
	broker.stop = guard
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	handle, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	return broker, guard, handle, request, authority
}

func jobStopRequest(request workercontract.LeaseRequest, epoch uint64) stopcontract.ControlRequest {
	return stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case", OrganizationID: request.Scope.OrganizationID,
		TenantID: request.Scope.TenantID, CaseID: request.Scope.CaseID}, Epoch: epoch}
}
