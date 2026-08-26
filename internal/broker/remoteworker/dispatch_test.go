package remoteworker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func TestIssueAndDispatchSingleUse(t *testing.T) {
	broker, _, audit, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	handle, decision, err := broker.Issue(context.Background(), request, authority)
	if err != nil || decision.Outcome != "allowed" || handle == nil {
		t.Fatalf("issue decision=%#v err=%v", decision, err)
	}
	dispatch := dispatchFixture(handle.LeaseID, request.Scope)
	called := 0
	completion, err := broker.Use(context.Background(), handle, dispatch, authority,
		func(_ context.Context, envelope workercontract.DispatchEnvelope) error {
			called++
			if envelope.LeaseID != handle.LeaseID || envelope.WorkerRevision != record.Revision {
				t.Fatalf("envelope=%#v", envelope)
			}
			if envelope.Scope.IsolationClass != "remote_isolated" {
				t.Fatalf("envelope=%#v", envelope)
			}
			return nil
		})
	if err != nil || called != 1 || completion.Event != "runner_dispatch_completion" || completion.Outcome != "allowed" {
		t.Fatalf("completion=%#v called=%d err=%v", completion, called, err)
	}
	if _, err = handle.digest(); workercontract.Reason(err) != "capability_destroyed" {
		t.Fatalf("destroyed err=%v", err)
	}
	if len(audit.decisions) != 4 { // enrollment, issuance, pre-dispatch, completion
		t.Fatalf("audit decisions=%d", len(audit.decisions))
	}
}

func TestDispatchDenialsConsumeCapability(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*workercontract.DispatchRequest, *workercontract.LeaseAuthority)
		reason string
	}{
		{"scope", func(request *workercontract.DispatchRequest, _ *workercontract.LeaseAuthority) {
			request.Scope.Operation = "other"
		}, "lease_scope_mismatch"},
		{"task canceled", func(_ *workercontract.DispatchRequest, authority *workercontract.LeaseAuthority) {
			authority.TaskActive = false
		}, "lease_authority_denied"},
		{"emergency stop", func(_ *workercontract.DispatchRequest, authority *workercontract.LeaseAuthority) {
			authority.EmergencyStopActive = true
		}, "lease_authority_denied"},
		{"certificate rotated", func(_ *workercontract.DispatchRequest, authority *workercontract.LeaseAuthority) {
			authority.Transport.CertificateRevision++
		}, "worker_transport_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broker, _, _, clock := setupBroker(t)
			record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
			leaseRequest, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
			handle, _, err := broker.Issue(context.Background(), leaseRequest, authority)
			if err != nil {
				t.Fatal(err)
			}
			dispatch := dispatchFixture(handle.LeaseID, leaseRequest.Scope)
			test.mutate(&dispatch, &authority)
			called := false
			_, err = broker.Use(context.Background(), handle, dispatch, authority,
				func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil })
			if workercontract.Reason(err) != test.reason || called {
				t.Fatalf("reason=%q called=%v err=%v", workercontract.Reason(err), called, err)
			}
			if _, err = handle.digest(); workercontract.Reason(err) != "capability_destroyed" {
				t.Fatalf("not destroyed err=%v", err)
			}
		})
	}
}

func TestConcurrentClaimOnlyOneCallback(t *testing.T) {
	broker, _, _, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	handle, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := dispatchFixture(handle.LeaseID, request.Scope)
	var callbacks atomic.Int32
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			_, _ = broker.Use(context.Background(), handle, dispatch, authority,
				func(context.Context, workercontract.DispatchEnvelope) error { callbacks.Add(1); return nil })
		}()
	}
	wait.Wait()
	if callbacks.Load() != 1 {
		t.Fatalf("callbacks=%d", callbacks.Load())
	}
}

func TestWorkerRevocationInvalidatesLease(t *testing.T) {
	broker, _, _, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	handle, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = broker.Revoke(context.Background(), revocationFixture("worker", record.Scope, workerID, "", "operator_revoked"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = broker.Use(context.Background(), handle,
		dispatchFixture(handle.LeaseID, request.Scope), authority,
		func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil })
	if workercontract.Reason(err) != "lease_revoked" || called {
		t.Fatalf("called=%v err=%v", called, err)
	}
}

func TestLeaseCapabilityAndAuditFailures(t *testing.T) {
	broker, _, audit, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	request.Scope.Resources.MemoryBytes = record.Attestation.Resources.MemoryBytes + 1
	if _, _, err := broker.Issue(context.Background(), request, authority); workercontract.Reason(err) != "lease_authority_mismatch" {
		// Authority must match request before the capacity check.
		t.Fatalf("mismatch err=%v", err)
	}
	request, authority = leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	authority.Scope.Resources.MemoryBytes = record.Attestation.Resources.MemoryBytes + 1
	request.Scope.Resources = authority.Scope.Resources
	if _, _, err := broker.Issue(context.Background(), request, authority); workercontract.Reason(err) != "worker_capacity_exceeded" {
		t.Fatalf("capacity err=%v", err)
	}
	request, authority = leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	capabilityTests := []struct {
		name   string
		mutate func(*workercontract.LeaseRequest, *workercontract.LeaseAuthority)
		reason string
	}{
		{"isolation", func(request *workercontract.LeaseRequest, authority *workercontract.LeaseAuthority) {
			request.Scope.IsolationClass, authority.Scope.IsolationClass = "native_restricted", "native_restricted"
		}, "worker_isolation_mismatch"},
		{"tier", func(request *workercontract.LeaseRequest, authority *workercontract.LeaseAuthority) {
			request.Scope.RequiredTier, authority.Scope.RequiredTier = "T3", "T3"
			authority.Worker.Attestation.MaximumActionTier = "T2"
		}, "worker_isolation_mismatch"},
		{"registry", func(request *workercontract.LeaseRequest, authority *workercontract.LeaseAuthority) {
			request.Scope.ToolRegistryDigest, authority.Scope.ToolRegistryDigest = digest("old-registry"), digest("old-registry")
		}, "worker_isolation_mismatch"},
		{"network", func(request *workercontract.LeaseRequest, authority *workercontract.LeaseAuthority) {
			request.Scope.NetworkMode, authority.Scope.NetworkMode = "brokered_egress", "brokered_egress"
			authority.Worker.Attestation.NetworkModes = []string{"none"}
		}, "worker_capacity_exceeded"},
	}
	for _, test := range capabilityTests {
		t.Run(test.name, func(t *testing.T) {
			changedRequest, changedAuthority := request, authority
			test.mutate(&changedRequest, &changedAuthority)
			if _, _, err := broker.Issue(context.Background(), changedRequest, changedAuthority); workercontract.Reason(err) != test.reason {
				t.Fatalf("reason=%q err=%v", workercontract.Reason(err), err)
			}
		})
	}
	request, authority = leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	audit.fail = true
	handle, _, err := broker.Issue(context.Background(), request, authority)
	if workercontract.Reason(err) != "audit_unavailable" || handle != nil {
		t.Fatalf("handle=%v err=%v", handle, err)
	}
}

func TestLeaseEntropyAndStoreFailure(t *testing.T) {
	baseBroker, memory, audit, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, baseBroker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	entropyBroker, err := NewWithDependencies(memory, audit, clock, errorReader{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if handle, _, issueErr := entropyBroker.Issue(context.Background(), request, authority); handle != nil ||
		workercontract.Reason(issueErr) != "entropy_unavailable" {
		t.Fatalf("entropy handle=%v err=%v", handle, issueErr)
	}
	store := &failingStore{MemoryStore: memory, failLeaseCreate: true}
	storeBroker, err := NewWithDependencies(store, audit, clock, &repeatReader{value: 33}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "store-failure"
	request.RequestID = "018f47a6-4b2c-7a1e-8a12-123456789ac2"
	if handle, _, issueErr := storeBroker.Issue(context.Background(), request, authority); handle != nil ||
		workercontract.Reason(issueErr) != "worker_store_unavailable" {
		t.Fatalf("store handle=%v err=%v", handle, issueErr)
	}
}
