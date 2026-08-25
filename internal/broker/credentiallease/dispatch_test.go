package credentiallease

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/broker/secretresolver"
	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *mutableClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *mutableClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type secretAuditStub struct {
	mu        sync.Mutex
	decisions []secretref.Decision
	err       error
}

func (audit *secretAuditStub) AppendSecretDecision(_ context.Context, decision secretref.Decision) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.decisions = append(audit.decisions, decision)
	return audit.err
}

type dispatchFixture struct {
	broker      *Broker
	store       *MemoryStore
	leaseAudit  *auditStub
	secretAudit *secretAuditStub
	backend     *secretresolver.SealedMemoryBackend
	clock       *mutableClock
	request     leasecontract.IssuanceRequest
	authority   leasecontract.IssuanceAuthority
	handle      *Handle
}

func TestDispatchUsesSecretOnlyAfterAtomicClaimAndAudit(t *testing.T) {
	fixture := newDispatchFixture(t)
	dispatchRequest, dispatchAuthority := fixture.dispatchInput()
	var consumed []byte
	decision, err := fixture.broker.Use(context.Background(), fixture.handle, dispatchRequest, dispatchAuthority, func(value []byte) error {
		consumed = append([]byte(nil), value...)
		return nil
	})
	if err != nil || decision.Outcome != "allowed" || decision.ReasonCode != "dispatch_authorized" || decision.SecretDecisionDigest == "" {
		t.Fatalf("decision = %+v, err = %v", decision, err)
	}
	if string(consumed) != "credential-value" || !fixture.handle.dead || !fixture.store.records[fixture.handle.LeaseID].Consumed {
		t.Fatalf("value = %q, handle dead = %t, record = %+v", consumed, fixture.handle.dead, fixture.store.records[fixture.handle.LeaseID])
	}
	if len(fixture.leaseAudit.decisions) != 2 || len(fixture.secretAudit.decisions) != 1 {
		t.Fatalf("lease audit = %d, secret audit = %d", len(fixture.leaseAudit.decisions), len(fixture.secretAudit.decisions))
	}
	for _, decisionJSON := range []string{mustJSON(t, decision), mustJSON(t, fixture.leaseAudit.decisions[1]), mustJSON(t, fixture.secretAudit.decisions[0])} {
		if bytes.Contains([]byte(decisionJSON), []byte("credential-value")) || bytes.Contains([]byte(decisionJSON), []byte(fixture.request.Reference.EntryID)) {
			t.Fatalf("secret metadata leaked: %s", decisionJSON)
		}
	}
}

func TestDispatchRejectsReplayBeforeResolution(t *testing.T) {
	fixture := newDispatchFixture(t)
	clone := cloneHandle(fixture.handle)
	request, authority := fixture.dispatchInput()
	if _, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	called := false
	decision, err := fixture.broker.Use(context.Background(), clone, request, authority, func([]byte) error {
		called = true
		return nil
	})
	if leasecontract.Code(err) != leasecontract.Conflict || reason(err) != "lease_replayed" || decision.Outcome != "denied" || called {
		t.Fatalf("decision = %+v, called = %t, err = %v", decision, called, err)
	}
	if len(fixture.secretAudit.decisions) != 1 {
		t.Fatalf("secret resolutions = %d", len(fixture.secretAudit.decisions))
	}
}

func TestConcurrentDispatchHasExactlyOneCredentialConsumer(t *testing.T) {
	fixture := newDispatchFixture(t)
	request, authority := fixture.dispatchInput()
	const attempts = 16
	handles := make([]*Handle, attempts)
	for index := range handles {
		handles[index] = cloneHandle(fixture.handle)
	}
	fixture.handle.Destroy()
	var consumers atomic.Int32
	var wait sync.WaitGroup
	wait.Add(attempts)
	for _, handle := range handles {
		go func(candidate *Handle) {
			defer wait.Done()
			_, _ = fixture.broker.Use(context.Background(), candidate, request, authority, func([]byte) error {
				consumers.Add(1)
				return nil
			})
		}(handle)
	}
	wait.Wait()
	if consumers.Load() != 1 || len(fixture.secretAudit.decisions) != 1 || len(fixture.leaseAudit.decisions) != attempts+1 {
		t.Fatalf("consumers = %d, secret decisions = %d, lease decisions = %d", consumers.Load(), len(fixture.secretAudit.decisions), len(fixture.leaseAudit.decisions))
	}
}

func TestDispatchDeniesScopeAndAuthorityChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*leasecontract.DispatchRequest, *leasecontract.DispatchAuthority)
		reason string
	}{
		{"action", func(request *leasecontract.DispatchRequest, _ *leasecontract.DispatchAuthority) {
			request.ActionDigest = digest("f")
		}, "lease_scope_mismatch"},
		{"target", func(request *leasecontract.DispatchRequest, _ *leasecontract.DispatchAuthority) {
			request.TargetDigests = []string{digest("3")}
		}, "lease_scope_mismatch"},
		{"audience", func(request *leasecontract.DispatchRequest, _ *leasecontract.DispatchAuthority) {
			request.Audience.ID = "runner.other"
		}, "audience_scope_mismatch"},
		{"transport-rotation", func(request *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			request.Audience.TransportIdentityDigest = digest("f")
			authority.Audience.TransportIdentityDigest = digest("f")
		}, "transport_identity_rotated"},
		{"actor-revision", func(_ *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			authority.ActorRevision++
		}, "authority_state_stale"},
		{"policy-revision", func(_ *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			authority.PolicyDecisionDigest = digest("f")
		}, "authority_state_stale"},
		{"task-canceled", func(_ *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			authority.TaskActive = false
		}, "task_canceled"},
		{"emergency-stop", func(_ *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			authority.EmergencyStopActive = true
		}, "emergency_stop_active"},
		{"actor-revoked", func(_ *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			authority.Active = false
		}, "actor_revoked"},
		{"audience-revoked", func(_ *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			authority.Audience.Active = false
		}, "audience_revoked"},
		{"certificate-revoked", func(_ *leasecontract.DispatchRequest, authority *leasecontract.DispatchAuthority) {
			authority.Audience.MutualTLS = false
		}, "mutual_tls_required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDispatchFixture(t)
			request, authority := fixture.dispatchInput()
			test.mutate(&request, &authority)
			called := false
			decision, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error {
				called = true
				return nil
			})
			if leasecontract.Code(err) != leasecontract.Denied || reason(err) != test.reason || decision.Outcome != "denied" || called || len(fixture.secretAudit.decisions) != 0 {
				t.Fatalf("decision = %+v, called = %t, secret decisions = %d, err = %v", decision, called, len(fixture.secretAudit.decisions), err)
			}
		})
	}
}

func TestDispatchDeniesExpirationRevocationAndCapabilityTamper(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*dispatchFixture)
		reason string
	}{
		{"expired", func(fixture *dispatchFixture) { fixture.clock.Advance(time.Minute) }, "lease_expired"},
		{"revoked", func(fixture *dispatchFixture) {
			_, _ = fixture.store.Revoke(context.Background(), fixture.handle.LeaseID, "operator_revoked")
		}, "lease_revoked"},
		{"tampered", func(fixture *dispatchFixture) { fixture.handle.token[0] ^= 0xff }, "capability_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDispatchFixture(t)
			test.mutate(fixture)
			request, authority := fixture.dispatchInput()
			called := false
			decision, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { called = true; return nil })
			if (leasecontract.Code(err) != leasecontract.Denied && leasecontract.Code(err) != leasecontract.Conflict) || reason(err) != test.reason || decision.Outcome != "denied" || called || len(fixture.secretAudit.decisions) != 0 {
				t.Fatalf("decision = %+v, called = %t, err = %v", decision, called, err)
			}
		})
	}
}

func TestDispatchDeniesCredentialRotationAndRevocation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*dispatchFixture)
		reason string
	}{
		{"rotation", func(fixture *dispatchFixture) {
			fixture.replaceSecret(t, 8, 2, true, []byte("rotated-value"))
		}, "credential_stale_reference"},
		{"revocation", func(fixture *dispatchFixture) {
			fixture.replaceSecret(t, 7, 2, false, []byte("credential-value"))
		}, "credential_secret_revoked"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDispatchFixture(t)
			test.mutate(fixture)
			request, authority := fixture.dispatchInput()
			called := false
			decision, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { called = true; return nil })
			if leasecontract.Code(err) != leasecontract.Denied || reason(err) != test.reason || decision.Outcome != "denied" || decision.SecretDecisionDigest == "" || called {
				t.Fatalf("decision = %+v, called = %t, err = %v", decision, called, err)
			}
		})
	}
}

func TestDispatchAuditFailureAndCallbackFailureStayFailClosed(t *testing.T) {
	t.Run("lease-audit", func(t *testing.T) {
		fixture := newDispatchFixture(t)
		fixture.leaseAudit.err = errors.New("private lease audit failure")
		request, authority := fixture.dispatchInput()
		called := false
		decision, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { called = true; return nil })
		if leasecontract.Code(err) != leasecontract.Unavailable || reason(err) != "audit_unavailable" || decision.ReasonCode != "audit_unavailable" || called {
			t.Fatalf("decision = %+v, called = %t, err = %v", decision, called, err)
		}
	})
	t.Run("secret-audit", func(t *testing.T) {
		fixture := newDispatchFixture(t)
		fixture.secretAudit.err = errors.New("private secret audit failure")
		request, authority := fixture.dispatchInput()
		called := false
		decision, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { called = true; return nil })
		if leasecontract.Code(err) != leasecontract.Unavailable || reason(err) != "credential_audit_unavailable" || decision.Outcome != "unavailable" || called {
			t.Fatalf("decision = %+v, called = %t, err = %v", decision, called, err)
		}
	})
	t.Run("callback", func(t *testing.T) {
		fixture := newDispatchFixture(t)
		request, authority := fixture.dispatchInput()
		privateErr := errors.New("private connector failure with credential-value")
		_, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { return privateErr })
		if leasecontract.Code(err) != leasecontract.Unavailable || reason(err) != "dispatch_failed" || bytes.Contains([]byte(err.Error()), []byte(privateErr.Error())) {
			t.Fatalf("err = %v", err)
		}
	})
}

type flakyClaimStore struct {
	*MemoryStore
	mu       sync.Mutex
	failNext bool
}

func (store *flakyClaimStore) Claim(ctx context.Context, leaseID string, digest [32]byte, now time.Time) (Record, error) {
	store.mu.Lock()
	if store.failNext {
		store.failNext = false
		store.mu.Unlock()
		return Record{}, errors.New("private store outage")
	}
	store.mu.Unlock()
	return store.MemoryStore.Claim(ctx, leaseID, digest, now)
}

func TestDispatchRecoversAfterPredispatchStoreOutage(t *testing.T) {
	fixture := newDispatchFixture(t)
	flaky := &flakyClaimStore{MemoryStore: fixture.store, failNext: true}
	fixture.broker.store = flaky
	request, authority := fixture.dispatchInput()
	called := false
	decision, err := fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { called = true; return nil })
	if leasecontract.Code(err) != leasecontract.Unavailable || reason(err) != "lease_store_unavailable" || decision.Outcome != "unavailable" || called || fixture.handle.dead {
		t.Fatalf("first decision = %+v, called = %t, dead = %t, err = %v", decision, called, fixture.handle.dead, err)
	}
	decision, err = fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { called = true; return nil })
	if err != nil || decision.Outcome != "allowed" || !called {
		t.Fatalf("retry decision = %+v, called = %t, err = %v", decision, called, err)
	}
}

func TestDispatchCancellationBeforeClaimCanRecover(t *testing.T) {
	fixture := newDispatchFixture(t)
	request, authority := fixture.dispatchInput()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	decision, err := fixture.broker.Use(ctx, fixture.handle, request, authority, func([]byte) error { called = true; return nil })
	if leasecontract.Code(err) != leasecontract.Canceled || decision.Outcome != "canceled" || called || fixture.handle.dead {
		t.Fatalf("canceled decision = %+v, called = %t, dead = %t, err = %v", decision, called, fixture.handle.dead, err)
	}
	decision, err = fixture.broker.Use(context.Background(), fixture.handle, request, authority, func([]byte) error { called = true; return nil })
	if err != nil || decision.Outcome != "allowed" || !called {
		t.Fatalf("retry decision = %+v, called = %t, err = %v", decision, called, err)
	}
}

func newDispatchFixture(t *testing.T) *dispatchFixture {
	t.Helper()
	request, authority := validIssueInput()
	request.Reference.Backend = "sealed-memory"
	request.Reference.EntryID = "broker.private-entry"
	store := NewMemoryStore()
	leaseAudit := &auditStub{}
	secretAudit := &secretAuditStub{}
	entry := secretRecord(request, 7, 1, true, []byte("credential-value"))
	backend, err := secretresolver.NewSealedMemoryBackend([]secretresolver.Record{entry})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	resolver, err := secretresolver.New([]secretresolver.Backend{backend}, secretAudit, secretresolver.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	clock := &mutableClock{now: authority.Audience.ObservedAt.Add(time.Second)}
	broker, err := NewWithDependencies(store, leaseAudit, resolver, clock, bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	return &dispatchFixture{broker: broker, store: store, leaseAudit: leaseAudit, secretAudit: secretAudit, backend: backend, clock: clock, request: request, authority: authority, handle: handle}
}

func (fixture *dispatchFixture) dispatchInput() (leasecontract.DispatchRequest, leasecontract.DispatchAuthority) {
	request := leasecontract.DispatchRequest{Context: fixture.request.Context, TaskID: fixture.request.TaskID,
		ActionDigest: fixture.request.ActionDigest, TargetDigests: append([]string(nil), fixture.request.TargetDigests...),
		Operation: fixture.request.Operation, Audience: fixture.request.Audience}
	authority := leasecontract.DispatchAuthority{IssuanceAuthority: fixture.authority, TaskActive: true}
	authority.Audience.ObservedAt = fixture.clock.Now()
	return request, authority
}

func (fixture *dispatchFixture) replaceSecret(t *testing.T, version, revision uint64, active bool, value []byte) {
	t.Helper()
	if err := fixture.backend.Replace(context.Background(), secretRecord(fixture.request, version, revision, active, value)); err != nil {
		t.Fatal(err)
	}
}

func secretRecord(request leasecontract.IssuanceRequest, version, revision uint64, active bool, value []byte) secretresolver.Record {
	return secretresolver.Record{Backend: request.Reference.Backend, EntryID: request.Reference.EntryID, Version: version,
		Revision: revision, Active: active, OrganizationID: request.Context.OrganizationID, TenantID: request.Context.TenantID,
		CaseIDs: []string{request.Context.CaseID}, CredentialClass: request.CredentialClass, Value: value}
}

func cloneHandle(handle *Handle) *Handle {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return &Handle{LeaseID: handle.LeaseID, token: append([]byte(nil), handle.token...)}
}
