package credentiallease

import (
	"context"
	"errors"
	"testing"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
)

func TestRevokeImmediatelyBlocksDispatchAndRecordsProof(t *testing.T) {
	fixture := newDispatchFixture(t)
	decision, err := fixture.broker.Revoke(context.Background(), leasecontract.RevocationRequest{
		LeaseID: fixture.handle.LeaseID, Reason: "operator_revoked",
	})
	if err != nil || decision.Event != "lease_revocation" || decision.Outcome != "allowed" || decision.ReasonCode != "operator_revoked" {
		t.Fatalf("decision = %+v, err = %v", decision, err)
	}
	request, authority := fixture.dispatchInput()
	called := false
	dispatchDecision, dispatchErr := fixture.broker.Dispatch(context.Background(), fixture.handle, request, authority, func([]byte) error {
		called = true
		return nil
	})
	if leasecontract.Code(dispatchErr) != leasecontract.Denied || reason(dispatchErr) != "lease_revoked" || dispatchDecision.Outcome != "denied" || called {
		t.Fatalf("dispatch decision = %+v, called = %t, err = %v", dispatchDecision, called, dispatchErr)
	}
	if len(fixture.leaseAudit.decisions) != 3 || fixture.leaseAudit.decisions[1].Event != "lease_revocation" {
		t.Fatalf("audit = %+v", fixture.leaseAudit.decisions)
	}
}

func TestRevocationAuditFailureCannotRestoreLease(t *testing.T) {
	fixture := newDispatchFixture(t)
	fixture.leaseAudit.err = errors.New("private audit failure")
	decision, err := fixture.broker.Revoke(context.Background(), leasecontract.RevocationRequest{
		LeaseID: fixture.handle.LeaseID, Reason: "emergency_stop",
	})
	if leasecontract.Code(err) != leasecontract.Unavailable || reason(err) != "audit_unavailable" || decision.ReasonCode != "audit_unavailable" {
		t.Fatalf("decision = %+v, err = %v", decision, err)
	}
	fixture.leaseAudit.err = nil
	request, authority := fixture.dispatchInput()
	_, dispatchErr := fixture.broker.Dispatch(context.Background(), fixture.handle, request, authority, func([]byte) error { return nil })
	if leasecontract.Code(dispatchErr) != leasecontract.Denied || reason(dispatchErr) != "lease_revoked" {
		t.Fatalf("dispatch err = %v", dispatchErr)
	}
}

func TestRevokeRejectsInvalidReasonWithoutChangingLease(t *testing.T) {
	fixture := newDispatchFixture(t)
	decision, err := fixture.broker.Revoke(context.Background(), leasecontract.RevocationRequest{
		LeaseID: fixture.handle.LeaseID, Reason: "freeform private reason",
	})
	if leasecontract.Code(err) != leasecontract.InvalidInput || decision.Outcome != "invalid" || fixture.store.records[fixture.handle.LeaseID].Revoked {
		t.Fatalf("decision = %+v, record = %+v, err = %v", decision, fixture.store.records[fixture.handle.LeaseID], err)
	}
}
