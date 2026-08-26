package remoteworker

import (
	"context"
	"testing"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func TestEmergencyStopControlRevokesOnlyItsCaseAndIsIdempotent(t *testing.T) {
	store := NewMemoryStore()
	createRunnerLeaseRecord(t, store, "target", caseID, 1)
	createRunnerLeaseRecord(t, store, "other", "018f47a6-4b2c-7a1e-8a12-123456789ad0", 2)
	control, err := NewEmergencyStopControl(store)
	if err != nil {
		t.Fatal(err)
	}
	request := stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case", OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}, Epoch: 9}
	first, err := control.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := control.Apply(context.Background(), request)
	if err != nil || first == "" || second != first {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
	if !store.leases["target"].Revoked || store.leases["target"].RevokeReason != "emergency_stop" || store.leases["other"].Revoked {
		t.Fatalf("leases=%+v", store.leases)
	}
}

func createRunnerLeaseRecord(t *testing.T, store *MemoryStore, leaseID, targetCase string, token byte) {
	t.Helper()
	var tokenDigest [32]byte
	tokenDigest[0] = token
	store.leases[leaseID] = LeaseRecord{LeaseID: leaseID, tokenDigest: tokenDigest,
		Request: workercontract.LeaseRequest{Scope: workercontract.LeaseScope{OrganizationID: organizationID,
			TenantID: tenantID, CaseID: targetCase}}}
}
