package credentiallease

import (
	"context"
	"testing"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

func TestEmergencyStopControlRevokesOnlyItsCaseAndIsIdempotent(t *testing.T) {
	store := NewMemoryStore()
	targetCase, otherCase := uuid("3"), uuid("7")
	createCredentialLeaseRecord(t, store, "target", targetCase, 1)
	createCredentialLeaseRecord(t, store, "other", otherCase, 2)
	control, err := NewEmergencyStopControl(store)
	if err != nil {
		t.Fatal(err)
	}
	request := stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case", OrganizationID: uuid("1"), TenantID: uuid("2"), CaseID: targetCase}, Epoch: 4}
	first, err := control.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := control.Apply(context.Background(), request)
	if err != nil || second != first || first == "" {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
	if !store.records["target"].Revoked || store.records["target"].RevokeReason != "emergency_stop" || store.records["other"].Revoked {
		t.Fatalf("records=%+v", store.records)
	}
}

func createCredentialLeaseRecord(t *testing.T, store *MemoryStore, leaseID, caseID string, token byte) {
	t.Helper()
	request := leasecontract.IssuanceRequest{IdempotencyKey: leaseID,
		Context: secretref.Context{OrganizationID: uuid("1"), TenantID: uuid("2"), CaseID: caseID, ActorID: uuid("4")}}
	var tokenDigest [32]byte
	tokenDigest[0] = token
	result, err := store.Create(context.Background(), Record{LeaseID: leaseID, tokenDigest: tokenDigest,
		RequestDigest: digest(string(rune('a' + token))), Request: request})
	if err != nil || result != CreateNew {
		t.Fatalf("create result=%q err=%v", result, err)
	}
}
