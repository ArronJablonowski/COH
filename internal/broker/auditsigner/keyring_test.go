package auditsigner

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func TestKeyringSignsResolvesAndDestroys(t *testing.T) {
	seed := sha256.Sum256([]byte("COH-CYB-49-AUDIT-KEYRING-TEST"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	now := time.Date(2026, 8, 26, 1, 0, 0, 0, time.UTC)
	keyring, err := New([]Key{{ID: "audit-primary", Revision: 2, PrivateKey: privateKey,
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	draft := tamperaudit.Checkpoint{SchemaVersion: tamperaudit.CheckpointSchemaVersion,
		ContractVersion: tamperaudit.ContractVersion, CheckpointID: "0198d6c4-1111-7111-8111-111111111111",
		OrganizationID: "0198d6c4-2222-7222-8222-222222222222", TenantID: "0198d6c4-3333-7333-8333-333333333333",
		CoveredFromSequence: 1, Sequence: 1, RecordCount: 1,
		ChainHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Reason:    "daily", CreatedAt: now.Format("2006-01-02T15:04:05.000000000Z")}
	signed, err := keyring.SignAuditCheckpoint(context.Background(), draft)
	if err != nil || signed.SigningKeyRevision != 2 {
		t.Fatalf("signed=%+v err=%v", signed, err)
	}
	authority, err := keyring.ResolveAuditKey(context.Background(), signed.SigningKeyID, signed.SigningKeyRevision)
	if err != nil || tamperaudit.VerifyCheckpoint(signed, authority.PublicKey) != nil {
		t.Fatalf("authority=%+v err=%v", authority, err)
	}
	id, err := keyring.NewAuditID(now)
	if err != nil {
		t.Fatal(err)
	}
	encodedTime, err := tamperaudit.UUIDv7Time(id)
	if err != nil || encodedTime != now.Format("2006-01-02T15:04:05.000000000Z") {
		t.Fatalf("id=%s time=%s err=%v", id, encodedTime, err)
	}
	keyring.Destroy()
	if _, err := keyring.SignAuditCheckpoint(context.Background(), draft); err == nil {
		t.Fatal("destroyed keyring signed")
	}
}

func TestKeyringRejectsRevokedCurrentKey(t *testing.T) {
	seed := sha256.Sum256([]byte("COH-CYB-49-AUDIT-KEYRING-REVOKED"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	now := time.Date(2026, 8, 26, 1, 0, 0, 0, time.UTC)
	revoked := now.Add(-time.Minute)
	keyring, err := New([]Key{{ID: "audit-primary", Revision: 2, PrivateKey: privateKey,
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), RevokedAt: &revoked, Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	draft := tamperaudit.Checkpoint{CreatedAt: now.Format("2006-01-02T15:04:05.000000000Z")}
	if _, err := keyring.SignAuditCheckpoint(context.Background(), draft); err == nil {
		t.Fatal("revoked key signed")
	}
}
