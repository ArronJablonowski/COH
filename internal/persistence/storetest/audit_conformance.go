package storetest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
)

const (
	auditOrganization = "0198d6c4-a111-7a11-8a11-111111111111"
	auditTenant       = "0198d6c4-a222-7a22-8a22-222222222222"
	auditDayOne       = "2026-08-26T23:59:00.000000000Z"
	auditDayTwo       = "2026-08-27T00:01:00.000000000Z"
)

func RunAuditConformance(t *testing.T, store auditlog.Store) {
	t.Helper()
	ctx := context.Background()
	first := auditEvent("0198d6c4-a333-7a33-8a33-333333333333", auditDayOne)
	firstRecord, _ := tamperaudit.BuildRecord(first, 1, tamperaudit.GenesisHash, auditDayOne)
	firstCommit := auditlog.Commit{IdempotencyKey: first.EventID, RequestDigest: firstRecord.EventDigest,
		ExpectedHead: tamperaudit.Head{ChainHash: tamperaudit.GenesisHash}, Record: firstRecord}
	firstResult, err := store.CommitAudit(ctx, firstCommit)
	if err != nil || firstResult.Sequence != 1 || firstResult.Replayed {
		t.Fatalf("first audit commit=%+v err=%v", firstResult, err)
	}
	head, err := store.LoadHead(ctx, auditOrganization, auditTenant)
	if err != nil || head.Sequence != 1 || head.ChainHash != firstRecord.ChainHash {
		t.Fatalf("head=%+v err=%v", head, err)
	}
	replayed, err := store.CommitAudit(ctx, firstCommit)
	if err != nil || !replayed.Replayed || replayed.Sequence != 1 {
		t.Fatalf("audit replay=%+v err=%v", replayed, err)
	}

	second := auditEvent("0198d6c4-a444-7a44-8a44-444444444444", auditDayTwo)
	secondRecord, _ := tamperaudit.BuildRecord(second, 2, firstRecord.ChainHash, auditDayTwo)
	checkpoint := signedAuditCheckpoint(t, firstRecord)
	secondCommit := auditlog.Commit{IdempotencyKey: second.EventID, RequestDigest: secondRecord.EventDigest,
		ExpectedHead: head, Record: secondRecord, Checkpoint: &checkpoint}
	secondResult, err := store.CommitAudit(ctx, secondCommit)
	if err != nil || secondResult.Sequence != 2 || secondResult.CheckpointID != checkpoint.CheckpointID {
		t.Fatalf("second audit commit=%+v err=%v", secondResult, err)
	}
	records, err := store.ReadAuditRecords(ctx, auditOrganization, auditTenant, 0, 10)
	if err != nil || len(records) != 2 || tamperaudit.VerifyRecord(records[1], 2, records[0].ChainHash) != nil {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	checkpoints, err := store.ReadAuditCheckpoints(ctx, auditOrganization, auditTenant)
	if err != nil || len(checkpoints) != 1 || checkpoints[0].CheckpointID != checkpoint.CheckpointID {
		t.Fatalf("checkpoints=%+v err=%v", checkpoints, err)
	}

	staleEvent := auditEvent("0198d6c4-a555-7a55-8a55-555555555555", auditDayOne)
	staleRecord, _ := tamperaudit.BuildRecord(staleEvent, 2, firstRecord.ChainHash, auditDayOne)
	stale := auditlog.Commit{IdempotencyKey: staleEvent.EventID, RequestDigest: staleRecord.EventDigest,
		ExpectedHead: head, Record: staleRecord}
	if _, err := store.CommitAudit(ctx, stale); workflow.StorageCode(err) != workflow.StorageConflict {
		t.Fatalf("stale append err=%v", err)
	}
}

func auditEvent(id, occurredAt string) tamperaudit.Event {
	return tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: id, OrganizationID: auditOrganization, TenantID: auditTenant,
		SourceSchema: "coh.policy-decision/v1", Operation: "evaluate", Outcome: "allowed",
		ReasonCode: "policy_allowed", EvidenceDigests: []string{}, OccurredAt: occurredAt}
}

func signedAuditCheckpoint(t *testing.T, record tamperaudit.Record) tamperaudit.Checkpoint {
	t.Helper()
	seed := sha256.Sum256([]byte("COH-CYB-49-STORE-CONFORMANCE-KEY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	checkpoint, err := tamperaudit.SignCheckpoint(tamperaudit.Checkpoint{
		SchemaVersion: tamperaudit.CheckpointSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		CheckpointID: "0198d6c4-a666-7a66-8a66-666666666666", OrganizationID: auditOrganization, TenantID: auditTenant,
		CoveredFromSequence: 1, Sequence: 1, RecordCount: 1, ChainHash: record.ChainHash,
		Reason: "daily", SigningKeyID: "audit-primary", SigningKeyRevision: 1,
		SignatureAlgorithm: tamperaudit.SignatureAlgorithm, CreatedAt: auditDayTwo,
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}
