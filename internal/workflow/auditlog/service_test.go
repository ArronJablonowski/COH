package auditlog

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type memoryStore struct {
	mu          sync.Mutex
	head        tamperaudit.Head
	records     []tamperaudit.Record
	checkpoints []tamperaudit.Checkpoint
	idempotency map[string]memoryReplay
}

type memoryReplay struct {
	digest string
	result AppendResult
}

func newMemoryStore() *memoryStore { return &memoryStore{idempotency: map[string]memoryReplay{}} }

func (store *memoryStore) LoadHead(_ context.Context, _, _ string) (tamperaudit.Head, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.head, nil
}

func (store *memoryStore) CommitAudit(_ context.Context, commit Commit) (AppendResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if replay, exists := store.idempotency[commit.IdempotencyKey]; exists {
		if replay.digest != commit.RequestDigest {
			return AppendResult{}, ErrConflict
		}
		replay.result.Replayed = true
		return replay.result, nil
	}
	expectedSequence, expectedHash := store.head.Sequence, store.head.ChainHash
	if expectedSequence == 0 && expectedHash == "" {
		expectedHash = tamperaudit.GenesisHash
	}
	if commit.ExpectedHead.Sequence != expectedSequence || commit.ExpectedHead.ChainHash != expectedHash ||
		tamperaudit.VerifyRecord(commit.Record, expectedSequence+1, expectedHash) != nil {
		return AppendResult{}, ErrConflict
	}
	result := AppendResult{Sequence: commit.Record.Sequence, ChainHash: commit.Record.ChainHash}
	if commit.Checkpoint != nil {
		result.CheckpointID = commit.Checkpoint.CheckpointID
		store.checkpoints = append(store.checkpoints, *commit.Checkpoint)
	}
	store.records = append(store.records, commit.Record)
	store.head = tamperaudit.Head{OrganizationID: commit.Record.OrganizationID, TenantID: commit.Record.TenantID,
		Sequence: commit.Record.Sequence, ChainHash: commit.Record.ChainHash, LastRecordAt: commit.Record.AppendedAt,
		LastCheckpointSequence: commit.ExpectedHead.LastCheckpointSequence,
		LastCheckpointAt:       commit.ExpectedHead.LastCheckpointAt}
	if commit.Checkpoint != nil {
		store.head.LastCheckpointSequence = commit.Checkpoint.Sequence
		store.head.LastCheckpointAt = commit.Checkpoint.CreatedAt
	}
	store.idempotency[commit.IdempotencyKey] = memoryReplay{digest: commit.RequestDigest, result: result}
	return result, nil
}

func (store *memoryStore) ReadAuditRecords(_ context.Context, _, _ string, after uint64, limit uint16) ([]tamperaudit.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]tamperaudit.Record, 0, limit)
	for _, record := range store.records {
		if record.Sequence > after && len(result) < int(limit) {
			result = append(result, record)
		}
	}
	return result, nil
}

func (store *memoryStore) ReadAuditCheckpoints(_ context.Context, _, _ string) ([]tamperaudit.Checkpoint, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]tamperaudit.Checkpoint(nil), store.checkpoints...), nil
}

type testAuthority struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	fail    bool
}

func newTestAuthority() *testAuthority {
	seed := sha256.Sum256([]byte("COH-CYB-49-WORKFLOW-TEST-KEY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return &testAuthority{private: privateKey, public: privateKey.Public().(ed25519.PublicKey)}
}

func (authority *testAuthority) SignAuditCheckpoint(_ context.Context, checkpoint tamperaudit.Checkpoint) (tamperaudit.Checkpoint, error) {
	if authority.fail {
		return tamperaudit.Checkpoint{}, ErrUnavailable
	}
	checkpoint.SigningKeyID = "audit-primary"
	checkpoint.SigningKeyRevision = 1
	checkpoint.SignatureAlgorithm = tamperaudit.SignatureAlgorithm
	return tamperaudit.SignCheckpoint(checkpoint, authority.private)
}

func (authority *testAuthority) ResolveAuditKey(_ context.Context, keyID string, revision uint64) (KeyAuthority, error) {
	if authority.fail || keyID != "audit-primary" || revision != 1 {
		return KeyAuthority{}, ErrUnavailable
	}
	return KeyAuthority{KeyID: keyID, Revision: revision, PublicKey: authority.public,
		ValidFrom:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

type testIDs struct {
	mu   sync.Mutex
	next uint64
}

func (ids *testIDs) NewAuditID(_ time.Time) (string, error) {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	ids.next++
	return fmt.Sprintf("0198d6c4-aaaa-7aaa-8aaa-%012x", ids.next), nil
}

func TestAppendReplaysAndDailyCheckpoint(t *testing.T) {
	store := newMemoryStore()
	authority := newTestAuthority()
	clock := &testClock{now: time.Date(2026, 8, 26, 1, 0, 0, 0, time.UTC)}
	service, _ := New(store, authority, authority, clock, &testIDs{})
	first := testEvent("0198d6c4-0001-7001-8001-000000000001", formatTime(clock.now))
	result, err := service.Append(context.Background(), first)
	if err != nil || result.Sequence != 1 || result.CheckpointID != "" {
		t.Fatalf("first append = %+v err=%v", result, err)
	}
	clock.now = clock.now.Add(24 * time.Hour)
	second := testEvent("0198d6c4-0002-7002-8002-000000000002", formatTime(clock.now))
	result, err = service.Append(context.Background(), second)
	if err != nil || result.Sequence != 2 || result.CheckpointID == "" || len(store.checkpoints) != 1 ||
		store.checkpoints[0].Sequence != 1 || store.checkpoints[0].Reason != "daily" {
		t.Fatalf("rollover append = %+v checkpoints=%+v err=%v", result, store.checkpoints, err)
	}
	replayed, err := service.Append(context.Background(), first)
	if err != nil || !replayed.Replayed || replayed.Sequence != 1 {
		t.Fatalf("replay = %+v err=%v", replayed, err)
	}
}

func TestCheckpointFailureBlocksAppend(t *testing.T) {
	store := newMemoryStore()
	authority := newTestAuthority()
	clock := &testClock{now: time.Date(2026, 8, 26, 23, 59, 0, 0, time.UTC)}
	service, _ := New(store, authority, authority, clock, &testIDs{})
	_, _ = service.Append(context.Background(), testEvent("0198d6c4-0001-7001-8001-000000000001", formatTime(clock.now)))
	clock.now = clock.now.Add(2 * time.Minute)
	authority.fail = true
	if _, err := service.Append(context.Background(), testEvent("0198d6c4-0002-7002-8002-000000000002", formatTime(clock.now))); err != ErrUnavailable {
		t.Fatalf("checkpoint failure err=%v", err)
	}
	if len(store.records) != 1 {
		t.Fatal("event committed without required checkpoint")
	}
}

func TestVerifyDetectsMutationAndMissingDailyCheckpoint(t *testing.T) {
	store := newMemoryStore()
	authority := newTestAuthority()
	clock := &testClock{now: time.Date(2026, 8, 26, 23, 59, 0, 0, time.UTC)}
	service, _ := New(store, authority, authority, clock, &testIDs{})
	_, _ = service.Append(context.Background(), testEvent("0198d6c4-0001-7001-8001-000000000001", formatTime(clock.now)))
	clock.now = clock.now.Add(2 * time.Minute)
	_, _ = service.Append(context.Background(), testEvent("0198d6c4-0002-7002-8002-000000000002", formatTime(clock.now)))
	report, err := service.Verify(context.Background(), "0198d6c4-1111-7111-8111-111111111111", "0198d6c4-2222-7222-8222-222222222222")
	if err != nil || report.RecordCount != 2 || report.CheckpointCount != 1 || report.LastCheckpoint != 1 {
		t.Fatalf("verification report=%+v err=%v", report, err)
	}
	store.mu.Lock()
	store.records[0].Event.Outcome = "denied"
	store.mu.Unlock()
	if _, err := service.Verify(context.Background(), report.OrganizationID, report.TenantID); err != ErrIntegrity {
		t.Fatalf("mutated verification err=%v", err)
	}
	store.mu.Lock()
	store.records[0].Event.Outcome = "allowed"
	store.checkpoints = nil
	store.head.LastCheckpointSequence = 0
	store.head.LastCheckpointAt = ""
	store.mu.Unlock()
	if _, err := service.Verify(context.Background(), report.OrganizationID, report.TenantID); err != ErrIntegrity {
		t.Fatalf("missing checkpoint verification err=%v", err)
	}
}

func TestConcurrentAppendsSerialize(t *testing.T) {
	store := newMemoryStore()
	authority := newTestAuthority()
	clock := &testClock{now: time.Date(2026, 8, 26, 1, 0, 0, 0, time.UTC)}
	service, _ := New(store, authority, authority, clock, &testIDs{})
	var wait sync.WaitGroup
	errorsFound := make(chan error, 2)
	for index := 1; index <= 2; index++ {
		wait.Add(1)
		go func(value int) {
			defer wait.Done()
			id := fmt.Sprintf("0198d6c4-000%d-700%d-800%d-%012d", value, value, value, value)
			_, err := service.Append(context.Background(), testEvent(id, formatTime(clock.now)))
			errorsFound <- err
		}(index)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(store.records) != 2 || store.records[0].Sequence != 1 || store.records[1].Sequence != 2 {
		t.Fatalf("records=%+v", store.records)
	}
}

func TestOutboxProjectionReturnsSettlementEvidence(t *testing.T) {
	store := newMemoryStore()
	authority := newTestAuthority()
	clock := &testClock{now: time.Date(2026, 8, 26, 1, 0, 0, 0, time.UTC)}
	service, _ := New(store, authority, authority, clock, &testIDs{})
	delivery := workflowbase.OutboxDelivery{LeaseID: "0198d6c4-9999-7999-8999-999999999999",
		Message: workflowbase.OutboxMessage{ID: "0198d6c4-0001-7001-8001-000000000001",
			Case: domain.CaseRef{OrganizationID: "0198d6c4-1111-7111-8111-111111111111",
				TenantID: "0198d6c4-2222-7222-8222-222222222222", CaseID: "0198d6c4-3333-7333-8333-333333333333"},
			Topic: "approval.request", PayloadRef: "record:approval:one:1",
			PayloadDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	result, err := service.AppendOutbox(context.Background(), delivery)
	if err != nil || result.Sequence != 1 || result.ChainHash == "" {
		t.Fatalf("outbox result=%+v err=%v", result, err)
	}
	if store.records[0].Event.SubjectDigest != delivery.Message.PayloadDigest || store.records[0].Event.Operation != delivery.Message.Topic {
		t.Fatalf("projected event=%+v", store.records[0].Event)
	}
}

func TestCheckpointTargetUsesEarlierMandatoryTrigger(t *testing.T) {
	record := tamperaudit.Record{Sequence: tamperaudit.CheckpointRecordLimit,
		ChainHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	head := tamperaudit.Head{Sequence: tamperaudit.CheckpointRecordLimit - 1,
		ChainHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		LastRecordAt: "2026-08-26T01:00:00.000000000Z"}
	sequence, chainHash, reason := checkpointTarget(head, record, time.Date(2026, 8, 26, 2, 0, 0, 0, time.UTC))
	if sequence != tamperaudit.CheckpointRecordLimit || chainHash != record.ChainHash || reason != "record_limit" {
		t.Fatalf("record trigger = %d %s %s", sequence, chainHash, reason)
	}
	sequence, chainHash, reason = checkpointTarget(head, record, time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC))
	if sequence != head.Sequence || chainHash != head.ChainHash || reason != "daily" {
		t.Fatalf("earlier daily trigger = %d %s %s", sequence, chainHash, reason)
	}
}

func testEvent(id, occurredAt string) tamperaudit.Event {
	return tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: id, OrganizationID: "0198d6c4-1111-7111-8111-111111111111",
		TenantID: "0198d6c4-2222-7222-8222-222222222222", CaseID: "0198d6c4-3333-7333-8333-333333333333",
		ActorID: "0198d6c4-4444-7444-8444-444444444444", ActorRevision: 1,
		SourceSchema: "coh.approval-lifecycle/v2", Operation: "grant", Outcome: "allowed",
		ReasonCode: "approval_granted", EvidenceDigests: []string{}, OccurredAt: occurredAt}
}
