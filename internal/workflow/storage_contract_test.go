package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	testOrg     = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	testTenant  = "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16"
	testCase    = "0198d6c4-7618-7d31-8e0a-9da53cae8ca2"
	testMessage = "0198d6c4-1111-7111-8111-111111111111"
	testLease   = "0198d6c4-2222-7222-8222-222222222222"
)

type storageDriverStub struct {
	get       func(context.Context, RecordKey) (MetadataRecord, error)
	transact  func(context.Context, Transaction) (CommitResult, error)
	claim     func(context.Context, OutboxClaim) ([]OutboxDelivery, error)
	settle    func(context.Context, OutboxSettlement) error
	status    func(context.Context, string) (MigrationResult, error)
	migrate   func(context.Context, MigrationPlan) (MigrationResult, error)
	callCount int
}

func (stub *storageDriverStub) Get(ctx context.Context, key RecordKey) (MetadataRecord, error) {
	stub.callCount++
	return stub.get(ctx, key)
}

func (stub *storageDriverStub) Transact(ctx context.Context, transaction Transaction) (CommitResult, error) {
	stub.callCount++
	return stub.transact(ctx, transaction)
}

func (stub *storageDriverStub) ClaimOutbox(ctx context.Context, claim OutboxClaim) ([]OutboxDelivery, error) {
	stub.callCount++
	return stub.claim(ctx, claim)
}

func (stub *storageDriverStub) SettleOutbox(ctx context.Context, settlement OutboxSettlement) error {
	stub.callCount++
	return stub.settle(ctx, settlement)
}

func (stub *storageDriverStub) MigrationStatus(ctx context.Context, component string) (MigrationResult, error) {
	stub.callCount++
	return stub.status(ctx, component)
}

func (stub *storageDriverStub) Migrate(ctx context.Context, plan MigrationPlan) (MigrationResult, error) {
	stub.callCount++
	return stub.migrate(ctx, plan)
}

func TestGuardStorageRejectsMissingDriver(t *testing.T) {
	if _, err := GuardStorage(nil); StorageCode(err) != StorageInvalidInput {
		t.Fatalf("GuardStorage error code = %q, want %q", StorageCode(err), StorageInvalidInput)
	}
	var typedNil *storageDriverStub
	if _, err := GuardStorage(typedNil); StorageCode(err) != StorageInvalidInput {
		t.Fatalf("typed-nil driver error code = %q, want %q", StorageCode(err), StorageInvalidInput)
	}
}

func TestGuardedStorageTransactionAndReplay(t *testing.T) {
	transaction := validTransaction(t)
	original := append([]byte(nil), transaction.Mutations[0].Record.Canonical...)
	calls := 0
	driver := validDriver(t)
	driver.transact = func(_ context.Context, received Transaction) (CommitResult, error) {
		calls++
		received.Mutations[0].Record.Canonical[0] = 'X'
		return validCommit(transaction, calls > 1), nil
	}
	store := mustGuard(t, driver)

	first, err := store.Transact(context.Background(), transaction)
	if err != nil || first.Replayed {
		t.Fatalf("first transact result=%+v err=%v", first, err)
	}
	second, err := store.Transact(context.Background(), transaction)
	if err != nil || !second.Replayed {
		t.Fatalf("replayed transact result=%+v err=%v", second, err)
	}
	if string(transaction.Mutations[0].Record.Canonical) != string(original) {
		t.Fatal("driver mutated caller-owned canonical bytes")
	}
	first.RecordVersions["tamper"] = 99
	third, err := store.Transact(context.Background(), transaction)
	if err != nil || third.RecordVersions["tamper"] != 0 {
		t.Fatal("commit result aliases driver or earlier caller state")
	}
}

func TestGuardedStorageRejectsInvalidAndDriverFailure(t *testing.T) {
	driver := validDriver(t)
	store := mustGuard(t, driver)
	transaction := validTransaction(t)
	transaction.ContractVersion = "coh.storage/v2"
	if _, err := store.Transact(context.Background(), transaction); StorageCode(err) != StorageInvalidInput || driver.callCount != 0 {
		t.Fatalf("invalid transaction code=%q calls=%d", StorageCode(err), driver.callCount)
	}

	secret := "postgres://operator:secret@example.invalid"
	driver.transact = func(context.Context, Transaction) (CommitResult, error) {
		return CommitResult{}, errors.New(secret)
	}
	transaction = validTransaction(t)
	_, err := store.Transact(context.Background(), transaction)
	if StorageCode(err) != StorageUnavailable || strings.Contains(err.Error(), secret) || errors.Unwrap(err) != nil {
		t.Fatalf("driver failure was not safely normalized: %v", err)
	}

	driver.transact = func(context.Context, Transaction) (CommitResult, error) {
		return CommitResult{}, NewStorageError(StorageConflict, "transact", "revision", "optimistic concurrency check failed", nil)
	}
	if _, err := store.Transact(context.Background(), transaction); StorageCode(err) != StorageConflict {
		t.Fatalf("conflict code = %q", StorageCode(err))
	}
}

func TestGuardedStorageCancellationTimeoutAndRecovery(t *testing.T) {
	driver := validDriver(t)
	store := mustGuard(t, driver)
	transaction := validTransaction(t)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Transact(canceled, transaction); StorageCode(err) != StorageCanceled || driver.callCount != 0 {
		t.Fatalf("canceled code=%q calls=%d", StorageCode(err), driver.callCount)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := store.Transact(expired, transaction); StorageCode(err) != StorageTimeout || driver.callCount != 0 {
		t.Fatalf("timeout code=%q calls=%d", StorageCode(err), driver.callCount)
	}
	if result, err := store.Transact(context.Background(), transaction); err != nil || result.IdempotencyKey != transaction.IdempotencyKey {
		t.Fatalf("recovery result=%+v err=%v", result, err)
	}
}

func TestGuardedStorageReadAndOutboxBoundaries(t *testing.T) {
	driver := validDriver(t)
	store := mustGuard(t, driver)
	record := validRecord(t)
	got, err := store.Get(context.Background(), record.Key)
	if err != nil || got.Digest != record.Digest {
		t.Fatalf("Get result=%+v err=%v", got, err)
	}
	got.Canonical[0] = 'X'
	again, err := store.Get(context.Background(), record.Key)
	if err != nil || again.Canonical[0] == 'X' {
		t.Fatal("Get returned aliased canonical bytes")
	}

	claim := validClaim()
	deliveries, err := store.ClaimOutbox(context.Background(), claim)
	if err != nil || len(deliveries) != 1 || deliveries[0].LeaseID != testLease {
		t.Fatalf("ClaimOutbox result=%+v err=%v", deliveries, err)
	}
	settlement := OutboxSettlement{OrganizationID: testOrg, TenantID: testTenant, MessageID: testMessage, LeaseID: testLease, Outcome: OutboxDelivered, EvidenceDigest: digestOf("evidence")}
	if err := store.SettleOutbox(context.Background(), settlement); err != nil {
		t.Fatalf("SettleOutbox error: %v", err)
	}

	driver.claim = func(context.Context, OutboxClaim) ([]OutboxDelivery, error) {
		message := validTransaction(t).Outbox[0]
		message.Case.TenantID = "0198d6c4-3333-7333-8333-333333333333"
		return []OutboxDelivery{{Message: message, LeaseID: testLease}}, nil
	}
	if _, err := store.ClaimOutbox(context.Background(), claim); StorageCode(err) != StorageDenied {
		t.Fatalf("cross-scope claim code = %q", StorageCode(err))
	}
}

func TestGuardedStorageMigrationApplyRollbackAndStatus(t *testing.T) {
	driver := validDriver(t)
	store := mustGuard(t, driver)
	plan := validMigrationPlan(MigrationApply)
	result, err := store.Migrate(context.Background(), plan)
	if err != nil || result.State != MigrationApplied {
		t.Fatalf("apply result=%+v err=%v", result, err)
	}
	status, err := store.MigrationStatus(context.Background(), plan.Component)
	if err != nil || status.State != MigrationApplied {
		t.Fatalf("status result=%+v err=%v", status, err)
	}

	plan.Direction = MigrationRollback
	driver.migrate = func(_ context.Context, received MigrationPlan) (MigrationResult, error) {
		return migrationResult(received, MigrationRolledBack, false), nil
	}
	if result, err = store.Migrate(context.Background(), plan); err != nil || result.State != MigrationRolledBack {
		t.Fatalf("rollback result=%+v err=%v", result, err)
	}

	plan.Checksum = digestOf("tampered")
	driver.migrate = func(_ context.Context, received MigrationPlan) (MigrationResult, error) {
		result := migrationResult(received, MigrationApplied, false)
		result.Checksum = digestOf("different")
		return result, nil
	}
	if _, err := store.Migrate(context.Background(), plan); StorageCode(err) != StorageDenied {
		t.Fatalf("mismatched migration result code = %q", StorageCode(err))
	}
}

func TestRecordAndTransactionDenials(t *testing.T) {
	record := validRecord(t)
	record.Digest = digestOf("wrong")
	if err := ValidateMetadataRecord(record); StorageCode(err) != StorageDenied {
		t.Fatalf("record digest code = %q", StorageCode(err))
	}
	record = validRecord(t)
	record.Key.Case.TenantID = "0198d6c4-3333-7333-8333-333333333333"
	if err := ValidateMetadataRecord(record); StorageCode(err) != StorageDenied {
		t.Fatalf("record envelope code = %q", StorageCode(err))
	}
	transaction := validTransaction(t)
	transaction.Mutations = append(transaction.Mutations, transaction.Mutations[0])
	if err := ValidateTransaction(transaction); StorageCode(err) != StorageInvalidInput {
		t.Fatalf("duplicate mutation code = %q", StorageCode(err))
	}
	transaction = validTransaction(t)
	transaction.Outbox[0].Case.TenantID = "0198d6c4-3333-7333-8333-333333333333"
	if err := ValidateTransaction(transaction); StorageCode(err) != StorageDenied {
		t.Fatalf("cross-tenant transaction code = %q", StorageCode(err))
	}
	settlement := OutboxSettlement{MessageID: testMessage, LeaseID: testLease, Outcome: OutboxDelivered}
	if err := ValidateOutboxSettlement(settlement); StorageCode(err) != StorageInvalidInput {
		t.Fatalf("unscoped settlement code = %q", StorageCode(err))
	}
}

func validDriver(t *testing.T) *storageDriverStub {
	t.Helper()
	record := validRecord(t)
	transaction := validTransaction(t)
	plan := validMigrationPlan(MigrationApply)
	return &storageDriverStub{
		get:      func(context.Context, RecordKey) (MetadataRecord, error) { return cloneRecord(record), nil },
		transact: func(context.Context, Transaction) (CommitResult, error) { return validCommit(transaction, false), nil },
		claim: func(context.Context, OutboxClaim) ([]OutboxDelivery, error) {
			return []OutboxDelivery{{Message: transaction.Outbox[0], LeaseID: testLease}}, nil
		},
		settle: func(context.Context, OutboxSettlement) error { return nil },
		status: func(context.Context, string) (MigrationResult, error) {
			return migrationResult(plan, MigrationApplied, false), nil
		},
		migrate: func(_ context.Context, received MigrationPlan) (MigrationResult, error) {
			return migrationResult(received, MigrationApplied, false), nil
		},
	}
}

func mustGuard(t *testing.T, driver StorageDriver) Repository {
	t.Helper()
	store, err := GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func validRecord(t *testing.T) MetadataRecord {
	t.Helper()
	encoded := []byte(`{"schema":"coh.domain/v1","kind":"case","id":"` + testCase + `","organization_id":"` + testOrg + `","tenant_id":"` + testTenant + `","case_id":"` + testCase + `","revision":1,"created_at":"2026-08-25T18:00:00.000000000Z","data":{}}`)
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return MetadataRecord{
		Key:    RecordKey{Case: domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}, Kind: "case", ID: testCase},
		Schema: "coh.domain/v1", Revision: 1, Canonical: canonical, Digest: digestBytes(canonical),
	}
}

func validTransaction(t *testing.T) Transaction {
	t.Helper()
	record := validRecord(t)
	return Transaction{
		ContractVersion: StorageContractVersion,
		IdempotencyKey:  "case-create-1",
		Mutations:       []Mutation{{Kind: MutationPut, Key: record.Key, ExpectedRevision: 0, Record: &record}},
		Outbox: []OutboxMessage{{
			ID: testMessage, Case: record.Key.Case, Topic: "case.created",
			PayloadRef: "record:" + testCase + ":1", PayloadDigest: record.Digest,
		}},
	}
}

func validCommit(transaction Transaction, replayed bool) CommitResult {
	versions := map[string]uint64{recordKeyString(transaction.Mutations[0].Key): 1}
	return CommitResult{IdempotencyKey: transaction.IdempotencyKey, CommitSequence: 1, Replayed: replayed, RecordVersions: versions, OutboxIDs: []string{testMessage}}
}

func validClaim() OutboxClaim {
	return OutboxClaim{OrganizationID: testOrg, TenantID: testTenant, WorkerID: "worker-1", Limit: 16, LeaseUntil: time.Date(2026, 8, 25, 19, 0, 0, 0, time.UTC)}
}

func validMigrationPlan(direction MigrationDirection) MigrationPlan {
	return MigrationPlan{ContractVersion: StorageContractVersion, Component: "metadata", Version: 1, Checksum: digestOf("migration-v1"), BackupDigest: digestOf("backup-v0"), Direction: direction}
}

func migrationResult(plan MigrationPlan, state MigrationState, replayed bool) MigrationResult {
	return MigrationResult{Component: plan.Component, Version: plan.Version, Checksum: plan.Checksum, State: state, ResumeDigest: digestOf("checkpoint"), Replayed: replayed}
}

func digestOf(value string) string { return digestBytes([]byte(value)) }

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
