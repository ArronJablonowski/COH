// Package storetest contains the shared storage-driver conformance suite.
package storetest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	OrganizationID = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	TenantID       = "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16"
	CaseID         = "0198d6c4-7618-7d31-8e0a-9da53cae8ca2"
	MessageID      = "0198d6c4-1111-7111-8111-111111111111"
)

// Factory returns a fresh driver with the fixture migration registered.
type Factory func(*testing.T, Fixture) workflow.StorageDriver

type Fixture struct {
	Create       workflow.Transaction
	Update       workflow.Transaction
	ChangedRetry workflow.Transaction
	Claim        workflow.OutboxClaim
	Settlement   workflow.OutboxSettlement
	Migration    workflow.MigrationPlan
}

// Run proves semantics shared by SQLite and PostgreSQL implementations.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	fixture := NewFixture(t)
	t.Run("transaction-replay-and-read", func(t *testing.T) {
		store := newStore(t, factory, fixture)
		first := transact(t, store, fixture.Create)
		if first.Replayed || first.CommitSequence == 0 {
			t.Fatalf("first commit = %+v", first)
		}
		replayed := transact(t, store, fixture.Create)
		if !replayed.Replayed || replayed.CommitSequence != first.CommitSequence {
			t.Fatalf("replayed commit = %+v, first = %+v", replayed, first)
		}
		record, err := store.Get(context.Background(), fixture.Create.Mutations[0].Key)
		if err != nil || record.Revision != 1 || record.Digest != fixture.Create.Mutations[0].Record.Digest {
			t.Fatalf("stored record = %+v, err = %v", record, err)
		}
	})

	t.Run("idempotency-mismatch-and-optimistic-conflict", func(t *testing.T) {
		store := newStore(t, factory, fixture)
		transact(t, store, fixture.Create)
		if _, err := store.Transact(context.Background(), fixture.ChangedRetry); workflow.StorageCode(err) != workflow.StorageConflict {
			t.Fatalf("changed retry code = %q, err = %v", workflow.StorageCode(err), err)
		}
		stale := fixture.Create
		stale.IdempotencyKey = "stale-create"
		if _, err := store.Transact(context.Background(), stale); workflow.StorageCode(err) != workflow.StorageConflict {
			t.Fatalf("stale write code = %q, err = %v", workflow.StorageCode(err), err)
		}
		updated := transact(t, store, fixture.Update)
		if updated.RecordVersions[keyString(fixture.Update.Mutations[0].Key)] != 2 {
			t.Fatalf("updated commit = %+v", updated)
		}
	})

	t.Run("transactional-outbox-and-idempotent-settlement", func(t *testing.T) {
		store := newStore(t, factory, fixture)
		transact(t, store, fixture.Create)
		deliveries, err := store.ClaimOutbox(context.Background(), fixture.Claim)
		if err != nil || len(deliveries) != 1 || deliveries[0].Message.ID != MessageID {
			t.Fatalf("deliveries = %+v, err = %v", deliveries, err)
		}
		settlement := fixture.Settlement
		settlement.LeaseID = deliveries[0].LeaseID
		if err := store.SettleOutbox(context.Background(), settlement); err != nil {
			t.Fatal(err)
		}
		if err := store.SettleOutbox(context.Background(), settlement); err != nil {
			t.Fatalf("replayed settlement: %v", err)
		}
		deliveries, err = store.ClaimOutbox(context.Background(), fixture.Claim)
		if err != nil || len(deliveries) != 0 {
			t.Fatalf("settled claim = %+v, err = %v", deliveries, err)
		}
	})

	t.Run("cancellation-timeout-and-recovery", func(t *testing.T) {
		store := newStore(t, factory, fixture)
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := store.Transact(canceled, fixture.Create); workflow.StorageCode(err) != workflow.StorageCanceled {
			t.Fatalf("canceled code = %q", workflow.StorageCode(err))
		}
		expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer stop()
		if _, err := store.Transact(expired, fixture.Create); workflow.StorageCode(err) != workflow.StorageTimeout {
			t.Fatalf("timeout code = %q", workflow.StorageCode(err))
		}
		transact(t, store, fixture.Create)
	})

	t.Run("migration-upgrade-replay-rollback", func(t *testing.T) {
		store := newStore(t, factory, fixture)
		status, err := store.MigrationStatus(context.Background(), fixture.Migration.Component)
		if err != nil || status.State != workflow.MigrationPending || status.Version != 0 {
			t.Fatalf("initial status = %+v, err = %v", status, err)
		}
		applied := migrate(t, store, fixture.Migration)
		if applied.State != workflow.MigrationApplied || applied.Replayed {
			t.Fatalf("applied migration = %+v", applied)
		}
		replayed := migrate(t, store, fixture.Migration)
		if !replayed.Replayed || replayed.State != workflow.MigrationApplied {
			t.Fatalf("replayed migration = %+v", replayed)
		}
		tampered := fixture.Migration
		tampered.Checksum = Digest("tampered-migration")
		if _, err := store.Migrate(context.Background(), tampered); workflow.StorageCode(err) != workflow.StorageDenied {
			t.Fatalf("tampered migration code = %q, err = %v", workflow.StorageCode(err), err)
		}
		rollback := fixture.Migration
		rollback.Direction = workflow.MigrationRollback
		rolledBack := migrate(t, store, rollback)
		if rolledBack.State != workflow.MigrationRolledBack {
			t.Fatalf("rollback migration = %+v", rolledBack)
		}
	})
}

func NewFixture(t *testing.T) Fixture {
	t.Helper()
	first := Record(t, 1, "open")
	second := Record(t, 2, "closed")
	create := workflow.Transaction{
		ContractVersion: workflow.StorageContractVersion, IdempotencyKey: "create-case",
		Mutations: []workflow.Mutation{{Kind: workflow.MutationPut, Key: first.Key, Record: &first}},
		Outbox:    []workflow.OutboxMessage{{ID: MessageID, Case: first.Key.Case, Topic: "case.created", PayloadRef: "record:" + CaseID + ":1", PayloadDigest: first.Digest}},
	}
	update := workflow.Transaction{
		ContractVersion: workflow.StorageContractVersion, IdempotencyKey: "close-case",
		Mutations: []workflow.Mutation{{Kind: workflow.MutationPut, Key: second.Key, ExpectedRevision: 1, Record: &second}},
	}
	changed := cloneTransaction(create)
	changed.Outbox[0].PayloadRef = "record:" + CaseID + ":changed"
	return Fixture{
		Create: create, Update: update, ChangedRetry: changed,
		Claim:      workflow.OutboxClaim{OrganizationID: OrganizationID, TenantID: TenantID, WorkerID: "conformance-worker", Limit: 8, LeaseUntil: time.Date(2026, 8, 25, 21, 0, 0, 0, time.UTC)},
		Settlement: workflow.OutboxSettlement{MessageID: MessageID, Outcome: workflow.OutboxDelivered, EvidenceDigest: Digest("delivery-evidence")},
		Migration:  workflow.MigrationPlan{ContractVersion: workflow.StorageContractVersion, Component: "conformance", Version: 1, Checksum: Digest("conformance-v1"), BackupDigest: Digest("conformance-v0-backup"), Direction: workflow.MigrationApply},
	}
}

func Record(t *testing.T, revision uint64, state string) workflow.MetadataRecord {
	t.Helper()
	encoded := []byte(`{"schema":"coh.domain/v1","kind":"case","id":"` + CaseID + `","organization_id":"` + OrganizationID + `","tenant_id":"` + TenantID + `","case_id":"` + CaseID + `","revision":` + uintText(revision) + `,"created_at":"2026-08-25T18:00:00.000000000Z","data":{"state":"` + state + `"}}`)
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return workflow.MetadataRecord{
		Key:    workflow.RecordKey{Case: domain.CaseRef{OrganizationID: OrganizationID, TenantID: TenantID, CaseID: CaseID}, Kind: "case", ID: CaseID},
		Schema: "coh.domain/v1", Revision: revision, Canonical: canonical, Digest: DigestBytes(canonical),
	}
}

func Digest(value string) string { return DigestBytes([]byte(value)) }
func DigestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newStore(t *testing.T, factory Factory, fixture Fixture) workflow.Repository {
	t.Helper()
	driver := factory(t, fixture)
	store, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func transact(t *testing.T, store workflow.Repository, transaction workflow.Transaction) workflow.CommitResult {
	t.Helper()
	result, err := store.Transact(context.Background(), transaction)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func migrate(t *testing.T, store workflow.Repository, plan workflow.MigrationPlan) workflow.MigrationResult {
	t.Helper()
	result, err := store.Migrate(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func keyString(key workflow.RecordKey) string {
	return key.Case.OrganizationID + "/" + key.Case.TenantID + "/" + key.Case.CaseID + "/" + key.Kind + "/" + key.ID
}

func cloneTransaction(value workflow.Transaction) workflow.Transaction {
	value.Mutations = append([]workflow.Mutation(nil), value.Mutations...)
	value.Outbox = append([]workflow.OutboxMessage(nil), value.Outbox...)
	return value
}

func uintText(value uint64) string {
	if value == 0 {
		return "0"
	}
	result := ""
	for value > 0 {
		result = string(rune('0'+value%10)) + result
		value /= 10
	}
	return result
}
