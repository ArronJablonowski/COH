package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/persistence/storetest"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

var testNow = time.Date(2026, 8, 25, 18, 0, 0, 0, time.UTC)

func TestStorageConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T, fixture storetest.Fixture) workflow.StorageDriver {
		store := openTestStore(t)
		store.registerMigration(migration{
			component: fixture.Migration.Component,
			version:   fixture.Migration.Version,
			checksum:  fixture.Migration.Checksum,
		})
		backupPath := filepath.Join(store.backupDir, "conformance-fixture.backup")
		if err := os.WriteFile(backupPath, []byte("conformance-v0-backup"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := store.registerBackupForTest(context.Background(), backupPath, fixture.Migration.BackupDigest); err != nil {
			t.Fatal(err)
		}
		return store
	})
}

func TestWALRecoveryAndConsistentBackup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "coh.sqlite3")
	backupDir := filepath.Join(root, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), Config{Path: path, BackupDirectory: backupDir, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	fixture := storetest.NewFixture(t)
	first, err := guarded.Transact(context.Background(), fixture.Create)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Backup(context.Background())
	if err != nil || artifact.Digest == "" || artifact.Length == 0 {
		t.Fatalf("backup = %+v, err = %v", artifact, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), Config{Path: path, BackupDirectory: backupDir, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	guarded, err = workflow.GuardStorage(reopened)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := guarded.Transact(context.Background(), fixture.Create)
	if err != nil || !replayed.Replayed || replayed.CommitSequence != first.CommitSequence {
		t.Fatalf("reopen replay = %+v, err = %v", replayed, err)
	}
	if _, err := os.Stat(artifact.Path); err != nil {
		t.Fatal(err)
	}
}

func TestOutboxRetryIsReplaySafeAndReclaimable(t *testing.T) {
	store := openTestStore(t)
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	fixture := storetest.NewFixture(t)
	if _, err := guarded.Transact(context.Background(), fixture.Create); err != nil {
		t.Fatal(err)
	}
	deliveries, err := guarded.ClaimOutbox(context.Background(), fixture.Claim)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, err = %v", deliveries, err)
	}
	retry := workflow.OutboxSettlement{MessageID: deliveries[0].Message.ID, LeaseID: deliveries[0].LeaseID, Outcome: workflow.OutboxRetry}
	if err := guarded.SettleOutbox(context.Background(), retry); err != nil {
		t.Fatal(err)
	}
	if err := guarded.SettleOutbox(context.Background(), retry); err != nil {
		t.Fatalf("retry replay: %v", err)
	}
	reclaimed, err := guarded.ClaimOutbox(context.Background(), fixture.Claim)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].LeaseID == retry.LeaseID {
		t.Fatalf("reclaim = %+v, err = %v", reclaimed, err)
	}
}

func TestMetadataRollbackRequiresEmptyStore(t *testing.T) {
	store := openTestStore(t)
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	fixture := storetest.NewFixture(t)
	if _, err := guarded.Transact(context.Background(), fixture.Create); err != nil {
		t.Fatal(err)
	}
	spec := store.migrations["metadata"]
	backup, err := store.Backup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = guarded.Migrate(context.Background(), workflow.MigrationPlan{
		ContractVersion: workflow.StorageContractVersion,
		Component:       spec.component,
		Version:         spec.version,
		Checksum:        spec.checksum,
		BackupDigest:    backup.Digest,
		Direction:       workflow.MigrationRollback,
	})
	if workflow.StorageCode(err) != workflow.StorageConflict {
		t.Fatalf("rollback code = %q, err = %v", workflow.StorageCode(err), err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	backupDir := filepath.Join(root, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), Config{
		Path:            filepath.Join(root, "coh.sqlite3"),
		BackupDirectory: backupDir,
		Clock:           func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
