package sqlite

import (
	"context"
	"os"
	"os/exec"
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
		store.registerMigration(migration{
			component: fixture.NextMigration.Component,
			version:   fixture.NextMigration.Version,
			checksum:  fixture.NextMigration.Checksum,
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

func TestAuditConformance(t *testing.T) {
	store := openTestStore(t)
	storetest.RunAuditConformance(t, store)
	var updateBlocked, deleteBlocked bool
	if _, err := store.db.Exec(`UPDATE coh_audit_records SET chain_hash=''`); err != nil {
		updateBlocked = true
	}
	if _, err := store.db.Exec(`DELETE FROM coh_audit_records`); err != nil {
		deleteBlocked = true
	}
	if !updateBlocked || !deleteBlocked {
		t.Fatalf("append-only triggers update=%v delete=%v", updateBlocked, deleteBlocked)
	}
}

func TestWALRecoveryAndConsistentBackup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "coh.sqlite3")
	backupDir := filepath.Join(root, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSQLiteCrashWriter$")
	command.Env = append(os.Environ(), "COH_SQLITE_CRASH_PATH="+path, "COH_SQLITE_CRASH_BACKUP_DIR="+backupDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crash writer: %v\n%s", err, output)
	}
	fixture := storetest.NewFixture(t)
	reopened, err := Open(context.Background(), Config{Path: path, BackupDirectory: backupDir, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	guarded, err := workflow.GuardStorage(reopened)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := guarded.Transact(context.Background(), fixture.Create)
	if err != nil || !replayed.Replayed || replayed.CommitSequence != 1 {
		t.Fatalf("reopen replay = %+v, err = %v", replayed, err)
	}
	artifact, err := reopened.Backup(context.Background())
	if err != nil || artifact.Digest == "" || artifact.Length == 0 {
		t.Fatalf("backup = %+v, err = %v", artifact, err)
	}
	if _, err := os.Stat(artifact.Path); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteCrashWriter(t *testing.T) {
	path := os.Getenv("COH_SQLITE_CRASH_PATH")
	backupDir := os.Getenv("COH_SQLITE_CRASH_BACKUP_DIR")
	if path == "" || backupDir == "" {
		t.Skip("subprocess helper")
	}
	store, err := Open(context.Background(), Config{Path: path, BackupDirectory: backupDir, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guarded.Transact(context.Background(), storetest.NewFixture(t).Create); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
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
	retry := workflow.OutboxSettlement{OrganizationID: storetest.OrganizationID, TenantID: storetest.TenantID, MessageID: deliveries[0].Message.ID, LeaseID: deliveries[0].LeaseID, Outcome: workflow.OutboxRetry}
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
	spec := store.migrations[migrationKey{component: "metadata", version: 1}]
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

func TestMigrationRejectsTamperedBackup(t *testing.T) {
	store := openTestStore(t)
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := store.Backup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(backup.Path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tamper"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	spec := store.migrations[migrationKey{component: "metadata", version: 1}]
	_, err = guarded.Migrate(context.Background(), workflow.MigrationPlan{
		ContractVersion: workflow.StorageContractVersion,
		Component:       spec.component,
		Version:         spec.version,
		Checksum:        spec.checksum,
		BackupDigest:    backup.Digest,
		Direction:       workflow.MigrationRollback,
	})
	if workflow.StorageCode(err) != workflow.StorageDenied {
		t.Fatalf("tampered backup code = %q, err = %v", workflow.StorageCode(err), err)
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
