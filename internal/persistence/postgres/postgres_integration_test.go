package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/persistence/storetest"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/jackc/pgx/v5"
)

const testBootstrapDigest = "sha256:1e1bbd8875a61c5a406b9af2037ba1a280ca67d2486e209cba9ba8b7131f4d9a"

type testBackupVerifier struct{ denied string }

func (verifier testBackupVerifier) VerifyBackup(ctx context.Context, digest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if digest == verifier.denied {
		return errors.New("backup is absent")
	}
	return nil
}

func TestPostgresConformance(t *testing.T) {
	url := integrationURL(t)
	resetDatabase(t, url)
	t.Cleanup(func() { resetDatabase(t, url) })
	storetest.Run(t, func(t *testing.T, fixture storetest.Fixture) workflow.StorageDriver {
		store := openTestStore(t, url, testBackupVerifier{})
		store.registerMigration(migration{
			component: fixture.Migration.Component, version: fixture.Migration.Version, checksum: fixture.Migration.Checksum,
			up:   []string{`CREATE TABLE public.coh_conformance_marker (identity INTEGER PRIMARY KEY)`},
			down: []string{`DROP TABLE public.coh_conformance_marker`},
		})
		t.Cleanup(func() { resetDatabase(t, url) })
		t.Cleanup(store.Close)
		return store
	})
}

func TestRowLevelTenantIsolationAndConnectionBounds(t *testing.T) {
	url := integrationURL(t)
	resetDatabase(t, url)
	t.Cleanup(func() { resetDatabase(t, url) })
	store := openTestStore(t, url, testBackupVerifier{})
	t.Cleanup(store.Close)
	if store.pool.Stat().MaxConns() != 4 {
		t.Fatalf("max connections = %d", store.pool.Stat().MaxConns())
	}
	fixture := storetest.NewFixture(t)
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guarded.Transact(context.Background(), fixture.Create); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.coh_records`).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("unscoped role saw %d tenant rows", visible)
	}
	other := fixture.Create.Mutations[0].Key
	other.Case.TenantID = "0198d6c4-3333-7333-8333-333333333333"
	if _, err := guarded.Get(context.Background(), other); workflow.StorageCode(err) != workflow.StorageNotFound {
		t.Fatalf("cross-tenant get code = %q, err = %v", workflow.StorageCode(err), err)
	}
	var forced, enabled bool
	if err := store.pool.QueryRow(context.Background(), `SELECT relforcerowsecurity, relrowsecurity
FROM pg_catalog.pg_class WHERE oid='public.coh_records'::regclass`).Scan(&forced, &enabled); err != nil {
		t.Fatal(err)
	}
	if !forced || !enabled {
		t.Fatalf("row security forced=%v enabled=%v", forced, enabled)
	}
	tx, err := store.beginScoped(context.Background(), storetest.OrganizationID, storetest.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, insertErr := tx.Exec(context.Background(), `INSERT INTO public.coh_records
(organization_id,tenant_id,case_id,kind,record_id,schema_id,revision,canonical,digest)
VALUES($1,$2,$3,'case',$3,'coh.domain/v1',1,'{}',$4)`, storetest.OrganizationID,
		"0198d6c4-3333-7333-8333-333333333333", storetest.CaseID, storetest.Digest("cross-scope"))
	tx.Rollback(context.Background())
	if workflow.StorageCode(normalizeError("transact", "record", insertErr)) != workflow.StorageDenied {
		t.Fatalf("cross-scope insert error = %v", insertErr)
	}
}

func TestConcurrentOutboxClaimAndDatabaseRecovery(t *testing.T) {
	url := integrationURL(t)
	resetDatabase(t, url)
	t.Cleanup(func() { resetDatabase(t, url) })
	store := openTestStore(t, url, testBackupVerifier{})
	t.Cleanup(store.Close)
	fixture := storetest.NewFixture(t)
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guarded.Transact(context.Background(), fixture.Create); err != nil {
		t.Fatal(err)
	}
	claims := []workflow.OutboxClaim{fixture.Claim, fixture.Claim}
	claims[0].WorkerID, claims[1].WorkerID = "worker-a", "worker-b"
	results := make(chan []workflow.OutboxDelivery, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for _, claim := range claims {
		wait.Add(1)
		go func(value workflow.OutboxClaim) {
			defer wait.Done()
			deliveries, claimErr := guarded.ClaimOutbox(context.Background(), value)
			results <- deliveries
			errorsSeen <- claimErr
		}(claim)
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	claimed := 0
	for claimErr := range errorsSeen {
		if claimErr != nil {
			t.Fatal(claimErr)
		}
	}
	for deliveries := range results {
		claimed += len(deliveries)
	}
	if claimed != 1 {
		t.Fatalf("concurrent workers claimed %d messages", claimed)
	}

	timeoutContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	tx, err := store.beginScoped(timeoutContext, storetest.OrganizationID, storetest.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, queryErr := tx.Exec(timeoutContext, `SELECT pg_catalog.pg_sleep(1)`)
	tx.Rollback(context.Background())
	if workflow.StorageCode(normalizeError("test", "timeout", queryErr)) != workflow.StorageTimeout {
		t.Fatalf("database timeout error = %v", queryErr)
	}
	if _, err := guarded.Get(context.Background(), fixture.Create.Mutations[0].Key); err != nil {
		t.Fatalf("recovery read failed: %v", err)
	}
}

func TestConcurrentIdempotentTransaction(t *testing.T) {
	url := integrationURL(t)
	resetDatabase(t, url)
	t.Cleanup(func() { resetDatabase(t, url) })
	store := openTestStore(t, url, testBackupVerifier{})
	t.Cleanup(store.Close)
	fixture := storetest.NewFixture(t)
	guarded, err := workflow.GuardStorage(store)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan workflow.CommitResult, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, transactErr := guarded.Transact(context.Background(), fixture.Create)
			results <- result
			errorsSeen <- transactErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for transactErr := range errorsSeen {
		if transactErr != nil {
			t.Fatal(transactErr)
		}
	}
	replayed := 0
	var sequence uint64
	for result := range results {
		if sequence == 0 {
			sequence = result.CommitSequence
		}
		if result.CommitSequence != sequence {
			t.Fatalf("commit sequences differ: %d and %d", sequence, result.CommitSequence)
		}
		if result.Replayed {
			replayed++
		}
	}
	if replayed != 1 {
		t.Fatalf("replayed results = %d", replayed)
	}
}

func TestBackupDenialAndPrivilegedRoleDenial(t *testing.T) {
	url := integrationURL(t)
	resetDatabase(t, url)
	t.Cleanup(func() { resetDatabase(t, url) })
	denied := storetest.Digest("denied-backup")
	store := openTestStore(t, url, testBackupVerifier{denied: denied})
	t.Cleanup(store.Close)
	spec := migration{component: "denied", version: 1, checksum: storetest.Digest("denied-migration"), up: []string{`SELECT 1`}, down: []string{`SELECT 1`}}
	store.registerMigration(spec)
	_, err := store.Migrate(context.Background(), workflow.MigrationPlan{
		ContractVersion: workflow.StorageContractVersion, Component: spec.component, Version: spec.version,
		Checksum: spec.checksum, BackupDigest: denied, Direction: workflow.MigrationApply,
	})
	if workflow.StorageCode(err) != workflow.StorageDenied {
		t.Fatalf("backup denial code = %q, err = %v", workflow.StorageCode(err), err)
	}
	adminURL := os.Getenv("COH_POSTGRES_ADMIN_TEST_URL")
	if adminURL == "" {
		t.Fatal("COH_POSTGRES_ADMIN_TEST_URL is required for privileged-role denial coverage")
	}
	_, err = Open(context.Background(), Config{
		URL: adminURL, MaxConnections: 1, AllowInsecureLocalhost: true,
		BootstrapBackupDigest: testBootstrapDigest, BackupVerifier: testBackupVerifier{},
	})
	if workflow.StorageCode(err) != workflow.StorageDenied {
		t.Fatalf("privileged role code = %q, err = %v", workflow.StorageCode(err), err)
	}
}

func openTestStore(t *testing.T, url string, verifier BackupVerifier) *Store {
	t.Helper()
	store, err := Open(context.Background(), Config{
		URL: url, MaxConnections: 4, MinConnections: 1, AllowInsecureLocalhost: true,
		BootstrapBackupDigest: testBootstrapDigest, BackupVerifier: verifier,
		Clock: func() time.Time { return time.Date(2026, 8, 25, 20, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func integrationURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("COH_POSTGRES_TEST_URL")
	if url == "" {
		t.Skip("COH_POSTGRES_TEST_URL is not set")
	}
	return url
}

func resetDatabase(t *testing.T, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	_, err = connection.Exec(ctx, `DROP TABLE IF EXISTS public.coh_conformance_marker, public.coh_outbox,
public.coh_idempotency, public.coh_records, public.coh_store_sequence, public.coh_migration_state CASCADE`)
	if err != nil {
		t.Fatal(err)
	}
}
