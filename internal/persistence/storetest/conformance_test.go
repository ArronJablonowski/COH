package storetest

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

const conformanceLeaseID = "0198d6c4-2222-7222-8222-222222222222"

type memoryCommit struct {
	fingerprint string
	result      workflow.CommitResult
}

type memoryOutbox struct {
	message    workflow.OutboxMessage
	leaseID    string
	settlement *workflow.OutboxSettlement
}

type memoryDriver struct {
	mu            sync.Mutex
	records       map[string]workflow.MetadataRecord
	commits       map[string]memoryCommit
	outbox        map[string]*memoryOutbox
	sequence      uint64
	registered    map[uint64]workflow.MigrationPlan
	migration     workflow.MigrationResult
	migrationRuns map[workflow.MigrationDirection]bool
}

func TestReferenceDriverConformance(t *testing.T) {
	Run(t, func(_ *testing.T, fixture Fixture) workflow.StorageDriver {
		return &memoryDriver{
			records: make(map[string]workflow.MetadataRecord), commits: make(map[string]memoryCommit),
			outbox: make(map[string]*memoryOutbox), registered: map[uint64]workflow.MigrationPlan{
				fixture.Migration.Version: fixture.Migration, fixture.NextMigration.Version: fixture.NextMigration,
			},
			migration:     workflow.MigrationResult{Component: fixture.Migration.Component, State: workflow.MigrationPending},
			migrationRuns: make(map[workflow.MigrationDirection]bool),
		}
	})
}

func (driver *memoryDriver) Get(ctx context.Context, key workflow.RecordKey) (workflow.MetadataRecord, error) {
	if err := ctx.Err(); err != nil {
		return workflow.MetadataRecord{}, err
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	record, exists := driver.records[keyString(key)]
	if !exists {
		return workflow.MetadataRecord{}, workflow.NewStorageError(workflow.StorageNotFound, "get", "key", "record not found", nil)
	}
	record.Canonical = append([]byte(nil), record.Canonical...)
	return record, nil
}

func (driver *memoryDriver) Transact(ctx context.Context, transaction workflow.Transaction) (workflow.CommitResult, error) {
	if err := ctx.Err(); err != nil {
		return workflow.CommitResult{}, err
	}
	encoded, err := json.Marshal(transaction)
	if err != nil {
		return workflow.CommitResult{}, err
	}
	fingerprint := DigestBytes(encoded)
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if previous, exists := driver.commits[transaction.IdempotencyKey]; exists {
		if previous.fingerprint != fingerprint {
			return workflow.CommitResult{}, workflow.NewStorageError(workflow.StorageConflict, "transact", "idempotency_key", "key was used for different input", nil)
		}
		result := cloneCommit(previous.result)
		result.Replayed = true
		return result, nil
	}
	for _, mutation := range transaction.Mutations {
		record, exists := driver.records[keyString(mutation.Key)]
		current := uint64(0)
		if exists {
			current = record.Revision
		}
		if current != mutation.ExpectedRevision {
			return workflow.CommitResult{}, workflow.NewStorageError(workflow.StorageConflict, "transact", "expected_revision", "optimistic concurrency check failed", nil)
		}
	}
	versions := make(map[string]uint64, len(transaction.Mutations))
	for _, mutation := range transaction.Mutations {
		key := keyString(mutation.Key)
		if mutation.Kind == workflow.MutationDelete {
			delete(driver.records, key)
			versions[key] = 0
			continue
		}
		record := *mutation.Record
		record.Canonical = append([]byte(nil), record.Canonical...)
		driver.records[key] = record
		versions[key] = record.Revision
	}
	outboxIDs := make([]string, 0, len(transaction.Outbox))
	for _, message := range transaction.Outbox {
		driver.outbox[message.ID] = &memoryOutbox{message: message}
		outboxIDs = append(outboxIDs, message.ID)
	}
	driver.sequence++
	result := workflow.CommitResult{
		IdempotencyKey: transaction.IdempotencyKey, CommitSequence: driver.sequence,
		RecordVersions: versions, OutboxIDs: outboxIDs,
	}
	driver.commits[transaction.IdempotencyKey] = memoryCommit{fingerprint: fingerprint, result: cloneCommit(result)}
	return result, nil
}

func (driver *memoryDriver) ClaimOutbox(ctx context.Context, claim workflow.OutboxClaim) ([]workflow.OutboxDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	ids := make([]string, 0, len(driver.outbox))
	for id, entry := range driver.outbox {
		if entry.settlement == nil && entry.message.Case.OrganizationID == claim.OrganizationID && entry.message.Case.TenantID == claim.TenantID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > int(claim.Limit) {
		ids = ids[:claim.Limit]
	}
	deliveries := make([]workflow.OutboxDelivery, 0, len(ids))
	for _, id := range ids {
		entry := driver.outbox[id]
		entry.leaseID = conformanceLeaseID
		deliveries = append(deliveries, workflow.OutboxDelivery{Message: entry.message, LeaseID: entry.leaseID})
	}
	return deliveries, nil
}

func (driver *memoryDriver) SettleOutbox(ctx context.Context, settlement workflow.OutboxSettlement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	entry, exists := driver.outbox[settlement.MessageID]
	if !exists {
		return workflow.NewStorageError(workflow.StorageNotFound, "settle_outbox", "message_id", "message not found", nil)
	}
	if entry.leaseID != settlement.LeaseID {
		return workflow.NewStorageError(workflow.StorageConflict, "settle_outbox", "lease_id", "lease does not match", nil)
	}
	if entry.settlement != nil {
		if *entry.settlement == settlement {
			return nil
		}
		return workflow.NewStorageError(workflow.StorageConflict, "settle_outbox", "outcome", "message already settled differently", nil)
	}
	copy := settlement
	entry.settlement = &copy
	return nil
}

func (driver *memoryDriver) MigrationStatus(ctx context.Context, component string) (workflow.MigrationResult, error) {
	if err := ctx.Err(); err != nil {
		return workflow.MigrationResult{}, err
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	registered := driver.registered[1]
	if component != registered.Component {
		return workflow.MigrationResult{}, workflow.NewStorageError(workflow.StorageNotFound, "migration_status", "component", "migration component not found", nil)
	}
	return driver.migration, nil
}

func (driver *memoryDriver) Migrate(ctx context.Context, plan workflow.MigrationPlan) (workflow.MigrationResult, error) {
	if err := ctx.Err(); err != nil {
		return workflow.MigrationResult{}, err
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	registered, ok := driver.registered[plan.Version]
	if !ok || plan.Component != registered.Component || plan.Checksum != registered.Checksum {
		return workflow.MigrationResult{}, workflow.NewStorageError(workflow.StorageDenied, "migrate", "checksum", "migration is not registered", nil)
	}
	if driver.migration.Version != 0 && (driver.migration.Version != plan.Version || driver.migration.Checksum != plan.Checksum) {
		return workflow.MigrationResult{}, workflow.NewStorageError(workflow.StorageDenied, "migrate", "state", "stored migration identity differs from plan", nil)
	}
	state := workflow.MigrationApplied
	if plan.Direction == workflow.MigrationRollback {
		state = workflow.MigrationRolledBack
	}
	result := workflow.MigrationResult{
		Component: plan.Component, Version: plan.Version, Checksum: plan.Checksum,
		State: state, ResumeDigest: Digest("migration-checkpoint"), Replayed: driver.migrationRuns[plan.Direction],
	}
	driver.migrationRuns[plan.Direction] = true
	driver.migration = result
	return result, nil
}

func cloneCommit(result workflow.CommitResult) workflow.CommitResult {
	versions := make(map[string]uint64, len(result.RecordVersions))
	for key, revision := range result.RecordVersions {
		versions[key] = revision
	}
	result.RecordVersions = versions
	result.OutboxIDs = append([]string(nil), result.OutboxIDs...)
	return result
}
