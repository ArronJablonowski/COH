package workflow

import (
	"context"
	"sort"
)

func contextReady(ctx context.Context, operation string) error {
	if ctx == nil {
		return invalid(operation, "context", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return storageContextError(operation, err)
	}
	return nil
}

func finishDriverCall(ctx context.Context, operation string, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return storageContextError(operation, contextErr)
	}
	return normalizeStorageError(operation, err)
}

func (store *guardedStorage) Get(ctx context.Context, key RecordKey) (MetadataRecord, error) {
	const operation = "get"
	if err := contextReady(ctx, operation); err != nil {
		return MetadataRecord{}, err
	}
	if err := validateRecordKey(operation, "key", key); err != nil {
		return MetadataRecord{}, err
	}
	record, err := store.driver.Get(ctx, key)
	if err = finishDriverCall(ctx, operation, err); err != nil {
		return MetadataRecord{}, err
	}
	if record.Key != key {
		return MetadataRecord{}, denied(operation, "result.key", "driver returned a different record identity")
	}
	if err := ValidateMetadataRecord(record); err != nil {
		return MetadataRecord{}, denied(operation, "result", "driver returned an invalid record")
	}
	return cloneRecord(record), nil
}

func (store *guardedStorage) Transact(ctx context.Context, transaction Transaction) (CommitResult, error) {
	const operation = "transact"
	if err := contextReady(ctx, operation); err != nil {
		return CommitResult{}, err
	}
	if err := ValidateTransaction(transaction); err != nil {
		return CommitResult{}, err
	}
	result, err := store.driver.Transact(ctx, cloneTransaction(transaction))
	if err = finishDriverCall(ctx, operation, err); err != nil {
		return CommitResult{}, err
	}
	if err := validateCommitResult(transaction, result); err != nil {
		return CommitResult{}, err
	}
	return cloneCommitResult(result), nil
}

func (store *guardedStorage) ClaimOutbox(ctx context.Context, claim OutboxClaim) ([]OutboxDelivery, error) {
	const operation = "claim_outbox"
	if err := contextReady(ctx, operation); err != nil {
		return nil, err
	}
	if err := ValidateOutboxClaim(claim); err != nil {
		return nil, err
	}
	deliveries, err := store.driver.ClaimOutbox(ctx, claim)
	if err = finishDriverCall(ctx, operation, err); err != nil {
		return nil, err
	}
	if len(deliveries) > int(claim.Limit) {
		return nil, denied(operation, "result", "driver exceeded the claim limit")
	}
	ids := make([]string, 0, len(deliveries))
	for index, delivery := range deliveries {
		if err := validateOutboxMessage(operation, "result["+itoa(index)+"].message", delivery.Message); err != nil {
			return nil, denied(operation, "result", "driver returned an invalid outbox message")
		}
		if !uuidV7Pattern.MatchString(delivery.LeaseID) || delivery.Message.Case.OrganizationID != claim.OrganizationID || delivery.Message.Case.TenantID != claim.TenantID {
			return nil, denied(operation, "result", "driver returned an invalid lease or cross-scope message")
		}
		ids = append(ids, delivery.Message.ID)
	}
	if !sort.StringsAreSorted(ids) || hasDuplicate(ids) {
		return nil, denied(operation, "result", "driver returned unsorted or duplicate messages")
	}
	return append([]OutboxDelivery(nil), deliveries...), nil
}

func (store *guardedStorage) SettleOutbox(ctx context.Context, settlement OutboxSettlement) error {
	const operation = "settle_outbox"
	if err := contextReady(ctx, operation); err != nil {
		return err
	}
	if err := ValidateOutboxSettlement(settlement); err != nil {
		return err
	}
	return finishDriverCall(ctx, operation, store.driver.SettleOutbox(ctx, settlement))
}

func (store *guardedStorage) MigrationStatus(ctx context.Context, component string) (MigrationResult, error) {
	const operation = "migration_status"
	if err := contextReady(ctx, operation); err != nil {
		return MigrationResult{}, err
	}
	if !tokenPattern.MatchString(component) {
		return MigrationResult{}, invalid(operation, "component", "component is invalid")
	}
	result, err := store.driver.MigrationStatus(ctx, component)
	if err = finishDriverCall(ctx, operation, err); err != nil {
		return MigrationResult{}, err
	}
	if err := validateMigrationResult(result); err != nil || result.Component != component {
		return MigrationResult{}, denied(operation, "result", "driver returned an invalid migration status")
	}
	return result, nil
}

func (store *guardedStorage) Migrate(ctx context.Context, plan MigrationPlan) (MigrationResult, error) {
	const operation = "migrate"
	if err := contextReady(ctx, operation); err != nil {
		return MigrationResult{}, err
	}
	if err := ValidateMigrationPlan(plan); err != nil {
		return MigrationResult{}, err
	}
	result, err := store.driver.Migrate(ctx, plan)
	if err = finishDriverCall(ctx, operation, err); err != nil {
		return MigrationResult{}, err
	}
	if err := validateMigrationResult(result); err != nil || result.Component != plan.Component || result.Version != plan.Version || result.Checksum != plan.Checksum {
		return MigrationResult{}, denied(operation, "result", "driver returned a migration result for different inputs")
	}
	if plan.Direction == MigrationApply && result.State != MigrationApplied || plan.Direction == MigrationRollback && result.State != MigrationRolledBack {
		return MigrationResult{}, denied(operation, "result.state", "driver returned an incompatible migration state")
	}
	return result, nil
}

func validateCommitResult(transaction Transaction, result CommitResult) error {
	if result.IdempotencyKey != transaction.IdempotencyKey || result.CommitSequence == 0 {
		return denied("transact", "result", "driver returned an invalid commit identity")
	}
	if len(result.RecordVersions) != len(transaction.Mutations) || len(result.OutboxIDs) != len(transaction.Outbox) {
		return denied("transact", "result", "driver returned an incomplete commit result")
	}
	for _, mutation := range transaction.Mutations {
		want := mutation.ExpectedRevision + 1
		if mutation.Kind == MutationDelete {
			want = 0
		}
		version, exists := result.RecordVersions[recordKeyString(mutation.Key)]
		if !exists || version != want {
			return denied("transact", "result.record_versions", "driver returned a different revision")
		}
	}
	if !sort.StringsAreSorted(result.OutboxIDs) || hasDuplicate(result.OutboxIDs) {
		return denied("transact", "result.outbox_ids", "outbox identities are not uniquely sorted")
	}
	for index := range transaction.Outbox {
		if result.OutboxIDs[index] != transaction.Outbox[index].ID {
			return denied("transact", "result.outbox_ids", "outbox identity differs from transaction")
		}
	}
	return nil
}

func validateMigrationResult(result MigrationResult) error {
	if !tokenPattern.MatchString(result.Component) {
		return invalid("migration_result", "identity", "component is invalid")
	}
	if result.State == MigrationPending && result.Version == 0 && result.Checksum == "" && result.ResumeDigest == "" {
		return nil
	}
	if result.Version == 0 {
		return invalid("migration_result", "version", "positive migration version is required")
	}
	if err := validateDigest("migration_result", "checksum", result.Checksum); err != nil {
		return err
	}
	if result.ResumeDigest != "" {
		if err := validateDigest("migration_result", "resume_digest", result.ResumeDigest); err != nil {
			return err
		}
	}
	switch result.State {
	case MigrationPending, MigrationInProgress, MigrationApplied, MigrationRolledBack:
		return nil
	default:
		return invalid("migration_result", "state", "unsupported migration state")
	}
}

func cloneRecord(record MetadataRecord) MetadataRecord {
	record.Canonical = append([]byte(nil), record.Canonical...)
	return record
}

func cloneTransaction(transaction Transaction) Transaction {
	transaction.Mutations = append([]Mutation(nil), transaction.Mutations...)
	for index := range transaction.Mutations {
		if transaction.Mutations[index].Record != nil {
			record := cloneRecord(*transaction.Mutations[index].Record)
			transaction.Mutations[index].Record = &record
		}
	}
	transaction.Outbox = append([]OutboxMessage(nil), transaction.Outbox...)
	return transaction
}

func cloneCommitResult(result CommitResult) CommitResult {
	versions := make(map[string]uint64, len(result.RecordVersions))
	for key, version := range result.RecordVersions {
		versions[key] = version
	}
	result.RecordVersions = versions
	result.OutboxIDs = append([]string(nil), result.OutboxIDs...)
	return result
}
