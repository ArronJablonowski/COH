package workflow

import (
	"context"
	"reflect"
)

// MetadataStore owns atomic metadata reads and optimistic transactions.
type MetadataStore interface {
	Get(context.Context, RecordKey) (MetadataRecord, error)
	Transact(context.Context, Transaction) (CommitResult, error)
}

// OutboxStore owns bounded leases and idempotent settlement.
type OutboxStore interface {
	ClaimOutbox(context.Context, OutboxClaim) ([]OutboxDelivery, error)
	SettleOutbox(context.Context, OutboxSettlement) error
}

// MigrationStore owns registered, checksummed, backup-aware migrations.
type MigrationStore interface {
	MigrationStatus(context.Context, string) (MigrationResult, error)
	Migrate(context.Context, MigrationPlan) (MigrationResult, error)
}

// Repository is the complete workflow-visible storage port.
type Repository interface {
	MetadataStore
	OutboxStore
	MigrationStore
}

// StorageDriver is implemented by concrete adapters. GuardStorage must wrap a
// driver before it is supplied to workflow.Dependencies.
type StorageDriver interface {
	Repository
}

type guardedStorage struct{ driver StorageDriver }

// GuardStorage creates the fail-closed workflow-visible storage boundary.
func GuardStorage(driver StorageDriver) (Repository, error) {
	if driver == nil || isNilStorageDriver(driver) {
		return nil, NewStorageError(StorageInvalidInput, "guard", "driver", "driver is required", nil)
	}
	return &guardedStorage{driver: driver}, nil
}

func isNilStorageDriver(driver StorageDriver) bool {
	value := reflect.ValueOf(driver)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
