package sqlite

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/extensionlifecycle"
)

// ExtensionLifecycle returns the narrow typed adapter used by the command
// composition root. The base Store retains its independent profile API.
func (store *Store) ExtensionLifecycle() extensionlifecycle.ActivationStore {
	return &extensionLifecycleStore{Store: store}
}

type extensionLifecycleStore struct{ *Store }

func (adapter *extensionLifecycleStore) LoadActive(ctx context.Context, extension, organization, tenant string) (extensionlifecycle.ActiveExtension, bool, error) {
	return adapter.Store.loadLifecycleActive(ctx, extension, organization, tenant)
}
func (adapter *extensionLifecycleStore) LoadInactivePredecessor(ctx context.Context, extension, organization, tenant, manifest string, revision uint64) (extensionlifecycle.Transition, bool, error) {
	return adapter.Store.loadInactiveLifecyclePredecessor(ctx, extension, organization, tenant, manifest, revision)
}
func (adapter *extensionLifecycleStore) LoadTransition(ctx context.Context, id string) (extensionlifecycle.Transition, bool, error) {
	return adapter.Store.loadLifecycleTransition(ctx, id)
}
func (adapter *extensionLifecycleStore) CreateTransition(ctx context.Context, value extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	return adapter.Store.createLifecycleTransition(ctx, value)
}
func (adapter *extensionLifecycleStore) AdvanceTransition(ctx context.Context, current, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	return adapter.Store.advanceLifecycleTransition(ctx, current, next)
}

var _ extensionlifecycle.ActivationStore = (*extensionLifecycleStore)(nil)
