package credentiallease

import (
	"context"
	"sync"
)

type allowStopGuard struct{}

func (allowStopGuard) Allow(context.Context, string, string, string) error { return nil }

type mutableStopGuard struct {
	mu    sync.Mutex
	err   error
	calls [][3]string
}

func (guard *mutableStopGuard) Allow(_ context.Context, organizationID, tenantID, caseID string) error {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.calls = append(guard.calls, [3]string{organizationID, tenantID, caseID})
	return guard.err
}

func (guard *mutableStopGuard) set(err error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.err = err
}
