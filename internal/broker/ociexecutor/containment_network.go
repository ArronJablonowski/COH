package ociexecutor

import (
	"context"
	"sort"
	"strconv"
	"sync"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

const networkContainmentControlID = "runner-network"

type StopGuard interface {
	Allow(context.Context, string, string, string) error
}

// ContainmentNetworkBroker tracks every broker-owned network lease so an
// emergency stop can cut affected egress independently of runner cooperation.
type ContainmentNetworkBroker struct {
	inner  NetworkBroker
	stop   StopGuard
	mu     sync.Mutex
	active map[string]*activeNetworkLease
	runs   map[string]*containmentRun
}

type activeNetworkLease struct {
	request NetworkRequest
	once    sync.Once
	done    chan struct{}
	err     error
	cleanup func() error
}

type containmentRun struct {
	done     chan struct{}
	evidence string
	err      error
}

func NewContainmentNetworkBroker(inner NetworkBroker, stop StopGuard) (*ContainmentNetworkBroker, error) {
	if inner == nil || stop == nil {
		return nil, NewError(InvalidInput, "containment_network_configuration")
	}
	return &ContainmentNetworkBroker{inner: inner, stop: stop, active: make(map[string]*activeNetworkLease),
		runs: make(map[string]*containmentRun)}, nil
}

func (*ContainmentNetworkBroker) ID() string   { return networkContainmentControlID }
func (*ContainmentNetworkBroker) Kind() string { return "egress" }

func (broker *ContainmentNetworkBroker) Acquire(ctx context.Context, request NetworkRequest) (NetworkLease, error) {
	if broker == nil || broker.inner == nil || broker.stop == nil {
		return NetworkLease{}, NewError(Unavailable, "containment_network_unavailable")
	}
	if err := broker.allow(ctx, request); err != nil {
		return NetworkLease{}, err
	}
	lease, err := broker.inner.Acquire(ctx, request)
	if err != nil {
		return NetworkLease{}, err
	}
	if lease.Cleanup == nil || lease.LeaseID == "" {
		if lease.Cleanup != nil {
			_ = lease.Cleanup()
		}
		return NetworkLease{}, NewError(Denied, "network_lease_invalid")
	}
	entry := &activeNetworkLease{request: request, done: make(chan struct{}), cleanup: lease.Cleanup}
	entry.cleanup = broker.trackedCleanup(lease.LeaseID, entry, lease.Cleanup)
	broker.mu.Lock()
	if _, exists := broker.active[lease.LeaseID]; exists {
		broker.mu.Unlock()
		_ = entry.close()
		return NetworkLease{}, NewError(Conflict, "network_lease_conflict")
	}
	broker.active[lease.LeaseID] = entry
	broker.mu.Unlock()
	lease.Cleanup = entry.close

	// This second authoritative read closes the race between the first read,
	// lease acquisition, and an activation snapshot.
	if err := broker.allow(ctx, request); err != nil {
		cleanupErr := entry.close()
		if cleanupErr != nil {
			return NetworkLease{}, NewError(Unavailable, "network_cleanup_failed")
		}
		return NetworkLease{}, err
	}
	return lease, nil
}

func (broker *ContainmentNetworkBroker) Apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	if broker == nil || request.Epoch == 0 || stopcontract.ValidateScope(request.Scope) != nil {
		return "", NewError(InvalidInput, "containment_request_invalid")
	}
	key := stopRunKey(request)
	broker.mu.Lock()
	if existing := broker.runs[key]; existing != nil {
		broker.mu.Unlock()
		select {
		case <-existing.done:
			return existing.evidence, existing.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	run := &containmentRun{done: make(chan struct{})}
	broker.runs[key] = run
	broker.mu.Unlock()
	run.evidence, run.err = broker.applyOnce(ctx, request)
	close(run.done)
	return run.evidence, run.err
}

func (broker *ContainmentNetworkBroker) applyOnce(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	broker.mu.Lock()
	keys := make([]string, 0)
	entries := make([]*activeNetworkLease, 0)
	for key, entry := range broker.active {
		if matchesStopScope(entry.request, request.Scope) {
			keys, entries = append(keys, key), append(entries, entry)
		}
	}
	broker.mu.Unlock()
	sort.Strings(keys)

	results := make(chan error, len(entries))
	for _, entry := range entries {
		go func(entry *activeNetworkLease) { results <- entry.close() }(entry)
	}
	for range entries {
		select {
		case err := <-results:
			if err != nil {
				return "", NewError(Unavailable, "network_cleanup_failed")
			}
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	evidence := struct {
		Scope    stopcontract.Scope
		Epoch    uint64
		LeaseIDs []string
	}{Scope: request.Scope, Epoch: request.Epoch, LeaseIDs: keys}
	return digestBytes(canonicalBytes(evidence)), nil
}

func stopRunKey(request stopcontract.ControlRequest) string {
	scope := request.Scope
	return scope.Kind + "\x00" + scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID +
		"\x00" + strconv.FormatUint(request.Epoch, 10)
}

func (broker *ContainmentNetworkBroker) trackedCleanup(key string, entry *activeNetworkLease, cleanup func() error) func() error {
	return func() error {
		defer func() {
			broker.mu.Lock()
			if broker.active[key] == entry {
				delete(broker.active, key)
			}
			broker.mu.Unlock()
		}()
		return cleanup()
	}
}

func (entry *activeNetworkLease) close() error {
	entry.once.Do(func() {
		entry.err = entry.cleanup()
		close(entry.done)
	})
	<-entry.done
	return entry.err
}

func (broker *ContainmentNetworkBroker) allow(ctx context.Context, request NetworkRequest) error {
	err := broker.stop.Allow(ctx, request.OrganizationID, request.TenantID, request.CaseID)
	if err == nil {
		return nil
	}
	switch stopcontract.Code(err) {
	case stopcontract.Denied:
		return NewError(Denied, "emergency_stop_active")
	case stopcontract.Canceled:
		return NewError(Canceled, "stop_check_canceled")
	case stopcontract.Timeout:
		return NewError(Timeout, "stop_check_timeout")
	default:
		return NewError(Unavailable, "stop_state_unavailable")
	}
}

func matchesStopScope(request NetworkRequest, scope stopcontract.Scope) bool {
	return request.OrganizationID == scope.OrganizationID && request.TenantID == scope.TenantID &&
		(scope.Kind == "global" || request.CaseID == scope.CaseID)
}

var _ NetworkBroker = (*ContainmentNetworkBroker)(nil)
var _ interface {
	ID() string
	Kind() string
	Apply(context.Context, stopcontract.ControlRequest) (string, error)
} = (*ContainmentNetworkBroker)(nil)
