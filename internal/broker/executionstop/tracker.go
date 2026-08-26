// Package executionstop tracks active cooperative executor contexts and
// exposes them as an emergency-stop control.
package executionstop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"sync"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

var controlIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type StopGuard interface {
	Allow(context.Context, string, string, string) error
}

type Scope struct {
	OrganizationID string
	TenantID       string
	CaseID         string
}

type Execution struct {
	Context context.Context
	entry   *entry
}

type entry struct {
	tracker *Tracker
	id      string
	scope   Scope
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
}

type controlRun struct {
	done     chan struct{}
	evidence string
	err      error
}

type Tracker struct {
	id     string
	stop   StopGuard
	mu     sync.Mutex
	active map[string]*entry
	runs   map[string]*controlRun
}

func New(controlID string, stop StopGuard) (*Tracker, error) {
	if !controlIDPattern.MatchString(controlID) || stop == nil {
		return nil, stopcontract.NewError(stopcontract.InvalidInput, "execution_tracker_configuration_invalid")
	}
	return &Tracker{id: controlID, stop: stop, active: make(map[string]*entry), runs: make(map[string]*controlRun)}, nil
}

func (tracker *Tracker) ID() string { return tracker.id }
func (*Tracker) Kind() string       { return "cooperative" }

func (tracker *Tracker) Begin(ctx context.Context, executionID string, scope Scope) (*Execution, error) {
	if tracker == nil || tracker.stop == nil || executionID == "" || ctx == nil || validateScope(scope) != nil {
		return nil, stopcontract.NewError(stopcontract.InvalidInput, "execution_registration_invalid")
	}
	if err := tracker.Check(ctx, scope); err != nil {
		return nil, err
	}
	executionCtx, cancel := context.WithCancel(ctx)
	active := &entry{tracker: tracker, id: executionID, scope: scope, cancel: cancel, done: make(chan struct{})}
	tracker.mu.Lock()
	if tracker.active[executionID] != nil {
		tracker.mu.Unlock()
		cancel()
		return nil, stopcontract.NewError(stopcontract.Conflict, "execution_identity_conflict")
	}
	tracker.active[executionID] = active
	tracker.mu.Unlock()
	execution := &Execution{Context: executionCtx, entry: active}
	// Close the check/register-vs-activation race after registration.
	if err := tracker.Check(executionCtx, scope); err != nil {
		cancel()
		execution.Finish()
		return nil, err
	}
	return execution, nil
}

func (execution *Execution) Finish() {
	if execution == nil || execution.entry == nil {
		return
	}
	entry := execution.entry
	entry.once.Do(func() {
		entry.tracker.mu.Lock()
		if entry.tracker.active[entry.id] == entry {
			delete(entry.tracker.active, entry.id)
		}
		entry.tracker.mu.Unlock()
		entry.cancel()
		close(entry.done)
	})
}

func (tracker *Tracker) Check(ctx context.Context, scope Scope) error {
	if tracker == nil || tracker.stop == nil {
		return stopcontract.NewError(stopcontract.Unavailable, "execution_tracker_unavailable")
	}
	if ctx == nil || validateScope(scope) != nil {
		return stopcontract.NewError(stopcontract.InvalidInput, "execution_scope_invalid")
	}
	return tracker.stop.Allow(ctx, scope.OrganizationID, scope.TenantID, scope.CaseID)
}

func (tracker *Tracker) Apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	if tracker == nil || ctx == nil || request.Epoch == 0 || stopcontract.ValidateScope(request.Scope) != nil {
		return "", stopcontract.NewError(stopcontract.InvalidInput, "execution_control_request_invalid")
	}
	key := runKey(request)
	tracker.mu.Lock()
	if existing := tracker.runs[key]; existing != nil {
		tracker.mu.Unlock()
		select {
		case <-existing.done:
			return existing.evidence, existing.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	run := &controlRun{done: make(chan struct{})}
	tracker.runs[key] = run
	tracker.mu.Unlock()
	run.evidence, run.err = tracker.apply(ctx, request)
	close(run.done)
	return run.evidence, run.err
}

func (tracker *Tracker) apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	tracker.mu.Lock()
	entries := make([]*entry, 0)
	ids := make([]string, 0)
	for _, active := range tracker.active {
		if matches(active.scope, request.Scope) {
			entries, ids = append(entries, active), append(ids, active.id)
			active.cancel()
		}
	}
	tracker.mu.Unlock()
	for _, active := range entries {
		select {
		case <-active.done:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	sort.Strings(ids)
	value, _ := json.Marshal(struct {
		Scope      stopcontract.Scope
		Epoch      uint64
		Executions []string
	}{Scope: request.Scope, Epoch: request.Epoch, Executions: ids})
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateScope(scope Scope) error {
	return stopcontract.ValidateScope(stopcontract.Scope{Kind: "case", OrganizationID: scope.OrganizationID,
		TenantID: scope.TenantID, CaseID: scope.CaseID})
}

func matches(scope Scope, stop stopcontract.Scope) bool {
	return scope.OrganizationID == stop.OrganizationID && scope.TenantID == stop.TenantID &&
		(stop.Kind == "global" || scope.CaseID == stop.CaseID)
}

func runKey(request stopcontract.ControlRequest) string {
	scope := request.Scope
	return scope.Kind + "\x00" + scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID +
		"\x00" + strconv.FormatUint(request.Epoch, 10)
}
