package queryruntime

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type managedSession struct {
	mu                 sync.Mutex
	value              Session
	query              queryconnector.ValidatedQuery
	authority          queryconnector.AuthorityBinding
	jobHandle          queryconnector.HandleRef
	pageHandle         *queryconnector.HandleRef
	partial            bool
	lastOperation      string
	lastInputDigest    string
	lastResult         Result
	lastErr            error
	cancellationKey    string
	cancellationReason string
	cancellationDigest string
	pollDelay          time.Duration
	nextPollAt         time.Time
}

type Controller struct {
	config   Config
	adapter  Adapter
	rate     RateGate
	recorder Recorder
	clock    Clock

	mu       sync.RWMutex
	sessions map[string]*managedSession
}

func New(config Config, adapter Adapter, rate RateGate, recorder Recorder, clock Clock) (*Controller, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if nilPort(adapter) || nilPort(rate) || nilPort(recorder) || nilPort(clock) {
		return nil, newError(InvalidInput, "dependencies_required", nil)
	}
	return &Controller{config: config, adapter: adapter, rate: rate, recorder: recorder,
		clock: clock, sessions: make(map[string]*managedSession)}, nil
}

func (controller *Controller) Start(ctx context.Context, request StartRequest) (Session, error) {
	if controller == nil {
		return Session{}, newError(InvalidInput, "controller_required", nil)
	}
	if err := contextError(ctx); err != nil {
		return Session{}, err
	}
	now := controller.clock.Now().UTC()
	profile, err := controller.profile(request.Mode)
	if err != nil {
		return Session{}, err
	}
	query := request.Admission.Query
	decision := request.Admission.Decision
	execution := request.Execution
	if query.Digest() == "" || execution.Digest() == "" {
		return Session{}, newError(InvalidInput, "start_records_required", nil)
	}
	if _, err := querybounds.VerifyDecision(decision); err != nil || decision.Outcome != "allowed" ||
		decision.QueryID != query.Value().QueryID || decision.QueryDigest != query.Digest() {
		return Session{}, newError(Denied, "bounds_admission_invalid", err)
	}
	queryValue, executionValue := query.Value(), execution.Value()
	if executionValue.QueryID != queryValue.QueryID || executionValue.Handle.SourceID != queryValue.Scope.SourceID ||
		!oneOf(executionValue.Outcome, "queued", "running") {
		return Session{}, newError(Conflict, "execution_mismatch", nil)
	}
	deadline, deadlineErr := time.Parse(timestampLayout, queryValue.Deadline)
	started, startedErr := time.Parse(timestampLayout, executionValue.StartedAt)
	if deadlineErr != nil || startedErr != nil || !now.Before(deadline) || started.After(now) ||
		!handleCurrent(executionValue.Handle, now) {
		return Session{}, newError(Denied, "execution_not_current", nil)
	}
	effective := minimumLimits(queryValue.Limits, profile.Limits)
	handleDigest, err := canonicalDigest(handleDigestDomain, executionValue.Handle)
	if err != nil {
		return Session{}, err
	}
	session := Session{SchemaVersion: SessionSchemaVersion, ContractVersion: ContractVersion,
		SessionID: executionValue.AttemptID, Revision: 1, QueryID: queryValue.QueryID, QueryDigest: query.Digest(),
		BoundsDecisionDigest: decision.DecisionDigest, ExecutionDigest: execution.Digest(), AttemptID: executionValue.AttemptID,
		OrganizationID: queryValue.Scope.OrganizationID, TenantID: queryValue.Scope.TenantID, CaseID: queryValue.Scope.CaseID,
		ActorID: queryValue.Authority.ActorID, SourceID: queryValue.Scope.SourceID, Mode: profile.Mode,
		EffectiveLimits: effective, Status: "running", ReasonCode: "execution_" + executionValue.Outcome,
		NextPageNumber: 1, PollDelayMillis: uint64(profile.MinimumPollInterval / time.Millisecond),
		NextPollAt: now.Format(timestampLayout), JobHandleDigest: handleDigest,
		VendorProvenanceDigest: executionValue.ProvenanceDigest,
		StartedAt:              executionValue.StartedAt, UpdatedAt: now.Format(timestampLayout), Deadline: queryValue.Deadline}
	finalized, err := finalizeSession(session)
	if err != nil {
		return Session{}, err
	}
	managed := &managedSession{value: finalized, query: query, authority: queryValue.Authority,
		jobHandle: executionValue.Handle, pollDelay: profile.MinimumPollInterval, nextPollAt: now}
	controller.mu.Lock()
	if existing := controller.sessions[session.SessionID]; existing != nil {
		controller.mu.Unlock()
		existing.mu.Lock()
		defer existing.mu.Unlock()
		if existing.value.QueryDigest == query.Digest() && existing.value.ExecutionDigest == execution.Digest() &&
			existing.value.Mode == request.Mode {
			return existing.value, nil
		}
		return Session{}, newError(Conflict, "session_exists", nil)
	}
	if len(controller.sessions) >= controller.config.MaximumSessions {
		controller.mu.Unlock()
		return Session{}, newError(Denied, "session_capacity_reached", nil)
	}
	if err := controller.record(ctx, finalized); err != nil {
		controller.mu.Unlock()
		return Session{}, err
	}
	controller.sessions[session.SessionID] = managed
	controller.mu.Unlock()
	return finalized, nil
}

func (controller *Controller) Get(ctx context.Context, reference SessionRef) (Session, error) {
	if err := contextError(ctx); err != nil {
		return Session{}, err
	}
	managed, err := controller.lookup(reference.SessionID)
	if err != nil {
		return Session{}, err
	}
	managed.mu.Lock()
	defer managed.mu.Unlock()
	if reference.SessionDigest != managed.value.SessionDigest {
		return Session{}, newError(Conflict, "session_revision_mismatch", nil)
	}
	return managed.value, VerifySession(managed.value)
}

// Release removes only terminal process-local state after its redacted final
// transition has been recorded. It cannot erase durable evidence.
func (controller *Controller) Release(ctx context.Context, reference SessionRef) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	managed, err := controller.lookup(reference.SessionID)
	if err != nil {
		return err
	}
	managed.mu.Lock()
	defer managed.mu.Unlock()
	if reference.SessionDigest != managed.value.SessionDigest {
		return newError(Conflict, "session_revision_mismatch", nil)
	}
	if active(managed.value.Status) {
		return newError(Denied, "session_active", nil)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.sessions[reference.SessionID] == managed {
		delete(controller.sessions, reference.SessionID)
	}
	return nil
}

func (controller *Controller) profile(mode string) (Profile, error) {
	switch mode {
	case "interactive":
		return controller.config.Interactive, nil
	case "export":
		return controller.config.Export, nil
	default:
		return Profile{}, newError(InvalidInput, "profile_invalid", nil)
	}
}

func (controller *Controller) lookup(sessionID string) (*managedSession, error) {
	if controller == nil || !uuidPattern.MatchString(sessionID) {
		return nil, newError(InvalidInput, "session_id_invalid", nil)
	}
	controller.mu.RLock()
	managed := controller.sessions[sessionID]
	controller.mu.RUnlock()
	if managed == nil {
		return nil, newError(Denied, "session_not_found", nil)
	}
	return managed, nil
}

func (controller *Controller) record(ctx context.Context, session Session) error {
	parent := context.Background()
	if ctx != nil {
		parent = context.WithoutCancel(ctx)
	}
	recordContext, cancel := context.WithTimeout(parent, controller.config.RecordWait)
	defer cancel()
	if err := controller.recorder.RecordQuerySession(recordContext, session); err != nil {
		return newError(Unavailable, "record_unavailable", err)
	}
	return nil
}

func minimumLimits(left, right queryconnector.Limits) queryconnector.Limits {
	return queryconnector.Limits{MaximumRows: min(left.MaximumRows, right.MaximumRows),
		MaximumBytes:          min(left.MaximumBytes, right.MaximumBytes),
		MaximumDurationMillis: min(left.MaximumDurationMillis, right.MaximumDurationMillis),
		MaximumPages:          min(left.MaximumPages, right.MaximumPages), MaximumSlices: min(left.MaximumSlices, right.MaximumSlices),
		MaximumCostMillionths: min(left.MaximumCostMillionths, right.MaximumCostMillionths),
		RequestsPerMinute:     min(left.RequestsPerMinute, right.RequestsPerMinute)}
}

func handleCurrent(handle queryconnector.HandleRef, now time.Time) bool {
	issued, issuedErr := time.Parse(timestampLayout, handle.IssuedAt)
	expires, expiresErr := time.Parse(timestampLayout, handle.ExpiresAt)
	return issuedErr == nil && expiresErr == nil && !now.Before(issued) && now.Before(expires)
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return slices.Contains([]reflect.Kind{reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice}, reflected.Kind()) && reflected.IsNil()
}
