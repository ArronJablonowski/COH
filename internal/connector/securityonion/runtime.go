package securityonion

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const maximumOQLRuntimeEntries = 4096

type validatedRuntimeOQL struct {
	queryDigest string
	query       queryconnector.Query
	validation  queryconnector.ValidatedValidation
	plan        ValidatedOQLPlan
	expiresAt   time.Time
}

type runtimeExecutionFlight struct {
	done             chan struct{}
	validationDigest string
	expiresAt        time.Time
	execution        queryconnector.ValidatedExecution
	err              error
}

type runtimeOQLJob struct {
	queryDigest string
	query       queryconnector.Query
	planDigest  string
	groupBy     []OQLColumn
	execution   queryconnector.ValidatedExecution
	result      EventQueryResult
	receipt     CallReceipt
	authority   queryconnector.AuthorityBinding
	expiresAt   time.Time
}

// OQLRuntime publishes synchronous Connect results through the shared opaque
// query lifecycle and never upgrades an unconfirmed result to complete.
type OQLRuntime struct {
	adapter  *Adapter
	compiler *OQLCompiler
	client   Client
	clock    Clock

	mu         sync.Mutex
	validated  map[string]validatedRuntimeOQL
	executions map[string]*runtimeExecutionFlight
	jobs       map[string]runtimeOQLJob
}

func NewOQLRuntime(adapter *Adapter, compiler *OQLCompiler, clock Clock) (*OQLRuntime, error) {
	if adapter == nil || compiler == nil || nilPort(clock) || nilPort(adapter.client) ||
		hashJSON("COH-SECURITY-ONION-CONFIG-BINDING-V1\x00", adapter.config) !=
			hashJSON("COH-SECURITY-ONION-CONFIG-BINDING-V1\x00", compiler.config) {
		return nil, invalid("securityonion_oql_runtime_configuration_invalid")
	}
	return &OQLRuntime{adapter: adapter, compiler: compiler, client: adapter.client, clock: clock,
		validated: make(map[string]validatedRuntimeOQL), executions: make(map[string]*runtimeExecutionFlight),
		jobs: make(map[string]runtimeOQLJob)}, nil
}

func (runtime *OQLRuntime) Probe(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if runtime == nil {
		return queryconnector.ValidatedCapability{}, invalid("securityonion_oql_runtime_required")
	}
	return runtime.adapter.Probe(ctx, scope, authority)
}

func (runtime *OQLRuntime) DiscoverSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if runtime == nil {
		return queryconnector.ValidatedSchemaPage{}, invalid("securityonion_oql_runtime_required")
	}
	return runtime.adapter.DiscoverSchema(ctx, request)
}

func (runtime *OQLRuntime) Validate(ctx context.Context,
	query queryconnector.ValidatedQuery) (queryconnector.ValidatedValidation, error) {
	if runtime == nil {
		return queryconnector.ValidatedValidation{}, invalid("securityonion_oql_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	now := runtime.clock.Now().UTC()
	queryValue := query.Value()
	if err := runtime.adapter.admitCapability(queryValue.Scope, queryValue.CapabilityDigest, now); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	schema, err := runtime.adapter.ResolveSchema(ctx, query)
	if err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	validation, plan, err := runtime.compiler.Validate(ctx, query, schema, runtime.adapter.qualification)
	if err != nil || plan == nil || validation.Value().Outcome != "accepted" {
		return validation, err
	}
	expiresAt, err := time.Parse(timestampLayout, queryValue.Deadline)
	qualificationExpiry, qualificationErr := runtime.adapter.qualificationExpiry(now)
	if err != nil || qualificationErr != nil || !now.Before(expiresAt) {
		return queryconnector.ValidatedValidation{}, denied("securityonion_oql_query_stale")
	}
	if qualificationExpiry.Before(expiresAt) {
		expiresAt = qualificationExpiry
	}
	runtime.mu.Lock()
	runtime.removeExpiredLocked(now)
	if _, exists := runtime.validated[query.Digest()]; !exists && len(runtime.validated) >= maximumOQLRuntimeEntries {
		runtime.mu.Unlock()
		return queryconnector.ValidatedValidation{}, denied("securityonion_oql_runtime_capacity_reached")
	}
	queryValue.NativeText = ""
	runtime.validated[query.Digest()] = validatedRuntimeOQL{queryDigest: query.Digest(), query: queryValue,
		validation: validation, plan: *plan, expiresAt: expiresAt}
	runtime.mu.Unlock()
	return validation, nil
}

func (runtime *OQLRuntime) Execute(ctx context.Context, query queryconnector.ValidatedQuery,
	validation queryconnector.ValidatedValidation) (queryconnector.ValidatedExecution, error) {
	if runtime == nil {
		return queryconnector.ValidatedExecution{}, invalid("securityonion_oql_runtime_required")
	}
	if err := queryconnector.AdmitExecution(ctx, query, validation); err != nil {
		return queryconnector.ValidatedExecution{}, err
	}
	now := runtime.clock.Now().UTC()
	runtime.mu.Lock()
	runtime.removeExpiredLocked(now)
	if pending, exists := runtime.executions[query.Digest()]; exists {
		if pending.validationDigest != validation.Digest() {
			runtime.mu.Unlock()
			return queryconnector.ValidatedExecution{}, conflict("securityonion_oql_validation_mismatch")
		}
		runtime.mu.Unlock()
		return runtime.waitExecution(ctx, pending)
	}
	if len(runtime.executions) >= maximumOQLRuntimeEntries || len(runtime.jobs) >= maximumOQLRuntimeEntries {
		runtime.mu.Unlock()
		return queryconnector.ValidatedExecution{}, denied("securityonion_oql_runtime_capacity_reached")
	}
	prepared, ok := runtime.validated[query.Digest()]
	if !ok || prepared.validation.Digest() != validation.Digest() ||
		prepared.plan.Digest() != validation.Value().ProvenanceDigest || !now.Before(prepared.expiresAt) {
		runtime.mu.Unlock()
		return queryconnector.ValidatedExecution{}, conflict("securityonion_oql_validation_mismatch")
	}
	pending := &runtimeExecutionFlight{done: make(chan struct{}), validationDigest: validation.Digest(), expiresAt: prepared.expiresAt}
	runtime.executions[query.Digest()] = pending
	runtime.mu.Unlock()

	executionContext, cancel := context.WithTimeout(ctx, prepared.expiresAt.Sub(now))
	defer cancel()
	execution, job, err := runtime.runExecute(executionContext, prepared, now)
	runtime.mu.Lock()
	pending.execution, pending.err = execution, err
	if err == nil {
		runtime.jobs[execution.Value().Handle.HandleID] = job
		delete(runtime.validated, query.Digest())
	} else {
		delete(runtime.executions, query.Digest())
	}
	close(pending.done)
	runtime.mu.Unlock()
	return execution, err
}

func (runtime *OQLRuntime) runExecute(ctx context.Context, prepared validatedRuntimeOQL,
	now time.Time) (queryconnector.ValidatedExecution, runtimeOQLJob, error) {
	queryValue := prepared.query
	if err := runtime.adapter.admitCapability(queryValue.Scope, queryValue.CapabilityDigest, now); err != nil {
		return queryconnector.ValidatedExecution{}, runtimeOQLJob{}, err
	}
	if len(queryValue.Scope.ResourceIDs) != 1 {
		return queryconnector.ValidatedExecution{}, runtimeOQLJob{}, denied("securityonion_oql_resource_scope_invalid")
	}
	binding := CallBinding{Scope: queryValue.Scope, Authority: queryValue.Authority,
		Operation: "securityonion.query_events", Targets: append([]string(nil), queryValue.Scope.ResourceIDs...)}
	result, receipt, err := runtime.client.QueryEvents(ctx, EventQueryRequest{Binding: binding,
		Qualification: runtime.adapter.qualification, Plan: prepared.plan})
	if err != nil {
		return queryconnector.ValidatedExecution{}, runtimeOQLJob{}, mapHTTPError(err)
	}
	if err := runtime.adapter.validateReceipt(receipt); err != nil || !digestPattern.MatchString(result.ResultDigest) {
		if err != nil {
			return queryconnector.ValidatedExecution{}, runtimeOQLJob{}, err
		}
		return queryconnector.ValidatedExecution{}, runtimeOQLJob{}, denied("securityonion_query_result_invalid")
	}
	handle := queryconnector.HandleRef{HandleID: deterministicUUID(now, prepared.plan.Digest()+result.ResultDigest),
		Kind: "query_job", SourceID: queryValue.Scope.SourceID,
		OpaqueDigest: hashJSON("COH-SECURITY-ONION-OQL-JOB-V1\x00", struct {
			Query, Plan, Result string
		}{prepared.queryDigest, prepared.plan.Digest(), result.ResultDigest}),
		IssuedAt: now.Format(timestampLayout), ExpiresAt: prepared.expiresAt.Format(timestampLayout)}
	attemptID := deterministicUUID(now, handle.OpaqueDigest+"attempt")
	executionValue := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: queryValue.QueryID, AttemptID: attemptID,
		Handle: handle, Outcome: "running", StartedAt: now.Format(timestampLayout),
		ProvenanceDigest: hashJSON("COH-SECURITY-ONION-OQL-EXECUTION-V1\x00", struct {
			Plan    string
			Receipt CallReceipt
		}{prepared.plan.Digest(), receipt})}
	encoded, _ := json.Marshal(executionValue)
	execution, err := queryconnector.DecodeExecution(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedExecution{}, runtimeOQLJob{}, err
	}
	return execution, runtimeOQLJob{queryDigest: prepared.queryDigest, query: queryValue,
		planDigest: prepared.plan.Digest(), groupBy: prepared.plan.Value().GroupBy,
		execution: execution, result: result, receipt: receipt,
		authority: queryValue.Authority, expiresAt: prepared.expiresAt}, nil
}

func (runtime *OQLRuntime) removeExpiredLocked(now time.Time) {
	for key, value := range runtime.validated {
		if !now.Before(value.expiresAt) {
			delete(runtime.validated, key)
		}
	}
	for key, value := range runtime.executions {
		if !now.Before(value.expiresAt) {
			delete(runtime.executions, key)
		}
	}
	for key, value := range runtime.jobs {
		if !now.Before(value.expiresAt) {
			delete(runtime.jobs, key)
		}
	}
}

func (runtime *OQLRuntime) waitExecution(ctx context.Context,
	pending *runtimeExecutionFlight) (queryconnector.ValidatedExecution, error) {
	select {
	case <-ctx.Done():
		return queryconnector.ValidatedExecution{}, contextError(ctx)
	case <-pending.done:
		if err := contextError(ctx); err != nil {
			return queryconnector.ValidatedExecution{}, err
		}
		return pending.execution, pending.err
	}
}
