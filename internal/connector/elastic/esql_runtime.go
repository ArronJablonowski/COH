package elastic

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticesql"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const maximumESQLRuntimeEntries = 4096

type SchemaResolver interface {
	ResolveSchema(context.Context, queryconnector.ValidatedQuery) (queryconnector.ValidatedSchemaPage, error)
}

type validatedESQL struct {
	queryDigest string
	query       queryconnector.Query
	validation  queryconnector.ValidatedValidation
	plan        elasticesql.ValidatedPlan
	expiresAt   time.Time
}

type executionFlight struct {
	done             chan struct{}
	validationDigest string
	expiresAt        time.Time
	execution        queryconnector.ValidatedExecution
	err              error
}

type esqlJob struct {
	queryDigest string
	query       queryconnector.Query
	planDigest  string
	execution   queryconnector.ValidatedExecution
	result      ESQLResult
	receipts    []CallReceipt
	authority   queryconnector.AuthorityBinding
	issuedAt    time.Time
	expiresAt   time.Time
}

// ESQLRuntime composes CYB-93 discovery with the bounded ES|QL compiler and the
// shared query connector lifecycle. Synchronous vendor results remain behind
// an opaque job handle until Poll releases the single bounded page.
type ESQLRuntime struct {
	discovery *Adapter
	compiler  *elasticesql.Compiler
	schemas   SchemaResolver
	client    ESQLClient
	clock     Clock

	mu         sync.Mutex
	validated  map[string]validatedESQL
	executions map[string]*executionFlight
	jobs       map[string]esqlJob
}

func NewESQLRuntime(discovery *Adapter, compiler *elasticesql.Compiler, schemas SchemaResolver,
	client ESQLClient, clock Clock) (*ESQLRuntime, error) {
	if discovery == nil || compiler == nil || nilPort(schemas) || nilPort(client) || nilPort(clock) {
		return nil, invalid("elastic_esql_runtime_configuration_invalid")
	}
	return &ESQLRuntime{discovery: discovery, compiler: compiler, schemas: schemas, client: client, clock: clock,
		validated: make(map[string]validatedESQL), executions: make(map[string]*executionFlight), jobs: make(map[string]esqlJob)}, nil
}

func (runtime *ESQLRuntime) Probe(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if runtime == nil {
		return queryconnector.ValidatedCapability{}, invalid("elastic_esql_runtime_required")
	}
	return runtime.discovery.Probe(ctx, scope, authority)
}

func (runtime *ESQLRuntime) DiscoverSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if runtime == nil {
		return queryconnector.ValidatedSchemaPage{}, invalid("elastic_esql_runtime_required")
	}
	return runtime.discovery.DiscoverSchema(ctx, request)
}

func (runtime *ESQLRuntime) Validate(ctx context.Context,
	query queryconnector.ValidatedQuery) (queryconnector.ValidatedValidation, error) {
	if runtime == nil {
		return queryconnector.ValidatedValidation{}, invalid("elastic_esql_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	now := runtime.clock.Now().UTC()
	queryValue := query.Value()
	if err := runtime.discovery.admitCapability(queryconnector.SchemaRequest{Scope: queryValue.Scope,
		CapabilityDigest: queryValue.CapabilityDigest}, now); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	schema, err := runtime.schemas.ResolveSchema(ctx, query)
	if err != nil {
		return queryconnector.ValidatedValidation{}, mapClientError(err)
	}
	validation, plan, err := runtime.compiler.Validate(ctx, query, schema)
	if err != nil || plan == nil || validation.Value().Outcome != "accepted" {
		return validation, err
	}
	expiresAt, err := time.Parse(timestampLayout, queryValue.Deadline)
	if err != nil || !now.Before(expiresAt) {
		return queryconnector.ValidatedValidation{}, denied("elastic_esql_query_stale")
	}
	runtime.mu.Lock()
	runtime.removeExpiredLocked(now)
	if _, exists := runtime.validated[query.Digest()]; !exists && len(runtime.validated) >= maximumESQLRuntimeEntries {
		runtime.mu.Unlock()
		return queryconnector.ValidatedValidation{}, denied("elastic_esql_runtime_capacity_reached")
	}
	queryValue.NativeText = ""
	runtime.validated[query.Digest()] = validatedESQL{queryDigest: query.Digest(), query: queryValue,
		validation: validation, plan: *plan, expiresAt: expiresAt}
	runtime.mu.Unlock()
	return validation, nil
}

func (runtime *ESQLRuntime) Execute(ctx context.Context, query queryconnector.ValidatedQuery,
	validation queryconnector.ValidatedValidation) (queryconnector.ValidatedExecution, error) {
	if runtime == nil {
		return queryconnector.ValidatedExecution{}, invalid("elastic_esql_runtime_required")
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
			return queryconnector.ValidatedExecution{}, conflict("elastic_esql_validation_mismatch")
		}
		runtime.mu.Unlock()
		return waitExecution(ctx, pending)
	}
	if len(runtime.executions) >= maximumESQLRuntimeEntries || len(runtime.jobs) >= maximumESQLRuntimeEntries {
		runtime.mu.Unlock()
		return queryconnector.ValidatedExecution{}, denied("elastic_esql_runtime_capacity_reached")
	}
	prepared, ok := runtime.validated[query.Digest()]
	if !ok || prepared.validation.Digest() != validation.Digest() ||
		prepared.plan.Digest() != validation.Value().ProvenanceDigest || !now.Before(prepared.expiresAt) {
		runtime.mu.Unlock()
		return queryconnector.ValidatedExecution{}, conflict("elastic_esql_validation_mismatch")
	}
	pending := &executionFlight{done: make(chan struct{}), validationDigest: validation.Digest(), expiresAt: prepared.expiresAt}
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

func (runtime *ESQLRuntime) runExecute(ctx context.Context, prepared validatedESQL,
	now time.Time) (queryconnector.ValidatedExecution, esqlJob, error) {
	queryValue := prepared.query
	if err := runtime.discovery.admitCapability(queryconnector.SchemaRequest{Scope: queryValue.Scope,
		CapabilityDigest: queryValue.CapabilityDigest}, now); err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	resources, err := validateScope(runtime.discovery.config, queryValue.Scope)
	if err != nil || len(resources) != 1 {
		return queryconnector.ValidatedExecution{}, esqlJob{}, denied("elastic_esql_resource_scope_invalid")
	}
	inspectBinding := CallBinding{Scope: queryValue.Scope, Authority: queryValue.Authority,
		Operation: "elastic.inspect", Targets: []string{resources[0].ID}}
	identity, inspectReceipt, err := runtime.discovery.client.Inspect(ctx, inspectBinding)
	if err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, mapClientError(err)
	}
	if err := validateIdentity(runtime.discovery.config, identity); err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	if err := validateReceipt(runtime.discovery.config, inspectReceipt); err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	resolved, resolveReceipt, err := runtime.discovery.client.Resolve(ctx, ResolveRequest{Binding: CallBinding{
		Scope: queryValue.Scope, Authority: queryValue.Authority, Operation: "elastic.resolve", Targets: []string{resources[0].ID}},
		Expression: resources[0].Expression, Expand: "open"})
	if err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, mapClientError(err)
	}
	if err := validateReceipt(runtime.discovery.config, resolveReceipt); err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	indices, err := normalizeResolution(resources[0], resolved)
	if err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	result, executeReceipt, err := runtime.client.ExecuteESQL(ctx, ESQLRequest{Binding: CallBinding{Scope: queryValue.Scope,
		Authority: queryValue.Authority, Operation: "elastic.esql", Targets: indices}, Indices: indices, Plan: prepared.plan})
	if err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	if err := validateReceipt(runtime.discovery.config, executeReceipt); err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	handle := queryconnector.HandleRef{HandleID: deterministicUUID(now, prepared.plan.Digest()+result.ResultDigest),
		Kind: "query_job", SourceID: queryValue.Scope.SourceID,
		OpaqueDigest: digest("COH-ELASTIC-ESQL-JOB-V1\x00", struct {
			Query  string
			Plan   string
			Result string
		}{prepared.queryDigest, prepared.plan.Digest(), result.ResultDigest}),
		IssuedAt: now.Format(timestampLayout), ExpiresAt: prepared.expiresAt.Format(timestampLayout)}
	attemptID := deterministicUUID(now, handle.OpaqueDigest+"attempt")
	executionValue := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: queryValue.QueryID, AttemptID: attemptID,
		Handle: handle, Outcome: "running", StartedAt: now.Format(timestampLayout),
		ProvenanceDigest: digest("COH-ELASTIC-ESQL-EXECUTION-V1\x00", struct {
			Plan     string
			Identity ClusterIdentity
			Receipts []CallReceipt
		}{prepared.plan.Digest(), identity, []CallReceipt{inspectReceipt, resolveReceipt, executeReceipt}})}
	encoded, _ := json.Marshal(executionValue)
	execution, err := queryconnector.DecodeExecution(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedExecution{}, esqlJob{}, err
	}
	job := esqlJob{queryDigest: prepared.queryDigest, query: queryValue, planDigest: prepared.plan.Digest(),
		execution: execution, result: result, receipts: []CallReceipt{inspectReceipt, resolveReceipt, executeReceipt},
		authority: queryValue.Authority, issuedAt: now, expiresAt: prepared.expiresAt}
	return execution, job, nil
}

func (runtime *ESQLRuntime) Poll(ctx context.Context,
	request queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	if runtime == nil {
		return queryconnector.ValidatedPoll{}, invalid("elastic_esql_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	now := runtime.clock.Now().UTC()
	runtime.mu.Lock()
	runtime.removeExpiredLocked(now)
	job, ok := runtime.jobs[request.Handle.HandleID]
	runtime.mu.Unlock()
	if !ok {
		return queryconnector.ValidatedPoll{}, queryconnector.NewError(queryconnector.Unavailable, "elastic_esql_job_unavailable", nil)
	}
	if request.Handle != job.execution.Value().Handle || request.QueryID != job.query.QueryID ||
		request.AttemptID != job.execution.Value().AttemptID || request.Authority != job.authority {
		return queryconnector.ValidatedPoll{}, conflict("elastic_esql_job_mismatch")
	}
	rowsBytes, _ := json.Marshal(job.result.Rows)
	if uint64(len(rowsBytes)) > job.query.Limits.MaximumBytes {
		return queryconnector.ValidatedPoll{}, denied("elastic_esql_result_oversized")
	}
	rowsScanned := max(job.result.DocumentsFound, uint64(len(job.result.Rows)))
	statistics := queryconnector.Statistics{RowsScanned: rowsScanned, RowsReturned: uint64(len(job.result.Rows)),
		BytesReturned: uint64(len(rowsBytes)), DurationMillis: job.result.TookMillis, PagesReturned: 1, SlicesCompleted: 1}
	completeness := queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
	page := queryconnector.ResultPage{SchemaVersion: queryconnector.PageSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, PageNumber: 1, Rows: cloneRows(job.result.Rows),
		ResultDigest: job.result.ResultDigest, Completeness: completeness, Statistics: statistics,
		ProvenanceDigest: digest("COH-ELASTIC-ESQL-PAGE-V1\x00", struct {
			Job      string
			Plan     string
			Result   string
			Receipts []CallReceipt
		}{request.Handle.OpaqueDigest, job.planDigest, job.result.ResultDigest, job.receipts})}
	pollValue := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: "completed", Page: &page,
		Statistics: statistics, Completeness: completeness,
		ProvenanceDigest: digest("COH-ELASTIC-ESQL-POLL-V1\x00", page.ProvenanceDigest)}
	encoded, _ := json.Marshal(pollValue)
	return queryconnector.DecodePoll(ctx, encoded)
}

func (runtime *ESQLRuntime) NextPage(ctx context.Context,
	_ queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	return queryconnector.ValidatedPage{}, unsupported("elastic_esql_single_page")
}

func (runtime *ESQLRuntime) Cancel(ctx context.Context,
	request queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	if runtime == nil {
		return queryconnector.ValidatedCancellation{}, invalid("elastic_esql_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCancellation{}, err
	}
	now := runtime.clock.Now().UTC()
	runtime.mu.Lock()
	job, ok := runtime.jobs[request.Handle.HandleID]
	runtime.mu.Unlock()
	if !ok {
		value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
			ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
			Outcome: "uncertain", RequestedAt: request.RequestedAt,
			ProvenanceDigest: digest("COH-ELASTIC-ESQL-CANCEL-UNKNOWN-V1\x00", struct {
				Handle    string
				Requested string
			}{request.Handle.OpaqueDigest, request.RequestedAt})}
		encoded, _ := json.Marshal(value)
		return queryconnector.DecodeCancellation(ctx, encoded)
	}
	if request.Handle != job.execution.Value().Handle || request.QueryID != job.query.QueryID ||
		request.AttemptID != job.execution.Value().AttemptID || request.Authority != job.authority {
		return queryconnector.ValidatedCancellation{}, conflict("elastic_esql_job_mismatch")
	}
	confirmed := now.Format(timestampLayout)
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
		Outcome: "confirmed", RequestedAt: request.RequestedAt, ConfirmedAt: &confirmed,
		ProvenanceDigest: digest("COH-ELASTIC-ESQL-CANCEL-V1\x00", struct {
			Job       string
			Requested string
			Confirmed string
		}{request.Handle.OpaqueDigest, request.RequestedAt, confirmed})}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodeCancellation(ctx, encoded)
}

func (runtime *ESQLRuntime) removeExpiredLocked(now time.Time) {
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

func waitExecution(ctx context.Context, pending *executionFlight) (queryconnector.ValidatedExecution, error) {
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

func cloneRows(rows []map[string]any) []map[string]any {
	cloned := make([]map[string]any, len(rows))
	for index, row := range rows {
		cloned[index] = make(map[string]any, len(row))
		for key, value := range row {
			cloned[index][key] = value
		}
	}
	return cloned
}

var _ queryconnector.Connector = (*ESQLRuntime)(nil)
