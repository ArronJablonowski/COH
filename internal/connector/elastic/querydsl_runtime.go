package elastic

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticquerydsl"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const maximumQueryDSLRuntimeEntries = 4096

type validatedQueryDSL struct {
	queryDigest string
	query       queryconnector.Query
	validation  queryconnector.ValidatedValidation
	plan        elasticquerydsl.ValidatedPlan
	indices     []string
	receipts    []CallReceipt
	expiresAt   time.Time
}

type pageReplay struct {
	handle queryconnector.HandleRef
	page   queryconnector.ValidatedPage
}

type queryDSLJob struct {
	mu sync.Mutex

	queryDigest  string
	query        queryconnector.Query
	plan         elasticquerydsl.ValidatedPlan
	execution    queryconnector.ValidatedExecution
	indices      []string
	authority    queryconnector.AuthorityBinding
	baseReceipts []CallReceipt
	expiresAt    time.Time

	pitID          string
	pitDigest      string
	closed         bool
	pageNumber     uint32
	rowsScanned    uint64
	rowsReturned   uint64
	bytesReturned  uint64
	durationMillis uint64
	searchAfter    []any
	nextHandle     *queryconnector.HandleRef
	firstPoll      *queryconnector.ValidatedPoll
	replays        map[string]pageReplay
}

type QueryDSLRuntime struct {
	discovery *Adapter
	compiler  *elasticquerydsl.Compiler
	schemas   SchemaResolver
	client    QueryDSLClient
	clock     Clock

	mu         sync.Mutex
	validated  map[string]validatedQueryDSL
	executions map[string]*executionFlight
	jobs       map[string]*queryDSLJob
}

func NewQueryDSLRuntime(discovery *Adapter, compiler *elasticquerydsl.Compiler, schemas SchemaResolver,
	client QueryDSLClient, clock Clock) (*QueryDSLRuntime, error) {
	if discovery == nil || compiler == nil || nilPort(schemas) || nilPort(client) || nilPort(clock) {
		return nil, invalid("elastic_querydsl_runtime_configuration_invalid")
	}
	return &QueryDSLRuntime{discovery: discovery, compiler: compiler, schemas: schemas, client: client, clock: clock,
		validated: make(map[string]validatedQueryDSL), executions: make(map[string]*executionFlight),
		jobs: make(map[string]*queryDSLJob)}, nil
}

func (runtime *QueryDSLRuntime) Probe(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if runtime == nil {
		return queryconnector.ValidatedCapability{}, invalid("elastic_querydsl_runtime_required")
	}
	return runtime.discovery.Probe(ctx, scope, authority)
}

func (runtime *QueryDSLRuntime) DiscoverSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if runtime == nil {
		return queryconnector.ValidatedSchemaPage{}, invalid("elastic_querydsl_runtime_required")
	}
	return runtime.discovery.DiscoverSchema(ctx, request)
}

func (runtime *QueryDSLRuntime) Validate(ctx context.Context,
	query queryconnector.ValidatedQuery) (queryconnector.ValidatedValidation, error) {
	if runtime == nil {
		return queryconnector.ValidatedValidation{}, invalid("elastic_querydsl_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	now, queryValue := runtime.clock.Now().UTC(), query.Value()
	if err := runtime.discovery.admitCapability(queryconnector.SchemaRequest{Scope: queryValue.Scope,
		CapabilityDigest: queryValue.CapabilityDigest}, now); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	schema, err := runtime.schemas.ResolveSchema(ctx, query)
	if err != nil {
		return queryconnector.ValidatedValidation{}, mapClientError(err)
	}
	localValidation, plan, err := runtime.compiler.Validate(ctx, query, schema)
	if err != nil || plan == nil || localValidation.Value().Outcome != "accepted" {
		return localValidation, err
	}
	expiresAt, err := time.Parse(timestampLayout, queryValue.Deadline)
	if err != nil || !now.Before(expiresAt) {
		return queryconnector.ValidatedValidation{}, denied("elastic_querydsl_query_stale")
	}
	identity, indices, receipts, err := runtime.resolveTargets(ctx, queryValue, now)
	if err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	vendorResult, vendorReceipt, err := runtime.client.ValidateQuery(ctx, QueryValidationRequest{Binding: CallBinding{
		Scope: queryValue.Scope, Authority: queryValue.Authority, Operation: "elastic.query.validate", Targets: indices},
		Indices: indices, Plan: *plan})
	if err != nil {
		if queryconnector.Code(err) == queryconnector.Denied {
			return queryDSLValidation(ctx, query, "denied", []string{queryconnector.Reason(err)},
				digest("COH-ELASTIC-QUERY-DSL-VENDOR-DENIAL-V1\x00", struct{ Plan, Reason string }{plan.Digest(), queryconnector.Reason(err)})), nil
		}
		return queryconnector.ValidatedValidation{}, err
	}
	if !vendorResult.Valid || validateReceipt(runtime.discovery.config, vendorReceipt) != nil {
		return queryconnector.ValidatedValidation{}, conflict("elastic_querydsl_validation_receipt_invalid")
	}
	receipts = append(receipts, vendorReceipt)
	provenance := digest("COH-ELASTIC-QUERY-DSL-VALIDATION-V1\x00", struct {
		Plan     string
		Identity ClusterIdentity
		Indices  []string
		Vendor   string
		Receipts []CallReceipt
	}{plan.Digest(), identity, indices, vendorResult.ResultDigest, receipts})
	validation := queryDSLValidation(ctx, query, "accepted", nil, provenance)
	runtime.mu.Lock()
	runtime.removeExpiredLocked(now)
	if _, exists := runtime.validated[query.Digest()]; !exists && len(runtime.validated) >= maximumQueryDSLRuntimeEntries {
		runtime.mu.Unlock()
		return queryconnector.ValidatedValidation{}, denied("elastic_querydsl_runtime_capacity_reached")
	}
	queryValue.NativeText = ""
	runtime.validated[query.Digest()] = validatedQueryDSL{queryDigest: query.Digest(), query: queryValue,
		validation: validation, plan: *plan, indices: append([]string(nil), indices...), receipts: receipts, expiresAt: expiresAt}
	runtime.mu.Unlock()
	return validation, nil
}

func (runtime *QueryDSLRuntime) Execute(ctx context.Context, query queryconnector.ValidatedQuery,
	validation queryconnector.ValidatedValidation) (queryconnector.ValidatedExecution, error) {
	if runtime == nil {
		return queryconnector.ValidatedExecution{}, invalid("elastic_querydsl_runtime_required")
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
			return queryconnector.ValidatedExecution{}, conflict("elastic_querydsl_validation_mismatch")
		}
		runtime.mu.Unlock()
		return waitExecution(ctx, pending)
	}
	if len(runtime.executions) >= maximumQueryDSLRuntimeEntries || len(runtime.jobs) >= maximumQueryDSLRuntimeEntries {
		runtime.mu.Unlock()
		return queryconnector.ValidatedExecution{}, denied("elastic_querydsl_runtime_capacity_reached")
	}
	prepared, ok := runtime.validated[query.Digest()]
	if !ok || prepared.validation.Digest() != validation.Digest() || !now.Before(prepared.expiresAt) {
		runtime.mu.Unlock()
		return queryconnector.ValidatedExecution{}, conflict("elastic_querydsl_validation_mismatch")
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

func (runtime *QueryDSLRuntime) runExecute(ctx context.Context, prepared validatedQueryDSL,
	now time.Time) (queryconnector.ValidatedExecution, *queryDSLJob, error) {
	identity, indices, receipts, err := runtime.resolveTargets(ctx, prepared.query, now)
	if err != nil {
		return queryconnector.ValidatedExecution{}, nil, err
	}
	if !slices.Equal(indices, prepared.indices) {
		return queryconnector.ValidatedExecution{}, nil, conflict("elastic_querydsl_target_drift")
	}
	keepAlive, err := boundedPITKeepAlive(now, prepared.expiresAt)
	if err != nil {
		return queryconnector.ValidatedExecution{}, nil, err
	}
	opened, openReceipt, err := runtime.client.OpenPIT(ctx, OpenPITRequest{Binding: CallBinding{Scope: prepared.query.Scope,
		Authority: prepared.query.Authority, Operation: "elastic.pit.open", Targets: indices}, Indices: indices,
		Plan: prepared.plan, KeepAlive: keepAlive})
	if err != nil {
		return queryconnector.ValidatedExecution{}, nil, err
	}
	if validateReceipt(runtime.discovery.config, openReceipt) != nil || opened.PITDigest == "" || opened.ID == "" {
		return queryconnector.ValidatedExecution{}, nil, conflict("elastic_pit_open_receipt_invalid")
	}
	receipts = append(append(append([]CallReceipt(nil), prepared.receipts...), receipts...), openReceipt)
	handle := queryconnector.HandleRef{HandleID: deterministicUUID(now, prepared.plan.Digest()+opened.PITDigest),
		Kind: "query_job", SourceID: prepared.query.Scope.SourceID,
		OpaqueDigest: digest("COH-ELASTIC-QUERY-DSL-JOB-V1\x00", struct{ Query, Plan, PIT string }{
			prepared.queryDigest, prepared.plan.Digest(), opened.PITDigest}), IssuedAt: now.Format(timestampLayout),
		ExpiresAt: prepared.expiresAt.Format(timestampLayout)}
	attemptID := deterministicUUID(now, handle.OpaqueDigest+"attempt")
	executionValue := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: prepared.query.QueryID, AttemptID: attemptID,
		Handle: handle, Outcome: "running", StartedAt: now.Format(timestampLayout),
		ProvenanceDigest: digest("COH-ELASTIC-QUERY-DSL-EXECUTION-V1\x00", struct {
			Plan     string
			Identity ClusterIdentity
			Indices  []string
			Receipts []CallReceipt
		}{prepared.plan.Digest(), identity, indices, receipts})}
	encoded, _ := json.Marshal(executionValue)
	execution, err := queryconnector.DecodeExecution(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedExecution{}, nil, err
	}
	job := &queryDSLJob{queryDigest: prepared.queryDigest, query: prepared.query, plan: prepared.plan,
		execution: execution, indices: append([]string(nil), indices...), authority: prepared.query.Authority,
		baseReceipts: receipts, expiresAt: prepared.expiresAt, pitID: opened.ID, pitDigest: opened.PITDigest,
		replays: make(map[string]pageReplay)}
	return execution, job, nil
}

func (runtime *QueryDSLRuntime) resolveTargets(ctx context.Context, query queryconnector.Query,
	now time.Time) (ClusterIdentity, []string, []CallReceipt, error) {
	if err := runtime.discovery.admitCapability(queryconnector.SchemaRequest{Scope: query.Scope,
		CapabilityDigest: query.CapabilityDigest}, now); err != nil {
		return ClusterIdentity{}, nil, nil, err
	}
	resources, err := validateScope(runtime.discovery.config, query.Scope)
	if err != nil || len(resources) != 1 {
		return ClusterIdentity{}, nil, nil, denied("elastic_querydsl_resource_scope_invalid")
	}
	identity, inspectReceipt, err := runtime.discovery.client.Inspect(ctx, CallBinding{Scope: query.Scope,
		Authority: query.Authority, Operation: "elastic.inspect", Targets: []string{resources[0].ID}})
	if err != nil {
		return ClusterIdentity{}, nil, nil, mapClientError(err)
	}
	if err := validateIdentity(runtime.discovery.config, identity); err != nil {
		return ClusterIdentity{}, nil, nil, err
	}
	if err := validateReceipt(runtime.discovery.config, inspectReceipt); err != nil {
		return ClusterIdentity{}, nil, nil, err
	}
	resolved, resolveReceipt, err := runtime.discovery.client.Resolve(ctx, ResolveRequest{Binding: CallBinding{Scope: query.Scope,
		Authority: query.Authority, Operation: "elastic.resolve", Targets: []string{resources[0].ID}},
		Expression: resources[0].Expression, Expand: "open"})
	if err != nil {
		return ClusterIdentity{}, nil, nil, mapClientError(err)
	}
	if err := validateReceipt(runtime.discovery.config, resolveReceipt); err != nil {
		return ClusterIdentity{}, nil, nil, err
	}
	indices, err := normalizeResolution(resources[0], resolved)
	if err != nil {
		return ClusterIdentity{}, nil, nil, err
	}
	return identity, indices, []CallReceipt{inspectReceipt, resolveReceipt}, nil
}

func (runtime *QueryDSLRuntime) removeExpiredLocked(now time.Time) {
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
			value.mu.Lock()
			value.pitID = ""
			value.mu.Unlock()
			delete(runtime.jobs, key)
		}
	}
}

func boundedPITKeepAlive(now, expiresAt time.Time) (time.Duration, error) {
	remaining := expiresAt.Sub(now)
	if remaining < time.Second {
		return 0, denied("elastic_querydsl_query_stale")
	}
	return min(remaining, time.Minute), nil
}

func queryDSLValidation(ctx context.Context, query queryconnector.ValidatedQuery, outcome string,
	reasons []string, provenance string) queryconnector.ValidatedValidation {
	value := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, Outcome: outcome,
		ReasonCodes: reasons, ValidatorVersion: elasticquerydsl.ValidatorVersion,
		CanonicalQueryDigest: query.Digest(), ProvenanceDigest: provenance}
	encoded, _ := json.Marshal(value)
	result, _ := queryconnector.DecodeValidation(ctx, encoded)
	return result
}

var _ queryconnector.Connector = (*QueryDSLRuntime)(nil)
