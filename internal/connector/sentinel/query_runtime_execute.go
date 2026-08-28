package sentinel

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (runtime *QueryRuntime) Execute(ctx context.Context, query queryconnector.ValidatedQuery,
	validation queryconnector.ValidatedValidation) (queryconnector.ValidatedExecution, error) {
	if runtime == nil || runtime.discovery == nil || nilPort(runtime.client) {
		return queryconnector.ValidatedExecution{}, invalidInput("sentinel_query_runtime_required")
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
			return queryconnector.ValidatedExecution{}, conflictCall("sentinel_validation_binding_mismatch")
		}
		runtime.mu.Unlock()
		return waitSentinelExecution(ctx, pending)
	}
	prepared, ok := runtime.prepared[query.Digest()]
	if !ok || prepared.validation.Digest() != validation.Digest() || !now.Before(prepared.expiresAt) ||
		len(runtime.executions) >= maximumRuntimeRecords || len(runtime.jobs) >= maximumRuntimeRecords {
		runtime.mu.Unlock()
		return queryconnector.ValidatedExecution{}, conflictCall("sentinel_validation_binding_mismatch")
	}
	flight := &executionFlight{done: make(chan struct{}), validationDigest: validation.Digest(), expiresAt: prepared.expiresAt}
	runtime.executions[query.Digest()] = flight
	runtime.mu.Unlock()

	execution, job, err := runtime.runExecute(ctx, prepared, now)
	runtime.mu.Lock()
	flight.execution, flight.err = execution, err
	if err == nil {
		runtime.jobs[execution.Value().Handle.HandleID] = job
		delete(runtime.prepared, query.Digest())
	} else {
		delete(runtime.executions, query.Digest())
	}
	close(flight.done)
	runtime.mu.Unlock()
	return execution, err
}

func (runtime *QueryRuntime) runExecute(ctx context.Context, prepared preparedQuery,
	now time.Time) (queryconnector.ValidatedExecution, *sentinelQueryJob, error) {
	query, admission := prepared.query.Value(), prepared.admission
	remaining := prepared.expiresAt.Sub(now)
	maximum := time.Duration(min(query.Limits.MaximumDurationMillis,
		runtime.discovery.config.HardLimits.MaximumDurationMillis)) * time.Millisecond
	if remaining <= 0 || maximum <= 0 {
		return queryconnector.ValidatedExecution{}, nil, deniedCall("sentinel_query_stale")
	}
	duration := min(remaining, maximum)
	attemptID := sentinelDeterministicUUID(now, prepared.query.Digest()+prepared.validation.Digest())
	handle := queryconnector.HandleRef{HandleID: sentinelDeterministicUUID(now, attemptID+runtime.config.Digest),
		Kind: "query_job", SourceID: query.Scope.SourceID,
		OpaqueDigest: hashValue("COH-SENTINEL-QUERY-HANDLE-V1\x00", struct{ Query, Validation, Attempt string }{
			prepared.query.Digest(), prepared.validation.Digest(), attemptID}),
		IssuedAt: now.Format(sentinelTimestampLayout), ExpiresAt: prepared.expiresAt.Format(sentinelTimestampLayout)}
	request := QueryTransportRequest{SchemaVersion: QueryRequestVersion, ContractVersion: ContractVersion,
		Operation: QueryOperation, QueryID: query.QueryID, AttemptID: attemptID, SliceNumber: 1,
		SourceID: query.Scope.SourceID, WorkspaceID: runtime.discovery.config.WorkspaceID,
		ScopeDigest:      hashValue("COH-SENTINEL-QUERY-SCOPE-V1\x00", query.Scope),
		AuthorityDigest:  hashValue("COH-SENTINEL-QUERY-AUTHORITY-V1\x00", query.Authority),
		CapabilityDigest: query.CapabilityDigest, SchemaDigest: query.SchemaDigest,
		QualificationDigest: runtime.discovery.qualification.Digest(), CommonQueryDigest: prepared.query.Digest(),
		ValidationDigest: prepared.validation.Digest(), CanonicalKQL: admission.CanonicalKQL,
		CanonicalKQLDigest: admission.CanonicalKQLDigest, PolicyDecisionDigest: query.Authority.PolicyDecisionDigest,
		AuditRecordDigest: admission.Audit.AuditRecordDigest, TimeRange: query.TimeRange,
		MaximumRows:             min(query.Limits.MaximumRows, runtime.discovery.config.HardLimits.MaximumRows),
		MaximumBytes:            min(query.Limits.MaximumBytes, runtime.config.MaximumResponseBytes),
		ServerWaitSeconds:       uint32(max(1, min(uint64(600), uint64((duration+time.Second-1)/time.Second)))),
		TransportIdentityDigest: runtime.discovery.config.TransportIdentityDigest}
	request.RequestDigest = queryTransportRequestDigest(request)
	validatedRequest, err := DecodeQueryTransportRequest(encodeQueryContract(request))
	if err != nil {
		return queryconnector.ValidatedExecution{}, nil, invalidInput("sentinel_query_request_invalid")
	}
	binding := runtime.discovery.callBinding(query.Scope, query.Authority)
	binding.Operation = QueryOperation
	operationContext, cancel := context.WithTimeout(ctx, duration)
	response, err := runtime.client.Query(operationContext, QueryCall{Binding: binding, Request: validatedRequest})
	cancel()
	if err != nil {
		return queryconnector.ValidatedExecution{}, nil, err
	}
	if response.RequestDigest != request.RequestDigest || response.Receipt.RequestDigest != request.RequestDigest ||
		response.Receipt.TransportIdentityDigest != runtime.discovery.config.TransportIdentityDigest {
		return queryconnector.ValidatedExecution{}, nil, conflictCall("sentinel_query_response_binding_mismatch")
	}
	value := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.QueryID, AttemptID: attemptID,
		Handle: handle, Outcome: "running", StartedAt: now.Format(sentinelTimestampLayout),
		ProvenanceDigest: hashValue("COH-SENTINEL-QUERY-EXECUTION-V1\x00", struct {
			Query, Validation, Canonical, Request, Response, Audit string
		}{prepared.query.Digest(), prepared.validation.Digest(), admission.CanonicalKQLDigest,
			request.RequestDigest, response.ResponseDigest, admission.Audit.AuditRecordDigest})}
	encoded, _ := json.Marshal(value)
	execution, err := queryconnector.DecodeExecution(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedExecution{}, nil, err
	}
	job := &sentinelQueryJob{query: query, queryDigest: prepared.query.Digest(), validation: prepared.validation,
		admission: cloneValidationAdmission(admission), execution: execution, request: request, response: response,
		authority: query.Authority, expiresAt: prepared.expiresAt}
	return execution, job, nil
}

func waitSentinelExecution(ctx context.Context, pending *executionFlight) (queryconnector.ValidatedExecution, error) {
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
