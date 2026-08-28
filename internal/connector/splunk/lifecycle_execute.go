package splunk

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (adapter *Adapter) Execute(ctx context.Context, query queryconnector.ValidatedQuery,
	validation queryconnector.ValidatedValidation) (queryconnector.ValidatedExecution, error) {
	if adapter == nil {
		return queryconnector.ValidatedExecution{}, invalidInput("splunk_adapter_required")
	}
	if err := queryconnector.AdmitExecution(ctx, query, validation); err != nil {
		return queryconnector.ValidatedExecution{}, err
	}
	now := adapter.clock.Now().UTC()
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	if _, revoked := adapter.revoked[query.Value().Authority.PolicyDecisionDigest]; revoked {
		adapter.mu.Unlock()
		return queryconnector.ValidatedExecution{}, deniedCall("splunk_authority_revoked")
	}
	if pending, exists := adapter.executions[query.Digest()]; exists {
		if pending.validationDigest != validation.Digest() {
			adapter.mu.Unlock()
			return queryconnector.ValidatedExecution{}, conflictCall("splunk_execution_validation_mismatch")
		}
		adapter.mu.Unlock()
		return waitSplunkExecution(ctx, pending)
	}
	if len(adapter.executions) >= maximumAdapterRecords || len(adapter.jobs) >= maximumAdapterRecords {
		adapter.mu.Unlock()
		return queryconnector.ValidatedExecution{}, deniedCall("splunk_adapter_capacity_reached")
	}
	prepared, exists := adapter.validations[query.Digest()]
	if !exists || !validPreparedExecution(query, validation, prepared, now) {
		adapter.mu.Unlock()
		return queryconnector.ValidatedExecution{}, conflictCall("splunk_execution_validation_mismatch")
	}
	pending := &splunkExecutionFlight{done: make(chan struct{}), validationDigest: validation.Digest(), expiresAt: prepared.expiresAt}
	adapter.executions[query.Digest()] = pending
	adapter.mu.Unlock()

	executionContext, cancel := context.WithTimeout(ctx, prepared.expiresAt.Sub(now))
	execution, job, err := adapter.dispatchSearch(executionContext, query, validation, prepared, now)
	cancel()

	adapter.mu.Lock()
	if err == nil {
		if _, revoked := adapter.revoked[job.query.Authority.PolicyDecisionDigest]; revoked {
			err = deniedCall("splunk_authority_revoked")
		} else if owner, owned := adapter.sidOwners[job.sidDigest]; owned && owner != job.queryDigest {
			err = conflictCall("splunk_sid_ownership_conflict")
		} else {
			adapter.sidOwners[job.sidDigest] = job.queryDigest
			adapter.jobs[execution.Value().Handle.HandleID] = job
		}
	}
	pending.execution, pending.err = execution, err
	close(pending.done)
	adapter.mu.Unlock()
	return execution, err
}

func (adapter *Adapter) dispatchSearch(ctx context.Context, query queryconnector.ValidatedQuery,
	validation queryconnector.ValidatedValidation, prepared splunkValidationRecord,
	now time.Time) (queryconnector.ValidatedExecution, splunkJobRecord, error) {
	queryValue := query.Value()
	binding := CallBinding{Scope: queryValue.Scope, Authority: queryValue.Authority,
		Operation: "splunk.search.create", Targets: append([]string(nil), queryValue.Scope.ResourceIDs...)}
	created, receipt, err := adapter.client.CreateSearch(ctx, SearchCreateRequest{Binding: binding, Plan: prepared.plan})
	if err != nil {
		return queryconnector.ValidatedExecution{}, splunkJobRecord{}, err
	}
	if !validSID(created.SID) || created.SIDDigest != hashValue("COH-SPLUNK-SID-V1\x00", created.SID) ||
		validateQualificationReceipt(adapter.config, receipt) != nil {
		return queryconnector.ValidatedExecution{}, splunkJobRecord{}, deniedCall("splunk_search_dispatch_receipt_invalid")
	}
	opaque := hashValue("COH-SPLUNK-JOB-HANDLE-V1\x00", struct {
		Query, Validation, Plan, SID, Dispatch, Expires string
	}{query.Digest(), validation.Digest(), prepared.plan.PlanDigest, created.SIDDigest,
		receipt.RequestDigest, prepared.expiresAt.Format(splunkTimestampLayout)})
	handle := queryconnector.HandleRef{HandleID: splunkDeterministicUUID(now, opaque), Kind: "query_job",
		SourceID: adapter.config.SourceID, OpaqueDigest: opaque, IssuedAt: now.Format(splunkTimestampLayout),
		ExpiresAt: prepared.expiresAt.Format(splunkTimestampLayout)}
	attemptID := splunkDeterministicUUID(now, opaque+"\x00attempt")
	value := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: queryValue.QueryID, AttemptID: attemptID,
		Handle: handle, Outcome: "running", StartedAt: now.Format(splunkTimestampLayout),
		ProvenanceDigest: hashValue("COH-SPLUNK-EXECUTION-V1\x00", struct {
			Query, Validation, Plan, SID, Request, Response, Lease, Transport string
		}{query.Digest(), validation.Digest(), prepared.plan.PlanDigest, created.SIDDigest,
			receipt.RequestDigest, receipt.ResponseDigest, receipt.LeaseDecisionDigest, receipt.TransportDigest})}
	encoded, _ := json.Marshal(value)
	execution, err := queryconnector.DecodeExecution(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedExecution{}, splunkJobRecord{}, err
	}
	queryValue.NativeText = ""
	job := splunkJobRecord{queryDigest: query.Digest(), validationDigest: validation.Digest(), query: queryValue,
		plan: prepared.plan, execution: execution, sid: created.SID, sidDigest: created.SIDDigest,
		dispatchReceipt: receipt, issuedAt: now, expiresAt: prepared.expiresAt}
	return execution, job, nil
}

func validPreparedExecution(query queryconnector.ValidatedQuery, validation queryconnector.ValidatedValidation,
	prepared splunkValidationRecord, now time.Time) bool {
	queryValue, validationValue, plan := query.Value(), validation.Value(), prepared.plan
	return prepared.validation.Digest() == validation.Digest() && prepared.queryID == queryValue.QueryID &&
		now.Before(prepared.expiresAt) && validationValue.ProvenanceDigest == plan.PlanDigest &&
		plan.PlanDigest == splunkparser.PlanDigest(plan) && plan.QueryID == queryValue.QueryID &&
		digestPattern.MatchString(plan.QueryDigest) && plan.SourceID == queryValue.Scope.SourceID &&
		slices.Equal(plan.ResourceIDs, queryValue.Scope.ResourceIDs) && plan.CapabilityDigest == queryValue.CapabilityDigest &&
		plan.SchemaDigest == queryValue.SchemaDigest && plan.ScopeDigest == hashValue("COH-SPLUNK-SCOPE-V1\x00", queryValue.Scope) &&
		plan.Earliest == queryValue.TimeRange.Start && plan.Latest == queryValue.TimeRange.End &&
		plan.MaximumRows > 0 && plan.MaximumRows <= queryValue.Limits.MaximumRows && plan.MaximumBytes == queryValue.Limits.MaximumBytes &&
		plan.MaximumDurationMillis == queryValue.Limits.MaximumDurationMillis && plan.Authority.ActorID == queryValue.Authority.ActorID &&
		plan.Authority.AuthorizationDigest == queryValue.Authority.AuthorizationDigest &&
		plan.Authority.PolicyDecisionDigest == queryValue.Authority.PolicyDecisionDigest &&
		plan.Authority.AuditReservationDigest == queryValue.Authority.AuditReservationDigest
}

func waitSplunkExecution(ctx context.Context,
	pending *splunkExecutionFlight) (queryconnector.ValidatedExecution, error) {
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
