package sentinel

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type sliceExecutionResult struct {
	requests      []QueryTransportRequest
	responses     []QueryTransportResponse
	plan          SlicePlan
	failureReason string
}

func (runtime *QueryRuntime) executeSlicePlan(ctx context.Context, prepared preparedQuery, attemptID string,
	duration time.Duration) (sliceExecutionResult, error) {
	query := prepared.query.Value()
	maximumSlices := min(query.Limits.MaximumSlices, runtime.discovery.config.HardLimits.MaximumSlices)
	plan := SlicePlan{SchemaVersion: SlicePlanVersion, ContractVersion: ContractVersion, QueryID: query.QueryID,
		AttemptID: attemptID, OriginalTimeRange: query.TimeRange, MaximumSlices: maximumSlices,
		MinimumDurationMS:  runtime.config.MinimumSliceDurationMillis,
		SplitThresholdRows: runtime.config.SplitThresholdRows, SplitThresholdBytes: runtime.config.SplitThresholdBytes,
		Slices: []SliceRecord{{Number: 1, TimeRange: query.TimeRange, State: "planned"}}}
	queue := []uint32{1}
	result := sliceExecutionResult{plan: plan}
	var aggregateRows, aggregateBytes uint64
	for len(queue) > 0 {
		if err := contextError(ctx); err != nil {
			return sliceExecutionResult{}, err
		}
		number := queue[0]
		queue = queue[1:]
		record := &result.plan.Slices[number-1]
		request, err := runtime.sliceRequest(prepared, attemptID, number, record.TimeRange, duration)
		if err != nil {
			return sliceExecutionResult{}, err
		}
		binding := runtime.discovery.callBinding(query.Scope, query.Authority)
		binding.Operation = QueryOperation
		response, err := runtime.client.Query(ctx, QueryCall{Binding: binding, Request: request})
		if err != nil {
			return sliceExecutionResult{}, err
		}
		if response.RequestDigest != request.RequestDigest || response.Receipt.RequestDigest != request.RequestDigest ||
			response.Receipt.TransportIdentityDigest != runtime.discovery.config.TransportIdentityDigest {
			return sliceExecutionResult{}, conflictCall("sentinel_query_response_binding_mismatch")
		}
		record.RequestDigest, record.ResponseDigest = request.RequestDigest, response.ResponseDigest
		result.requests = append(result.requests, request)
		if response.Error != nil {
			record.State, result.failureReason = "unknown", "sentinel_partial_error"
			result.responses = append(result.responses, response)
			break
		}
		if response.Statistics.RowsReturned >= runtime.config.SplitThresholdRows ||
			response.Statistics.BytesReturned >= runtime.config.SplitThresholdBytes {
			if !runtime.splitSlice(&result.plan, record, &queue) {
				record.State, result.failureReason = "denied", "sentinel_slice_limit_exceeded"
				break
			}
			continue
		}
		record.State = "complete"
		aggregateRows += response.Statistics.RowsReturned
		aggregateBytes += response.Statistics.BytesReturned
		result.responses = append(result.responses, response)
		if aggregateRows > query.Limits.MaximumRows || aggregateBytes > query.Limits.MaximumBytes {
			record.State, result.failureReason = "denied", "sentinel_aggregate_limit_exceeded"
			break
		}
	}
	result.plan.PlanDigest = slicePlanDigest(result.plan)
	validated, err := DecodeSlicePlan(encodeQueryContract(result.plan))
	if err != nil {
		return sliceExecutionResult{}, conflictCall("sentinel_slice_plan_invalid")
	}
	result.plan = validated
	return result, nil
}

func (runtime *QueryRuntime) sliceRequest(prepared preparedQuery, attemptID string, number uint32,
	timeRange queryconnector.TimeRange, duration time.Duration) (QueryTransportRequest, error) {
	query, admission := prepared.query.Value(), prepared.admission
	request := QueryTransportRequest{SchemaVersion: QueryRequestVersion, ContractVersion: ContractVersion,
		Operation: QueryOperation, QueryID: query.QueryID, AttemptID: attemptID, SliceNumber: number,
		SourceID: query.Scope.SourceID, WorkspaceID: runtime.discovery.config.WorkspaceID,
		ScopeDigest:      hashValue("COH-SENTINEL-QUERY-SCOPE-V1\x00", query.Scope),
		AuthorityDigest:  hashValue("COH-SENTINEL-QUERY-AUTHORITY-V1\x00", query.Authority),
		CapabilityDigest: query.CapabilityDigest, SchemaDigest: query.SchemaDigest,
		QualificationDigest: runtime.discovery.qualification.Digest(), CommonQueryDigest: prepared.query.Digest(),
		ValidationDigest: prepared.validation.Digest(), CanonicalKQL: admission.CanonicalKQL,
		CanonicalKQLDigest: admission.CanonicalKQLDigest, PolicyDecisionDigest: query.Authority.PolicyDecisionDigest,
		AuditRecordDigest: admission.Audit.AuditRecordDigest, TimeRange: timeRange,
		MaximumRows:             min(query.Limits.MaximumRows, runtime.discovery.config.HardLimits.MaximumRows),
		MaximumBytes:            min(query.Limits.MaximumBytes, runtime.config.MaximumResponseBytes),
		ServerWaitSeconds:       uint32(max(1, min(uint64(600), uint64((duration+time.Second-1)/time.Second)))),
		TransportIdentityDigest: runtime.discovery.config.TransportIdentityDigest}
	request.RequestDigest = queryTransportRequestDigest(request)
	validated, err := DecodeQueryTransportRequest(encodeQueryContract(request))
	if err != nil {
		return QueryTransportRequest{}, invalidInput("sentinel_query_request_invalid")
	}
	return validated, nil
}

func (runtime *QueryRuntime) splitSlice(plan *SlicePlan, parent *SliceRecord, queue *[]uint32) bool {
	start, startOK := queryTime(parent.TimeRange.Start)
	end, endOK := queryTime(parent.TimeRange.End)
	minimum := time.Duration(runtime.config.MinimumSliceDurationMillis) * time.Millisecond
	if !startOK || !endOK || end.Sub(start) <= minimum || len(plan.Slices)+2 > int(plan.MaximumSlices) {
		return false
	}
	midpoint := start.Add(end.Sub(start) / 2)
	if !start.Before(midpoint) || !midpoint.Before(end) {
		return false
	}
	parent.State = "split"
	leftNumber := uint32(len(plan.Slices) + 1)
	rightNumber := leftNumber + 1
	plan.Slices = append(plan.Slices,
		SliceRecord{Number: leftNumber, Parent: parent.Number,
			TimeRange: queryconnector.TimeRange{Start: start.Format(sentinelTimestampLayout), End: midpoint.Format(sentinelTimestampLayout)}, State: "planned"},
		SliceRecord{Number: rightNumber, Parent: parent.Number,
			TimeRange: queryconnector.TimeRange{Start: midpoint.Format(sentinelTimestampLayout), End: end.Format(sentinelTimestampLayout)}, State: "planned"})
	*queue = append([]uint32{leftNumber, rightNumber}, *queue...)
	return true
}
