package splunk

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const splunkCancellationWait = 5 * time.Second

func (adapter *Adapter) Cancel(ctx context.Context,
	request queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	if adapter == nil {
		return queryconnector.ValidatedCancellation{}, invalidInput("splunk_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCancellation{}, err
	}
	now := adapter.clock.Now().UTC()
	requestedAt, requestedErr := time.Parse(splunkTimestampLayout, request.RequestedAt)
	if requestedErr != nil || requestedAt.After(now) {
		return queryconnector.ValidatedCancellation{}, invalidInput("splunk_cancellation_request_invalid")
	}
	adapter.mu.Lock()
	if pending, exists := adapter.cancellations[request.Handle.HandleID]; exists {
		if pending.request != request {
			adapter.mu.Unlock()
			return queryconnector.ValidatedCancellation{}, conflictCall("splunk_cancellation_mismatch")
		}
		adapter.mu.Unlock()
		return waitSplunkCancellation(ctx, pending)
	}
	job, exists := adapter.jobs[request.Handle.HandleID]
	if !exists {
		adapter.mu.Unlock()
		result := uncertainSplunkCancellation(ctx, request, "splunk_job_unavailable", CallReceipt{})
		if result.Digest() == "" {
			return queryconnector.ValidatedCancellation{}, invalidInput("splunk_cancellation_request_invalid")
		}
		return result, nil
	}
	if !validCancelRequest(request, job) {
		adapter.mu.Unlock()
		return queryconnector.ValidatedCancellation{}, conflictCall("splunk_job_mismatch")
	}
	pending := &splunkCancellationFlight{done: make(chan struct{}), request: request}
	adapter.cancellations[request.Handle.HandleID] = pending
	adapter.mu.Unlock()

	pending.result = adapter.runSplunkCancellation(ctx, job, request, now)
	adapter.mu.Lock()
	if retained, ok := adapter.jobs[request.Handle.HandleID]; ok {
		adapter.removeJobLocked(request.Handle.HandleID, retained)
	}
	close(pending.done)
	adapter.mu.Unlock()
	return pending.result, nil
}

func (adapter *Adapter) runSplunkCancellation(ctx context.Context, job splunkJobRecord,
	request queryconnector.CancelRequest, now time.Time) queryconnector.ValidatedCancellation {
	if job.lastStatus != nil && terminalSplunkState(job.lastStatus.State) {
		return confirmedSplunkCancellation(ctx, request, now, "splunk_job_already_terminal", CallReceipt{}, CallReceipt{})
	}
	cancelContext, stop := context.WithTimeout(ctx, splunkCancellationWait)
	defer stop()
	binding := CallBinding{Scope: job.query.Scope, Authority: job.query.Authority,
		Operation: "splunk.search.cancel", Targets: append([]string(nil), job.query.Scope.ResourceIDs...)}
	acknowledged, cancelReceipt, err := adapter.client.CancelSearch(cancelContext,
		SearchCancelRequest{Binding: binding, SID: job.sid})
	if err != nil || !acknowledged.Acknowledged || validateQualificationReceipt(adapter.config, cancelReceipt) != nil {
		return uncertainSplunkCancellation(ctx, request, "splunk_cancel_unconfirmed", cancelReceipt)
	}
	statusBinding := binding
	statusBinding.Operation = "splunk.search.status"
	for {
		status, statusReceipt, statusErr := adapter.client.SearchStatus(cancelContext,
			SearchStatusRequest{Binding: statusBinding, SID: job.sid})
		if statusErr != nil {
			return uncertainSplunkCancellation(ctx, request, "splunk_cancel_status_unavailable", cancelReceipt)
		}
		encoded, _ := json.Marshal(status)
		validated, decodeErr := DecodeJobStatus(encoded)
		if decodeErr != nil || validateQualificationReceipt(adapter.config, statusReceipt) != nil ||
			!validStatusTransition(job.lastStatus, validated) {
			return uncertainSplunkCancellation(ctx, request, "splunk_cancel_status_invalid", cancelReceipt)
		}
		job.lastStatus = &validated
		if terminalSplunkState(validated.State) {
			return confirmedSplunkCancellation(ctx, request, now, "splunk_cancel_terminal_confirmed",
				cancelReceipt, statusReceipt)
		}
		timer := time.NewTimer(minimumSplunkPollInterval)
		select {
		case <-cancelContext.Done():
			timer.Stop()
			return uncertainSplunkCancellation(ctx, request, "splunk_cancel_confirmation_timeout", cancelReceipt)
		case <-timer.C:
		}
	}
}

func confirmedSplunkCancellation(_ context.Context, request queryconnector.CancelRequest, now time.Time,
	reason string, cancelReceipt, statusReceipt CallReceipt) queryconnector.ValidatedCancellation {
	confirmedAt := now.Format(splunkTimestampLayout)
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
		Outcome: "confirmed", RequestedAt: request.RequestedAt, ConfirmedAt: &confirmedAt,
		ProvenanceDigest: hashValue("COH-SPLUNK-CANCELLATION-V1\x00", struct {
			Handle, Reason string
			Cancel, Status CallReceipt
		}{request.Handle.OpaqueDigest, reason, cancelReceipt, statusReceipt})}
	encoded, _ := json.Marshal(value)
	result, _ := queryconnector.DecodeCancellation(context.Background(), encoded)
	return result
}

func uncertainSplunkCancellation(_ context.Context, request queryconnector.CancelRequest, reason string,
	receipt CallReceipt) queryconnector.ValidatedCancellation {
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
		Outcome: "uncertain", RequestedAt: request.RequestedAt,
		ProvenanceDigest: hashValue("COH-SPLUNK-CANCELLATION-UNCERTAIN-V1\x00", struct {
			Handle, Reason string
			Receipt        CallReceipt
		}{request.Handle.OpaqueDigest, reason, receipt})}
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeCancellation(context.Background(), encoded)
	if err != nil {
		return queryconnector.ValidatedCancellation{}
	}
	return result
}

func validCancelRequest(request queryconnector.CancelRequest, job splunkJobRecord) bool {
	value := job.execution.Value()
	return request.QueryID == job.query.QueryID && request.AttemptID == value.AttemptID &&
		request.Handle == value.Handle && request.Authority == job.query.Authority
}

func cancelRequestForJob(job splunkJobRecord, requestedAt time.Time) queryconnector.CancelRequest {
	value := job.execution.Value()
	return queryconnector.CancelRequest{QueryID: job.query.QueryID, AttemptID: value.AttemptID,
		Handle: value.Handle, Authority: job.query.Authority, RequestedAt: requestedAt.Format(splunkTimestampLayout)}
}

func waitSplunkCancellation(ctx context.Context,
	pending *splunkCancellationFlight) (queryconnector.ValidatedCancellation, error) {
	select {
	case <-ctx.Done():
		return queryconnector.ValidatedCancellation{}, contextError(ctx)
	case <-pending.done:
		if err := contextError(ctx); err != nil {
			return queryconnector.ValidatedCancellation{}, err
		}
		return pending.result, pending.err
	}
}
