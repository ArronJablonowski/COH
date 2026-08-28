package splunk

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const minimumSplunkPollInterval = 500 * time.Millisecond

func (adapter *Adapter) Poll(ctx context.Context,
	request queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	if adapter == nil {
		return queryconnector.ValidatedPoll{}, invalidInput("splunk_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	now := adapter.clock.Now().UTC()
	adapter.mu.Lock()
	job, exists := adapter.jobs[request.Handle.HandleID]
	if exists && !now.Before(job.expiresAt) {
		adapter.removeJobLocked(request.Handle.HandleID, job)
		adapter.removeExpiredLocked(now)
		adapter.mu.Unlock()
		return queryconnector.ValidatedPoll{}, queryconnector.NewError(queryconnector.Timeout,
			"splunk_job_deadline_exceeded", nil)
	}
	adapter.removeExpiredLocked(now)
	job, exists = adapter.jobs[request.Handle.HandleID]
	if !exists {
		adapter.mu.Unlock()
		return queryconnector.ValidatedPoll{}, queryconnector.NewError(queryconnector.Unavailable,
			"splunk_job_unavailable", nil)
	}
	if !validPollRequest(request, job) {
		adapter.mu.Unlock()
		return queryconnector.ValidatedPoll{}, conflictCall("splunk_job_mismatch")
	}
	if _, revoked := adapter.revoked[job.query.Authority.PolicyDecisionDigest]; revoked {
		adapter.mu.Unlock()
		return queryconnector.ValidatedPoll{}, deniedCall("splunk_authority_revoked")
	}
	if job.lastPoll != nil && (job.lastStatus != nil && terminalSplunkState(job.lastStatus.State) ||
		now.Sub(job.lastPolledAt) < minimumSplunkPollInterval) {
		cached := *job.lastPoll
		adapter.mu.Unlock()
		return cached, nil
	}
	if pending, ok := adapter.polls[request.Handle.HandleID]; ok {
		adapter.mu.Unlock()
		return waitSplunkPoll(ctx, pending)
	}
	pending := &splunkPollFlight{done: make(chan struct{})}
	adapter.polls[request.Handle.HandleID] = pending
	adapter.mu.Unlock()

	binding := CallBinding{Scope: job.query.Scope, Authority: job.query.Authority,
		Operation: "splunk.search.status", Targets: append([]string(nil), job.query.Scope.ResourceIDs...)}
	status, receipt, err := adapter.client.SearchStatus(ctx, SearchStatusRequest{Binding: binding, SID: job.sid})
	if err == nil {
		encodedStatus, _ := json.Marshal(status)
		validatedStatus, statusErr := DecodeJobStatus(encodedStatus)
		if statusErr != nil {
			err = deniedCall("splunk_search_status_response_invalid")
		} else if validateQualificationReceipt(adapter.config, receipt) != nil {
			err = deniedCall("splunk_search_status_receipt_invalid")
		} else if !validStatusTransition(job.lastStatus, validatedStatus) {
			err = conflictCall("splunk_search_state_regression")
		} else {
			status = validatedStatus
			pending.result, err = buildSplunkPoll(ctx, job, status, receipt)
		}
	}

	adapter.mu.Lock()
	if err == nil {
		current, retained := adapter.jobs[request.Handle.HandleID]
		if !retained || !validPollRequest(request, current) {
			err = conflictCall("splunk_job_mismatch")
		} else if _, revoked := adapter.revoked[current.query.Authority.PolicyDecisionDigest]; revoked {
			err = deniedCall("splunk_authority_revoked")
		} else {
			current.lastStatus, current.lastPoll, current.lastPolledAt = &status, &pending.result, now
			adapter.jobs[request.Handle.HandleID] = current
		}
	}
	pending.err = err
	delete(adapter.polls, request.Handle.HandleID)
	close(pending.done)
	adapter.mu.Unlock()
	return pending.result, err
}

func buildSplunkPoll(ctx context.Context, job splunkJobRecord, status JobStatus,
	receipt CallReceipt) (queryconnector.ValidatedPoll, error) {
	outcome, reason := "running", "splunk_job_running"
	switch status.State {
	case "DONE":
		reason = "splunk_results_pending"
	case "FAILED":
		outcome, reason = "failed", "splunk_job_failed"
	case "BAD_INPUT_CANCEL":
		outcome, reason = "canceled", "splunk_job_bad_input_canceled"
	case "INTERNAL_CANCEL":
		outcome, reason = "canceled", "splunk_job_internal_canceled"
	case "USER_CANCEL":
		outcome, reason = "canceled", "splunk_job_user_canceled"
	case "QUIT":
		outcome, reason = "canceled", "splunk_job_quit"
	case "PAUSE":
		return queryconnector.ValidatedPoll{}, queryconnector.NewError(queryconnector.Unsupported,
			"splunk_job_paused_unsupported", nil)
	}
	completeness := queryconnector.Completeness{Status: "unknown", ReasonCodes: []string{reason}}
	if outcome != "running" {
		completeness = queryconnector.Completeness{Status: "partial", ReasonCodes: []string{reason},
			Partial: true, VendorConfirmed: true}
	}
	statistics := queryconnector.Statistics{RowsScanned: status.ScanCount,
		DurationMillis: status.DurationMillis}
	value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: outcome, Statistics: statistics,
		Completeness: completeness, ProvenanceDigest: hashValue("COH-SPLUNK-POLL-V1\x00", struct {
			Job, Plan, SID string
			Status         JobStatus
			Receipt        CallReceipt
		}{job.execution.Value().Handle.OpaqueDigest, job.plan.PlanDigest, job.sidDigest, status, receipt})}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodePoll(ctx, encoded)
}

func validPollRequest(request queryconnector.PollRequest, job splunkJobRecord) bool {
	value := job.execution.Value()
	return request.QueryID == job.query.QueryID && request.AttemptID == value.AttemptID &&
		request.Handle == value.Handle && request.Authority == job.query.Authority
}

func validStatusTransition(previous *JobStatus, current JobStatus) bool {
	if previous == nil {
		return true
	}
	if terminalSplunkState(previous.State) {
		return current.State == previous.State && monotonicStatus(*previous, current)
	}
	if terminalSplunkState(current.State) {
		return monotonicStatus(*previous, current)
	}
	return splunkStateRank(current.State) >= splunkStateRank(previous.State) && monotonicStatus(*previous, current)
}

func monotonicStatus(previous, current JobStatus) bool {
	previousProgress, previousErr := strconv.ParseFloat(previous.DoneProgress, 64)
	currentProgress, currentErr := strconv.ParseFloat(current.DoneProgress, 64)
	return previousErr == nil && currentErr == nil && currentProgress >= previousProgress &&
		current.ScanCount >= previous.ScanCount && current.EventCount >= previous.EventCount &&
		current.ResultCount >= previous.ResultCount && current.DurationMillis >= previous.DurationMillis
}

func splunkStateRank(state string) int {
	switch state {
	case "QUEUED":
		return 1
	case "PARSING":
		return 2
	case "RUNNING":
		return 3
	case "FINALIZING":
		return 4
	case "DONE", "BAD_INPUT_CANCEL", "INTERNAL_CANCEL", "USER_CANCEL", "QUIT", "FAILED":
		return 5
	default:
		return 0
	}
}

func terminalSplunkState(state string) bool { return splunkStateRank(state) == 5 }

func waitSplunkPoll(ctx context.Context, pending *splunkPollFlight) (queryconnector.ValidatedPoll, error) {
	select {
	case <-ctx.Done():
		return queryconnector.ValidatedPoll{}, contextError(ctx)
	case <-pending.done:
		if err := contextError(ctx); err != nil {
			return queryconnector.ValidatedPoll{}, err
		}
		return pending.result, pending.err
	}
}

func (adapter *Adapter) removeJobLocked(handleID string, job splunkJobRecord) {
	delete(adapter.jobs, handleID)
	if adapter.sidOwners[job.sidDigest] == job.queryDigest {
		delete(adapter.sidOwners, job.sidDigest)
	}
}
