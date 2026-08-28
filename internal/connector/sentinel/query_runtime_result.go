package sentinel

import (
	"context"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/connector/kustovalidator"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (runtime *QueryRuntime) Poll(ctx context.Context,
	request queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	if runtime == nil {
		return queryconnector.ValidatedPoll{}, invalidInput("sentinel_query_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	runtime.mu.Lock()
	job, ok := runtime.jobs[request.Handle.HandleID]
	runtime.mu.Unlock()
	if !ok {
		return queryconnector.ValidatedPoll{}, queryconnector.NewError(queryconnector.Unavailable, "sentinel_query_job_unavailable", nil)
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if request.QueryID != job.query.QueryID || request.AttemptID != job.execution.Value().AttemptID ||
		request.Handle != job.execution.Value().Handle || request.Authority != job.authority {
		return queryconnector.ValidatedPoll{}, conflictCall("sentinel_query_job_mismatch")
	}
	if job.poll != nil {
		return *job.poll, nil
	}
	if job.canceled {
		return runtime.terminalPoll(ctx, job, "canceled", "sentinel_query_canceled")
	}
	if job.failureReason != "" {
		outcome := "failed"
		if job.failureReason == "sentinel_query_canceled" {
			outcome = "canceled"
		}
		return runtime.terminalPoll(ctx, job, outcome, job.failureReason)
	}
	page, statistics, err := runtime.resultPage(job)
	if err != nil {
		return runtime.terminalPoll(ctx, job, "failed", queryconnector.Reason(err))
	}
	completeness := queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
	value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: "completed", Page: &page,
		Statistics: statistics, Completeness: completeness,
		ProvenanceDigest: hashValue("COH-SENTINEL-QUERY-POLL-V1\x00", struct{ Execution, Page string }{
			job.execution.Digest(), page.ProvenanceDigest})}
	encoded, _ := json.Marshal(value)
	poll, err := queryconnector.DecodePoll(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	job.released, job.poll = true, &poll
	return poll, nil
}

func (runtime *QueryRuntime) resultPage(job *sentinelQueryJob) (queryconnector.ResultPage,
	queryconnector.Statistics, error) {
	merged, err := runtime.mergeResults(job)
	if err != nil {
		return queryconnector.ResultPage{}, queryconnector.Statistics{}, err
	}
	rows := make([]map[string]interface{}, len(merged.rows))
	for rowIndex, source := range merged.rows {
		rows[rowIndex] = make(map[string]interface{}, len(merged.columns))
		for columnIndex, column := range merged.columns {
			rows[rowIndex][column.Name] = source[columnIndex]
		}
	}
	completeness := queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
	resultDigest := hashValue("COH-SENTINEL-QUERY-RESULT-V1\x00", struct {
		Columns []QueryColumn
		Rows    [][]interface{}
	}{merged.columns, merged.rows})
	requestDigests := make([]string, len(job.requests))
	for index, request := range job.requests {
		requestDigests[index] = request.RequestDigest
	}
	responseDigests := make([]string, len(job.responses))
	for index, response := range job.responses {
		responseDigests[index] = response.ResponseDigest
	}
	page := queryconnector.ResultPage{SchemaVersion: queryconnector.PageSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, PageNumber: 1, Rows: rows,
		ResultDigest: resultDigest, Completeness: completeness, Statistics: merged.statistics,
		ProvenanceDigest: hashValue("COH-SENTINEL-QUERY-PAGE-V1\x00", struct {
			Plan, Merge, Result, Validation, Canonical, Audit string
			Requests, Responses                               []string
		}{job.plan.PlanDigest, merged.provenance, resultDigest, job.validation.Digest(),
			job.admission.CanonicalKQLDigest, job.admission.Audit.AuditRecordDigest,
			requestDigests, responseDigests})}
	encoded, _ := json.Marshal(page)
	validated, err := queryconnector.DecodePage(context.Background(), encoded)
	if err != nil {
		return queryconnector.ResultPage{}, queryconnector.Statistics{}, err
	}
	return validated.Value(), merged.statistics, nil
}

func (runtime *QueryRuntime) terminalPoll(ctx context.Context, job *sentinelQueryJob,
	outcome, reason string) (queryconnector.ValidatedPoll, error) {
	statistics := jobAggregateStatistics(job)
	completeness := queryconnector.Completeness{Status: "unknown", ReasonCodes: []string{reason}}
	value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: outcome, Statistics: statistics,
		Completeness: completeness, ProvenanceDigest: hashValue("COH-SENTINEL-QUERY-TERMINAL-V1\x00", struct {
			Plan, Request, Response, Reason string
		}{job.plan.PlanDigest, firstRequestDigest(job), lastResponseDigest(job), reason})}
	encoded, _ := json.Marshal(value)
	poll, err := queryconnector.DecodePoll(ctx, encoded)
	if err == nil {
		job.poll = &poll
	}
	return poll, err
}

func (runtime *QueryRuntime) NextPage(ctx context.Context,
	_ queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	if runtime == nil {
		return queryconnector.ValidatedPage{}, invalidInput("sentinel_query_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	return queryconnector.ValidatedPage{}, queryconnector.NewError(queryconnector.Unsupported, "sentinel_single_page", nil)
}

func (runtime *QueryRuntime) Cancel(ctx context.Context,
	request queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	if runtime == nil {
		return queryconnector.ValidatedCancellation{}, invalidInput("sentinel_query_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCancellation{}, err
	}
	runtime.mu.Lock()
	job, ok := runtime.jobs[request.Handle.HandleID]
	runtime.mu.Unlock()
	if !ok {
		return runtime.cancellation(ctx, request, "uncertain", nil)
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if request.QueryID != job.query.QueryID || request.AttemptID != job.execution.Value().AttemptID ||
		request.Handle != job.execution.Value().Handle || request.Authority != job.authority {
		return queryconnector.ValidatedCancellation{}, conflictCall("sentinel_query_job_mismatch")
	}
	if job.released {
		return runtime.cancellation(ctx, request, "uncertain", nil)
	}
	job.canceled, job.failureReason = true, "sentinel_query_canceled"
	job.responses = nil
	confirmed := runtime.clock.Now().UTC().Format(sentinelTimestampLayout)
	return runtime.cancellation(ctx, request, "confirmed", &confirmed)
}

func (runtime *QueryRuntime) cancellation(ctx context.Context, request queryconnector.CancelRequest,
	outcome string, confirmed *string) (queryconnector.ValidatedCancellation, error) {
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
		Outcome: outcome, RequestedAt: request.RequestedAt, ConfirmedAt: confirmed,
		ProvenanceDigest: hashValue("COH-SENTINEL-QUERY-CANCELLATION-V1\x00", struct {
			Handle, Requested, Outcome string
		}{request.Handle.OpaqueDigest, request.RequestedAt, outcome})}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodeCancellation(ctx, encoded)
}

func jobAggregateStatistics(job *sentinelQueryJob) queryconnector.Statistics {
	var value queryconnector.Statistics
	for _, response := range job.responses {
		value.RowsScanned += response.Statistics.RowsScanned
		value.BytesReturned += response.Statistics.BytesReturned
		value.DurationMillis += response.Statistics.DurationMillis
	}
	return value
}

func firstRequestDigest(job *sentinelQueryJob) string {
	if len(job.requests) == 0 {
		return ""
	}
	return job.requests[0].RequestDigest
}

func lastResponseDigest(job *sentinelQueryJob) string {
	if len(job.responses) == 0 {
		return ""
	}
	return job.responses[len(job.responses)-1].ResponseDigest
}

func outputSchemaMatches(expected []kustovalidator.OutputColumn, observed []QueryColumn) bool {
	if len(expected) != len(observed) {
		return false
	}
	for index := range expected {
		if expected[index].Name != observed[index].Name || expected[index].Type != observed[index].Type {
			return false
		}
	}
	return true
}

var _ queryconnector.Connector = (*QueryRuntime)(nil)
