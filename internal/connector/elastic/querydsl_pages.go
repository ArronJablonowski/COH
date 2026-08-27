package elastic

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (runtime *QueryDSLRuntime) Poll(ctx context.Context,
	request queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	if runtime == nil {
		return queryconnector.ValidatedPoll{}, invalid("elastic_querydsl_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	job, err := runtime.lookupQueryDSLJob(request.Handle.HandleID)
	if err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if err := verifyQueryDSLJob(job, request.QueryID, request.AttemptID, request.Handle, request.Authority); err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	if job.firstPoll != nil {
		return *job.firstPoll, nil
	}
	page, err := runtime.searchPageLocked(ctx, job)
	if err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	pageValue := page.Value()
	pollValue := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: "completed", Page: &pageValue,
		Statistics: pageValue.Statistics, Completeness: pageValue.Completeness,
		ProvenanceDigest: digest("COH-ELASTIC-QUERY-DSL-POLL-V1\x00", struct{ Job, Page string }{
			request.Handle.OpaqueDigest, page.Digest()})}
	encoded, _ := json.Marshal(pollValue)
	poll, err := queryconnector.DecodePoll(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedPoll{}, err
	}
	job.firstPoll = &poll
	return poll, nil
}

func (runtime *QueryDSLRuntime) NextPage(ctx context.Context,
	request queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	if runtime == nil {
		return queryconnector.ValidatedPage{}, invalid("elastic_querydsl_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	job, err := runtime.lookupQueryDSLJobByPage(request.Handle.HandleID)
	if err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if replay, ok := job.replays[request.Handle.HandleID]; ok {
		if replay.handle != request.Handle {
			return queryconnector.ValidatedPage{}, conflict("elastic_querydsl_page_handle_mismatch")
		}
		return replay.page, nil
	}
	if job.nextHandle == nil || *job.nextHandle != request.Handle || request.QueryID != job.query.QueryID ||
		request.AttemptID != job.execution.Value().AttemptID || request.Authority != job.authority {
		return queryconnector.ValidatedPage{}, conflict("elastic_querydsl_page_handle_mismatch")
	}
	if request.Limits.MaximumRows == 0 || request.Limits.MaximumBytes == 0 || request.Limits.MaximumPages == 0 {
		return queryconnector.ValidatedPage{}, invalid("elastic_querydsl_page_limits_invalid")
	}
	input := *job.nextHandle
	page, err := runtime.searchPageLocked(ctx, job)
	if err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	job.replays[input.HandleID] = pageReplay{handle: input, page: page}
	return page, nil
}

func (runtime *QueryDSLRuntime) searchPageLocked(ctx context.Context, job *queryDSLJob) (queryconnector.ValidatedPage, error) {
	if job.closed || job.pitID == "" {
		return queryconnector.ValidatedPage{}, conflict("elastic_querydsl_job_terminal")
	}
	now := runtime.clock.Now().UTC()
	keepAlive, err := boundedPITKeepAlive(now, job.expiresAt)
	if err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	plan := job.plan.Value()
	if job.rowsReturned >= plan.MaximumRows || job.pageNumber >= plan.MaximumPages {
		return queryconnector.ValidatedPage{}, denied("elastic_querydsl_export_limit_reached")
	}
	pageCapacity := min(plan.PageRows, plan.MaximumRows-job.rowsReturned)
	result, searchReceipt, err := runtime.client.SearchPIT(ctx, SearchPITRequest{Binding: CallBinding{Scope: job.query.Scope,
		Authority: job.authority, Operation: "elastic.pit.search", Targets: job.indices}, Indices: job.indices,
		Plan: job.plan, PITID: job.pitID, KeepAlive: keepAlive, Size: pageCapacity + 1,
		SearchAfter: append([]any(nil), job.searchAfter...)})
	if err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	if validateReceipt(runtime.discovery.config, searchReceipt) != nil || result.PITDigest == "" {
		return queryconnector.ValidatedPage{}, conflict("elastic_pit_search_receipt_invalid")
	}
	job.pitID, job.pitDigest = result.PITID, result.PITDigest
	releaseCount := min(uint64(len(result.Hits)), pageCapacity)
	rows := make([]map[string]any, 0, releaseCount)
	pageBytes := uint64(0)
	truncationReason := ""
	for index := uint64(0); index < releaseCount; index++ {
		row := cloneRows([]map[string]any{result.Hits[index].Row})[0]
		encoded, _ := json.Marshal(row)
		if job.bytesReturned+pageBytes+uint64(len(encoded)) > plan.MaximumBytes {
			truncationReason = "byte_limit_reached"
			break
		}
		pageBytes += uint64(len(encoded))
		rows = append(rows, row)
	}
	hasMore := uint64(len(result.Hits)) > uint64(len(rows))
	nextRows := job.rowsReturned + uint64(len(rows))
	nextPageNumber := job.pageNumber + 1
	if truncationReason == "" && hasMore && nextRows >= plan.MaximumRows {
		truncationReason = "row_limit_reached"
	}
	if truncationReason == "" && hasMore && nextPageNumber >= plan.MaximumPages {
		truncationReason = "page_limit_reached"
	}
	terminal := !hasMore || truncationReason != ""
	receipts := []CallReceipt{searchReceipt}
	if terminal {
		closeReceipt, closeErr := runtime.closePITLocked(ctx, job)
		if closeErr != nil {
			return queryconnector.ValidatedPage{}, closeErr
		}
		receipts = append(receipts, closeReceipt)
	}
	job.rowsScanned += uint64(len(result.Hits))
	job.rowsReturned = nextRows
	job.bytesReturned += pageBytes
	job.durationMillis += result.TookMillis
	job.pageNumber = nextPageNumber
	var nextHandle *queryconnector.HandleRef
	if !terminal {
		lastSort := append([]any(nil), result.Hits[len(rows)-1].Sort...)
		job.searchAfter = lastSort
		handle := queryconnector.HandleRef{HandleID: deterministicUUID(now, job.execution.Digest()+result.ResultDigest+strconv.FormatUint(uint64(nextPageNumber), 10)),
			Kind: "result_page", SourceID: job.query.Scope.SourceID,
			OpaqueDigest: digest("COH-ELASTIC-QUERY-DSL-PAGE-HANDLE-V1\x00", struct {
				Job, Plan, PIT string
				Page           uint32
				Sort           []any
			}{job.execution.Value().Handle.OpaqueDigest, job.plan.Digest(), job.pitDigest, nextPageNumber + 1, lastSort}),
			IssuedAt: now.Format(timestampLayout), ExpiresAt: job.expiresAt.Format(timestampLayout)}
		nextHandle = &handle
	}
	job.nextHandle = nextHandle
	statistics := queryconnector.Statistics{RowsScanned: job.rowsScanned, RowsReturned: job.rowsReturned,
		BytesReturned: job.bytesReturned, DurationMillis: job.durationMillis, PagesReturned: job.pageNumber,
		SlicesCompleted: job.pageNumber}
	completeness := queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
	if truncationReason != "" {
		completeness = queryconnector.Completeness{Status: "unknown", ReasonCodes: []string{truncationReason},
			Truncated: true, VendorConfirmed: false}
	}
	resultDigest := digest("COH-ELASTIC-QUERY-DSL-PAGE-RESULT-V1\x00", struct {
		Search     string
		Rows       []map[string]any
		Statistics queryconnector.Statistics
	}{result.ResultDigest, rows, statistics})
	pageValue := queryconnector.ResultPage{SchemaVersion: queryconnector.PageSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, PageNumber: job.pageNumber, Rows: rows, NextPage: nextHandle,
		ResultDigest: resultDigest, Completeness: completeness, Statistics: statistics,
		ProvenanceDigest: digest("COH-ELASTIC-QUERY-DSL-PAGE-V1\x00", struct {
			Job, Plan, PIT, Result string
			Receipts               []CallReceipt
		}{job.execution.Value().Handle.OpaqueDigest, job.plan.Digest(), job.pitDigest, resultDigest, receipts})}
	encoded, _ := json.Marshal(pageValue)
	return queryconnector.DecodePage(ctx, encoded)
}

func (runtime *QueryDSLRuntime) Cancel(ctx context.Context,
	request queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	if runtime == nil {
		return queryconnector.ValidatedCancellation{}, invalid("elastic_querydsl_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCancellation{}, err
	}
	job, err := runtime.lookupQueryDSLJob(request.Handle.HandleID)
	if err != nil {
		return uncertainQueryDSLCancellation(ctx, request), nil
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if err := verifyQueryDSLJob(job, request.QueryID, request.AttemptID, request.Handle, request.Authority); err != nil {
		return queryconnector.ValidatedCancellation{}, err
	}
	now := runtime.clock.Now().UTC()
	receipt := CallReceipt{}
	if !job.closed {
		var closeErr error
		receipt, closeErr = runtime.closePITLocked(ctx, job)
		if closeErr != nil {
			return uncertainQueryDSLCancellation(ctx, request), nil
		}
	}
	confirmed := now.Format(timestampLayout)
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
		Outcome: "confirmed", RequestedAt: request.RequestedAt, ConfirmedAt: &confirmed,
		ProvenanceDigest: digest("COH-ELASTIC-QUERY-DSL-CANCEL-V1\x00", struct {
			Job, Requested string
			Receipt        CallReceipt
		}{request.Handle.OpaqueDigest, request.RequestedAt, receipt})}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodeCancellation(ctx, encoded)
}

func (runtime *QueryDSLRuntime) closePITLocked(ctx context.Context, job *queryDSLJob) (CallReceipt, error) {
	if job.closed {
		return CallReceipt{}, nil
	}
	closed, receipt, err := runtime.client.ClosePIT(ctx, ClosePITRequest{Binding: CallBinding{Scope: job.query.Scope,
		Authority: job.authority, Operation: "elastic.pit.close", Targets: job.indices}, Indices: job.indices, PITID: job.pitID})
	if err != nil {
		return CallReceipt{}, err
	}
	if !closed.Succeeded || validateReceipt(runtime.discovery.config, receipt) != nil {
		return CallReceipt{}, conflict("elastic_pit_close_receipt_invalid")
	}
	job.closed, job.pitID = true, ""
	return receipt, nil
}

func (runtime *QueryDSLRuntime) lookupQueryDSLJob(handleID string) (*queryDSLJob, error) {
	runtime.mu.Lock()
	runtime.removeExpiredLocked(runtime.clock.Now().UTC())
	job := runtime.jobs[handleID]
	runtime.mu.Unlock()
	if job == nil {
		return nil, queryconnector.NewError(queryconnector.Unavailable, "elastic_querydsl_job_unavailable", nil)
	}
	return job, nil
}

func (runtime *QueryDSLRuntime) lookupQueryDSLJobByPage(handleID string) (*queryDSLJob, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.removeExpiredLocked(runtime.clock.Now().UTC())
	for _, job := range runtime.jobs {
		job.mu.Lock()
		matched := job.nextHandle != nil && job.nextHandle.HandleID == handleID
		if !matched {
			_, matched = job.replays[handleID]
		}
		job.mu.Unlock()
		if matched {
			return job, nil
		}
	}
	return nil, queryconnector.NewError(queryconnector.Unavailable, "elastic_querydsl_page_unavailable", nil)
}

func verifyQueryDSLJob(job *queryDSLJob, queryID, attemptID string, handle queryconnector.HandleRef,
	authority queryconnector.AuthorityBinding) error {
	if handle != job.execution.Value().Handle || queryID != job.query.QueryID || attemptID != job.execution.Value().AttemptID || authority != job.authority {
		return conflict("elastic_querydsl_job_mismatch")
	}
	return nil
}

func uncertainQueryDSLCancellation(ctx context.Context, request queryconnector.CancelRequest) queryconnector.ValidatedCancellation {
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
		Outcome: "uncertain", RequestedAt: request.RequestedAt,
		ProvenanceDigest: digest("COH-ELASTIC-QUERY-DSL-CANCEL-UNKNOWN-V1\x00", struct{ Handle, Requested string }{
			request.Handle.OpaqueDigest, request.RequestedAt})}
	encoded, _ := json.Marshal(value)
	result, _ := queryconnector.DecodeCancellation(ctx, encoded)
	return result
}
