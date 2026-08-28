package splunk

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (adapter *Adapter) buildCompletedSplunkPoll(ctx context.Context, job *splunkJobRecord,
	status JobStatus, statusReceipt CallReceipt) (queryconnector.ValidatedPoll, *splunkPageRecord, error) {
	if status.ResultCount > job.plan.MaximumRows {
		poll, err := boundedSplunkLimitPoll(ctx, *job, status, "splunk_row_limit_exceeded", statusReceipt)
		return poll, nil, err
	}
	if status.ResultCount == 0 {
		completeness := queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
		statistics := queryconnector.Statistics{RowsScanned: status.ScanCount, DurationMillis: status.DurationMillis}
		value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
			ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
			AttemptID: job.execution.Value().AttemptID, Outcome: "completed", Statistics: statistics,
			Completeness: completeness, ProvenanceDigest: hashValue("COH-SPLUNK-ZERO-RESULT-POLL-V1\x00", struct {
				Job, Plan, SID string
				Status         JobStatus
				Receipt        CallReceipt
			}{job.execution.Value().Handle.OpaqueDigest, job.plan.PlanDigest, job.sidDigest, status, statusReceipt})}
		encoded, _ := json.Marshal(value)
		poll, err := queryconnector.DecodePoll(ctx, encoded)
		return poll, nil, err
	}
	page, next, err := adapter.fetchSplunkPage(ctx, job, status, 0, 1)
	if err != nil {
		return queryconnector.ValidatedPoll{}, nil, err
	}
	pageValue := page.Value()
	outcome := "completed"
	if pageValue.Completeness.Truncated || pageValue.Completeness.Partial {
		outcome = "partial"
	}
	value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: outcome, Page: &pageValue,
		Statistics: pageValue.Statistics, Completeness: pageValue.Completeness,
		ProvenanceDigest: hashValue("COH-SPLUNK-COMPLETED-POLL-V1\x00", struct {
			Job, Page, StatusRequest, StatusResponse string
		}{job.execution.Value().Handle.OpaqueDigest, page.Digest(), statusReceipt.RequestDigest, statusReceipt.ResponseDigest})}
	encoded, _ := json.Marshal(value)
	poll, err := queryconnector.DecodePoll(ctx, encoded)
	return poll, next, err
}

func (adapter *Adapter) NextPage(ctx context.Context,
	request queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	if adapter == nil {
		return queryconnector.ValidatedPage{}, invalidInput("splunk_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	now := adapter.clock.Now().UTC()
	adapter.mu.Lock()
	if replay, exists := adapter.pageReplays[request.Handle.HandleID]; exists {
		job, retained := adapter.jobs[replay.jobHandleID]
		if !retained {
			adapter.mu.Unlock()
			return queryconnector.ValidatedPage{}, queryconnector.NewError(queryconnector.Unavailable,
				"splunk_page_unavailable", nil)
		}
		if !now.Before(job.expiresAt) {
			adapter.mu.Unlock()
			_, _ = adapter.Cancel(ctx, cancelRequestForJob(job, now))
			return queryconnector.ValidatedPage{}, queryconnector.NewError(queryconnector.Timeout,
				"splunk_job_deadline_exceeded", nil)
		}
		if replay.handle != request.Handle || replay.queryID != request.QueryID || replay.attemptID != request.AttemptID ||
			replay.authority != request.Authority || request.QueryID != job.query.QueryID ||
			request.AttemptID != job.execution.Value().AttemptID || request.Authority != job.query.Authority ||
			!validQueryLimits(request.Limits) || exceedsQueryLimits(request.Limits, job.query.Limits) {
			adapter.mu.Unlock()
			return queryconnector.ValidatedPage{}, conflictCall("splunk_page_handle_mismatch")
		}
		if _, revoked := adapter.revoked[job.query.Authority.PolicyDecisionDigest]; revoked {
			adapter.mu.Unlock()
			return queryconnector.ValidatedPage{}, deniedCall("splunk_authority_revoked")
		}
		adapter.mu.Unlock()
		return replay.page, nil
	}
	cursor, exists := adapter.pages[request.Handle.HandleID]
	if !exists {
		adapter.mu.Unlock()
		return queryconnector.ValidatedPage{}, queryconnector.NewError(queryconnector.Unavailable,
			"splunk_page_unavailable", nil)
	}
	job, exists := adapter.jobs[cursor.jobHandleID]
	if !exists || !now.Before(job.expiresAt) {
		adapter.mu.Unlock()
		if exists {
			_, _ = adapter.Cancel(ctx, cancelRequestForJob(job, now))
		}
		return queryconnector.ValidatedPage{}, queryconnector.NewError(queryconnector.Timeout,
			"splunk_job_deadline_exceeded", nil)
	}
	if !validPageRequest(request, cursor, job) {
		adapter.mu.Unlock()
		return queryconnector.ValidatedPage{}, conflictCall("splunk_page_handle_mismatch")
	}
	if _, revoked := adapter.revoked[job.query.Authority.PolicyDecisionDigest]; revoked {
		adapter.mu.Unlock()
		return queryconnector.ValidatedPage{}, deniedCall("splunk_authority_revoked")
	}
	if pending, ok := adapter.pageFlights[request.Handle.HandleID]; ok {
		adapter.mu.Unlock()
		return waitSplunkPage(ctx, pending)
	}
	pending := &splunkPageFlight{done: make(chan struct{})}
	adapter.pageFlights[request.Handle.HandleID] = pending
	adapter.mu.Unlock()

	status := *job.lastStatus
	var next *splunkPageRecord
	var err error
	pending.result, next, err = adapter.fetchSplunkPage(ctx, &job, status, cursor.offset, cursor.pageNumber)
	adapter.mu.Lock()
	if err == nil {
		current, retained := adapter.jobs[cursor.jobHandleID]
		if !retained || current.nextPage == nil || *current.nextPage != request.Handle {
			err = conflictCall("splunk_page_handle_mismatch")
		} else if _, revoked := adapter.revoked[current.query.Authority.PolicyDecisionDigest]; revoked {
			err = deniedCall("splunk_authority_revoked")
		} else {
			current.rowsReturned, current.bytesReturned, current.pageNumber = job.rowsReturned, job.bytesReturned, job.pageNumber
			current.resultChain, current.nextPage = job.resultChain, job.nextPage
			adapter.jobs[cursor.jobHandleID] = current
			delete(adapter.pages, request.Handle.HandleID)
			adapter.pageReplays[request.Handle.HandleID] = splunkPageReplay{handle: request.Handle,
				jobHandleID: cursor.jobHandleID, queryID: request.QueryID, attemptID: request.AttemptID,
				authority: request.Authority, page: pending.result}
			if next != nil {
				adapter.pages[next.handle.HandleID] = *next
			}
		}
	}
	pending.err = err
	delete(adapter.pageFlights, request.Handle.HandleID)
	close(pending.done)
	adapter.mu.Unlock()
	return pending.result, err
}

func (adapter *Adapter) fetchSplunkPage(ctx context.Context, job *splunkJobRecord, status JobStatus,
	offset uint64, pageNumber uint32) (queryconnector.ValidatedPage, *splunkPageRecord, error) {
	count, reason := splunkPageCapacity(*job, status.ResultCount)
	if reason != "" {
		return queryconnector.ValidatedPage{}, nil, deniedCall(reason)
	}
	binding := CallBinding{Scope: job.query.Scope, Authority: job.query.Authority,
		Operation: "splunk.search.results", Targets: append([]string(nil), job.query.Scope.ResourceIDs...)}
	envelope, receipt, err := adapter.client.SearchResults(ctx, SearchResultsRequest{Binding: binding, SID: job.sid,
		Offset: offset, Count: count, Total: status.ResultCount, Plan: job.plan})
	if err != nil {
		return queryconnector.ValidatedPage{}, nil, err
	}
	encodedEnvelope, _ := json.Marshal(envelope)
	validatedEnvelope, envelopeErr := DecodeResultEnvelope(encodedEnvelope)
	expectedFields := make([]string, len(job.plan.Columns))
	for index, column := range job.plan.Columns {
		expectedFields[index] = column.LogicalName
	}
	slices.Sort(expectedFields)
	if envelopeErr != nil || validateQualificationReceipt(adapter.config, receipt) != nil ||
		validatedEnvelope.Offset != offset || validatedEnvelope.Count != count ||
		validatedEnvelope.Total != status.ResultCount || !slices.Equal(validatedEnvelope.Fields, expectedFields) ||
		(len(validatedEnvelope.Results) < int(count) && offset+uint64(len(validatedEnvelope.Results)) != status.ResultCount) {
		return queryconnector.ValidatedPage{}, nil, deniedCall("splunk_result_page_receipt_invalid")
	}
	rows := make([]map[string]any, 0, len(validatedEnvelope.Results))
	pageBytes, truncationReason := uint64(0), ""
	for _, source := range validatedEnvelope.Results {
		row := make(map[string]any, len(source))
		for key, value := range source {
			row[key] = value
		}
		encodedRow, _ := json.Marshal(row)
		if job.bytesReturned+pageBytes+uint64(len(encodedRow)) > job.plan.MaximumBytes {
			truncationReason = "splunk_byte_limit_exceeded"
			break
		}
		pageBytes += uint64(len(encodedRow))
		rows = append(rows, row)
	}
	consumed := uint64(len(validatedEnvelope.Results))
	nextOffset := offset + consumed
	hasMore := nextOffset < status.ResultCount
	if truncationReason == "" && hasMore && job.rowsReturned+uint64(len(rows)) >= job.plan.MaximumRows {
		truncationReason = "splunk_row_limit_exceeded"
	}
	if truncationReason == "" && hasMore && pageNumber >= job.query.Limits.MaximumPages {
		truncationReason = "splunk_page_limit_exceeded"
	}
	job.rowsReturned += uint64(len(rows))
	job.bytesReturned += pageBytes
	job.pageNumber = pageNumber
	statistics := queryconnector.Statistics{RowsScanned: status.ScanCount, RowsReturned: job.rowsReturned,
		BytesReturned: job.bytesReturned, DurationMillis: status.DurationMillis,
		PagesReturned: job.pageNumber, SlicesCompleted: 1}
	completeness := queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
	var nextHandle *queryconnector.HandleRef
	var nextRecord *splunkPageRecord
	if truncationReason != "" {
		completeness = queryconnector.Completeness{Status: "unknown", ReasonCodes: []string{truncationReason},
			Truncated: true, VendorConfirmed: false}
	} else if hasMore {
		completeness = queryconnector.Completeness{Status: "unknown", ReasonCodes: []string{"splunk_more_pages"}}
		now := adapter.clock.Now().UTC()
		opaque := hashValue("COH-SPLUNK-PAGE-HANDLE-V1\x00", struct {
			Job, Plan, Chain string
			Offset           uint64
			Page             uint32
		}{job.execution.Value().Handle.OpaqueDigest, job.plan.PlanDigest, job.resultChain, nextOffset, pageNumber + 1})
		handle := queryconnector.HandleRef{HandleID: splunkDeterministicUUID(now, opaque), Kind: "result_page",
			SourceID: job.query.Scope.SourceID, OpaqueDigest: opaque, IssuedAt: now.Format(splunkTimestampLayout),
			ExpiresAt: job.expiresAt.Format(splunkTimestampLayout)}
		nextHandle = &handle
		nextRecord = &splunkPageRecord{handle: handle, jobHandleID: job.execution.Value().Handle.HandleID,
			offset: nextOffset, pageNumber: pageNumber + 1}
	}
	resultDigest := hashValue("COH-SPLUNK-PAGE-RESULT-V1\x00", struct {
		Previous, Envelope string
		Rows               []map[string]any
		Statistics         queryconnector.Statistics
	}{job.resultChain, validatedEnvelope.ResultDigest, rows, statistics})
	job.resultChain, job.nextPage = resultDigest, nextHandle
	value := queryconnector.ResultPage{SchemaVersion: queryconnector.PageSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, PageNumber: pageNumber, Rows: rows, NextPage: nextHandle,
		ResultDigest: resultDigest, Completeness: completeness, Statistics: statistics,
		ProvenanceDigest: hashValue("COH-SPLUNK-PAGE-V1\x00", struct {
			Job, Plan, SID, Result string
			Receipt                CallReceipt
		}{job.execution.Value().Handle.OpaqueDigest, job.plan.PlanDigest, job.sidDigest, resultDigest, receipt})}
	encoded, _ := json.Marshal(value)
	page, err := queryconnector.DecodePage(ctx, encoded)
	return page, nextRecord, err
}

func splunkPageCapacity(job splunkJobRecord, total uint64) (uint32, string) {
	if job.rowsReturned >= total || job.rowsReturned >= job.plan.MaximumRows ||
		job.pageNumber >= job.query.Limits.MaximumPages {
		return 0, "splunk_page_limit_exceeded"
	}
	remaining := total - job.rowsReturned
	remainingPages := uint64(job.query.Limits.MaximumPages - job.pageNumber)
	count := min(remaining, uint64(maximumSearchPageRows))
	needed := (remaining + remainingPages - 1) / remainingPages
	if needed > count {
		count = needed
	}
	if count == 0 || count > maximumSearchPageRows || count > job.plan.MaximumRows-job.rowsReturned {
		return 0, "splunk_page_limit_exceeded"
	}
	return uint32(count), ""
}

func boundedSplunkLimitPoll(ctx context.Context, job splunkJobRecord, status JobStatus, reason string,
	receipt CallReceipt) (queryconnector.ValidatedPoll, error) {
	completeness := queryconnector.Completeness{Status: "partial", ReasonCodes: []string{reason},
		Partial: true, Truncated: true, VendorConfirmed: true}
	statistics := queryconnector.Statistics{RowsScanned: status.ScanCount, DurationMillis: status.DurationMillis}
	value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: "partial", Statistics: statistics,
		Completeness: completeness, ProvenanceDigest: hashValue("COH-SPLUNK-LIMIT-POLL-V1\x00", struct {
			Job, Plan, Reason string
			Status            JobStatus
			Receipt           CallReceipt
		}{job.execution.Value().Handle.OpaqueDigest, job.plan.PlanDigest, reason, status, receipt})}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodePoll(ctx, encoded)
}

func validPageRequest(request queryconnector.PageRequest, cursor splunkPageRecord, job splunkJobRecord) bool {
	value := job.execution.Value()
	return request.Handle == cursor.handle && job.nextPage != nil && request.Handle == *job.nextPage &&
		request.QueryID == job.query.QueryID && request.AttemptID == value.AttemptID &&
		request.Authority == job.query.Authority && validQueryLimits(request.Limits) &&
		!exceedsQueryLimits(request.Limits, job.query.Limits)
}

func waitSplunkPage(ctx context.Context, pending *splunkPageFlight) (queryconnector.ValidatedPage, error) {
	select {
	case <-ctx.Done():
		return queryconnector.ValidatedPage{}, contextError(ctx)
	case <-pending.done:
		if err := contextError(ctx); err != nil {
			return queryconnector.ValidatedPage{}, err
		}
		return pending.result, pending.err
	}
}
