package securityonion

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (runtime *OQLRuntime) Poll(ctx context.Context,
	request queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	if runtime == nil {
		return queryconnector.ValidatedPoll{}, invalid("securityonion_oql_runtime_required")
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
		return queryconnector.ValidatedPoll{}, queryconnector.NewError(queryconnector.Unavailable,
			"securityonion_oql_job_unavailable", nil)
	}
	if request.Handle != job.execution.Value().Handle || request.QueryID != job.query.QueryID ||
		request.AttemptID != job.execution.Value().AttemptID || request.Authority != job.authority {
		return queryconnector.ValidatedPoll{}, conflict("securityonion_oql_job_mismatch")
	}
	rows := runtimeRows(job.result, job.groupBy)
	rowsBytes, _ := json.Marshal(rows)
	if uint64(len(rowsBytes)) > job.query.Limits.MaximumBytes {
		return queryconnector.ValidatedPoll{}, denied("securityonion_oql_result_oversized")
	}
	rowsScanned := max(job.result.TotalEvents, uint64(len(rows)))
	statistics := queryconnector.Statistics{RowsScanned: rowsScanned, RowsReturned: uint64(len(rows)),
		BytesReturned: uint64(len(rowsBytes)), DurationMillis: job.result.ElapsedMillis, PagesReturned: 1, SlicesCompleted: 1}
	completeness := runtimeCompleteness(job.result)
	outcome := "completed"
	if completeness.Status != "complete" {
		outcome = "partial"
	}
	page := queryconnector.ResultPage{SchemaVersion: queryconnector.PageSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, PageNumber: 1, Rows: rows,
		ResultDigest: job.result.ResultDigest, Completeness: completeness, Statistics: statistics,
		ProvenanceDigest: hashJSON("COH-SECURITY-ONION-OQL-PAGE-V1\x00", struct {
			Job, Plan, Result string
			Receipt           CallReceipt
		}{request.Handle.OpaqueDigest, job.planDigest, job.result.ResultDigest, job.receipt})}
	pollValue := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Outcome: outcome, Page: &page,
		Statistics: statistics, Completeness: completeness,
		ProvenanceDigest: hashJSON("COH-SECURITY-ONION-OQL-POLL-V1\x00", page.ProvenanceDigest)}
	encoded, _ := json.Marshal(pollValue)
	return queryconnector.DecodePoll(ctx, encoded)
}

func (runtime *OQLRuntime) NextPage(ctx context.Context,
	_ queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedPage{}, err
	}
	return queryconnector.ValidatedPage{}, unsupported("securityonion_oql_single_page")
}

func (runtime *OQLRuntime) Cancel(ctx context.Context,
	request queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	if runtime == nil {
		return queryconnector.ValidatedCancellation{}, invalid("securityonion_oql_runtime_required")
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
			ProvenanceDigest: hashJSON("COH-SECURITY-ONION-OQL-CANCEL-UNKNOWN-V1\x00", struct {
				Handle, Requested string
			}{request.Handle.OpaqueDigest, request.RequestedAt})}
		encoded, _ := json.Marshal(value)
		return queryconnector.DecodeCancellation(ctx, encoded)
	}
	if request.Handle != job.execution.Value().Handle || request.QueryID != job.query.QueryID ||
		request.AttemptID != job.execution.Value().AttemptID || request.Authority != job.authority {
		return queryconnector.ValidatedCancellation{}, conflict("securityonion_oql_job_mismatch")
	}
	confirmed := now.Format(timestampLayout)
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: request.QueryID, AttemptID: request.AttemptID,
		Outcome: "confirmed", RequestedAt: request.RequestedAt, ConfirmedAt: &confirmed,
		ProvenanceDigest: hashJSON("COH-SECURITY-ONION-OQL-CANCEL-V1\x00", struct {
			Job, Requested, Confirmed string
		}{request.Handle.OpaqueDigest, request.RequestedAt, confirmed})}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodeCancellation(ctx, encoded)
}

func runtimeRows(result EventQueryResult, groups []OQLColumn) []map[string]any {
	if len(result.Events) != 0 {
		rows := make([]map[string]any, len(result.Events))
		for index, event := range result.Events {
			rows[index] = make(map[string]any, len(event.Payload))
			for key, value := range event.Payload {
				rows[index][key] = value
			}
		}
		return rows
	}
	rows := make([]map[string]any, len(result.Metrics))
	for index, metric := range result.Metrics {
		row := map[string]any{"count": metric.Value}
		for groupIndex, key := range metric.Keys {
			name := "group_" + strconv.Itoa(groupIndex)
			if groupIndex < len(groups) {
				name = groups[groupIndex].LogicalName
			}
			row[name] = key
		}
		rows[index] = row
	}
	return rows
}

func runtimeCompleteness(result EventQueryResult) queryconnector.Completeness {
	if result.EventCapHit || result.MetricCapHit {
		reasons := []string{}
		if result.EventCapHit {
			reasons = append(reasons, "securityonion_event_limit_reached")
		}
		if result.MetricCapHit {
			reasons = append(reasons, "securityonion_metric_limit_reached")
		}
		slices.Sort(reasons)
		return queryconnector.Completeness{Status: "partial", ReasonCodes: reasons, Truncated: true, Partial: true}
	}
	if len(result.Metrics) != 0 || (len(result.Events) == 0 && result.TotalEvents != 0) {
		return queryconnector.Completeness{Status: "partial",
			ReasonCodes: []string{"securityonion_completion_unconfirmed"}, Partial: true}
	}
	return queryconnector.Completeness{Status: "complete", VendorConfirmed: true}
}

var _ queryconnector.Connector = (*OQLRuntime)(nil)
