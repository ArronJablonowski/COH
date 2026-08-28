package splunk

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
)

const maximumSearchPageRows = 10000

func (client *HTTPClient) CreateSearch(ctx context.Context,
	request SearchCreateRequest) (SearchCreateResult, CallReceipt, error) {
	if client == nil || validateCallBinding(client.config, request.Binding, "splunk.search.create") != nil {
		return SearchCreateResult{}, CallReceipt{}, deniedCall("splunk_search_create_request_invalid")
	}
	plan, err := validLifecyclePlan(client.config, request.Binding, request.Plan)
	if err != nil {
		return SearchCreateResult{}, CallReceipt{}, err
	}
	seconds := ceilingSeconds(plan.MaximumDurationMillis)
	form := url.Values{
		"search":         {plan.CanonicalSPL},
		"exec_mode":      {"normal"},
		"earliest_time":  {plan.Earliest},
		"latest_time":    {plan.Latest},
		"max_count":      {strconv.FormatUint(plan.MaximumRows, 10)},
		"max_time":       {seconds},
		"auto_cancel":    {seconds},
		"timeout":        {seconds},
		"enable_preview": {"false"},
		"status_buckets": {"0"},
		"output_mode":    {"json"},
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.MaximumDurationMillis)*time.Millisecond)
	defer cancel()
	body, receipt, err := client.postFormStatus(callCtx, request.Binding, "/services/search/jobs", form,
		"splunk_search_create_rejected", http.StatusOK, http.StatusCreated)
	if err != nil {
		return SearchCreateResult{}, CallReceipt{}, err
	}
	var response struct {
		SID string `json:"sid"`
	}
	if decodeStrictVendor(body, &response) != nil || !validSID(response.SID) {
		return SearchCreateResult{}, CallReceipt{}, deniedCall("splunk_search_create_response_invalid")
	}
	return SearchCreateResult{SID: response.SID, SIDDigest: hashValue("COH-SPLUNK-SID-V1\x00", response.SID)}, receipt, nil
}

func (client *HTTPClient) SearchStatus(ctx context.Context,
	request SearchStatusRequest) (JobStatus, CallReceipt, error) {
	if client == nil || validateCallBinding(client.config, request.Binding, "splunk.search.status") != nil || !validSID(request.SID) {
		return JobStatus{}, CallReceipt{}, deniedCall("splunk_search_status_request_invalid")
	}
	body, receipt, err := client.get(ctx, request.Binding, searchJobPath(request.SID),
		url.Values{"count": {"1"}, "output_mode": {"json"}})
	if err != nil {
		return JobStatus{}, CallReceipt{}, err
	}
	status, err := decodeSearchStatus(body, request.SID)
	if err != nil {
		return JobStatus{}, CallReceipt{}, err
	}
	return status, receipt, nil
}

func (client *HTTPClient) SearchResults(ctx context.Context,
	request SearchResultsRequest) (ResultEnvelope, CallReceipt, error) {
	if client == nil || validateCallBinding(client.config, request.Binding, "splunk.search.results") != nil ||
		!validSID(request.SID) || request.Count == 0 || request.Count > maximumSearchPageRows ||
		uint64(request.Count) > client.config.HardLimits.MaximumRows || request.Offset > request.Total ||
		request.Total-request.Offset == 0 {
		return ResultEnvelope{}, CallReceipt{}, deniedCall("splunk_search_results_request_invalid")
	}
	plan, planErr := validLifecyclePlan(client.config, request.Binding, request.Plan)
	if planErr != nil || request.Total > plan.MaximumRows {
		return ResultEnvelope{}, CallReceipt{}, deniedCall("splunk_search_results_request_invalid")
	}
	remaining := request.Total - request.Offset
	if uint64(request.Count) > remaining {
		return ResultEnvelope{}, CallReceipt{}, deniedCall("splunk_search_results_request_invalid")
	}
	query := url.Values{"count": {strconv.FormatUint(uint64(request.Count), 10)},
		"offset": {strconv.FormatUint(request.Offset, 10)}, "output_mode": {"json"}}
	body, receipt, err := client.get(ctx, request.Binding, searchJobPath(request.SID)+"/results", query)
	if err != nil {
		return ResultEnvelope{}, CallReceipt{}, err
	}
	if uint64(len(body)) > plan.MaximumBytes {
		return ResultEnvelope{}, CallReceipt{}, deniedCall("splunk_search_results_response_oversized")
	}
	result, err := decodeSearchResults(body, request, plan, receipt)
	if err != nil {
		return ResultEnvelope{}, CallReceipt{}, err
	}
	return result, receipt, nil
}

func (client *HTTPClient) CancelSearch(ctx context.Context,
	request SearchCancelRequest) (SearchCancelResult, CallReceipt, error) {
	if client == nil || validateCallBinding(client.config, request.Binding, "splunk.search.cancel") != nil || !validSID(request.SID) {
		return SearchCancelResult{}, CallReceipt{}, deniedCall("splunk_search_cancel_request_invalid")
	}
	form := url.Values{"action": {"cancel"}, "output_mode": {"json"}}
	body, receipt, err := client.postFormStatus(ctx, request.Binding, searchJobPath(request.SID)+"/control", form,
		"splunk_search_cancel_rejected", http.StatusOK)
	if err != nil {
		return SearchCancelResult{}, CallReceipt{}, err
	}
	var response struct{}
	if decodeStrictVendor(body, &response) != nil {
		return SearchCancelResult{}, CallReceipt{}, deniedCall("splunk_search_cancel_response_invalid")
	}
	return SearchCancelResult{Acknowledged: true}, receipt, nil
}

func decodeSearchStatus(body []byte, sid string) (JobStatus, error) {
	var response struct {
		Entry []struct {
			Name    string `json:"name"`
			Content struct {
				State        string      `json:"dispatchState"`
				DoneProgress json.Number `json:"doneProgress"`
				ScanCount    uint64      `json:"scanCount"`
				EventCount   uint64      `json:"eventCount"`
				ResultCount  uint64      `json:"resultCount"`
				RunDuration  json.Number `json:"runDuration"`
				Done         *bool       `json:"isDone"`
				Failed       *bool       `json:"isFailed"`
				Finalized    *bool       `json:"isFinalized"`
				RealTime     *bool       `json:"isRealTimeSearch"`
				Zombie       *bool       `json:"isZombie"`
			} `json:"content"`
		} `json:"entry"`
	}
	if decodeStrictVendor(body, &response) != nil || len(response.Entry) != 1 || response.Entry[0].Name != sid {
		return JobStatus{}, deniedCall("splunk_search_status_response_invalid")
	}
	value := response.Entry[0].Content
	progress, progressErr := strconv.ParseFloat(value.DoneProgress.String(), 64)
	duration, durationErr := strconv.ParseFloat(value.RunDuration.String(), 64)
	if progressErr != nil || durationErr != nil || math.IsNaN(progress) || math.IsInf(progress, 0) ||
		math.IsNaN(duration) || math.IsInf(duration, 0) || progress < 0 || progress > 1 || duration < 0 ||
		duration > float64(math.MaxUint64)/1000 || value.Done == nil || value.Failed == nil ||
		value.Finalized == nil || value.RealTime == nil || value.Zombie == nil {
		return JobStatus{}, deniedCall("splunk_search_status_response_invalid")
	}
	status := JobStatus{SchemaVersion: JobStatusVersion, ContractVersion: ContractVersion, State: value.State,
		DoneProgress: strconv.FormatFloat(progress, 'f', 5, 64), ScanCount: value.ScanCount,
		EventCount: value.EventCount, ResultCount: value.ResultCount,
		DurationMillis: uint64(math.Ceil(duration * 1000)), Done: *value.Done, Failed: *value.Failed,
		Finalized: *value.Finalized, RealTime: *value.RealTime, Zombie: *value.Zombie}
	encoded, _ := json.Marshal(status)
	validated, err := DecodeJobStatus(encoded)
	if err != nil {
		return JobStatus{}, deniedCall("splunk_search_status_response_invalid")
	}
	return validated, nil
}

func decodeSearchResults(body []byte, request SearchResultsRequest, plan splunkparser.Plan,
	receipt CallReceipt) (ResultEnvelope, error) {
	var response struct {
		Preview    *bool  `json:"preview"`
		InitOffset uint64 `json:"init_offset"`
		Messages   []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"messages"`
		Fields []struct {
			Name string `json:"name"`
		} `json:"fields"`
		Results []map[string]json.RawMessage `json:"results"`
	}
	if decodeStrictVendor(body, &response) != nil || response.Preview == nil || *response.Preview ||
		response.InitOffset != request.Offset || len(response.Messages) != 0 || len(response.Fields) != len(plan.Columns) ||
		len(response.Results) > int(request.Count) || (len(response.Results) < int(request.Count) &&
		request.Offset+uint64(len(response.Results)) != request.Total) {
		return ResultEnvelope{}, deniedCall("splunk_search_results_response_invalid")
	}
	vendorToLogical := make(map[string]string, len(plan.Columns))
	logicalFields := make([]string, len(plan.Columns))
	for index, field := range plan.Columns {
		vendorToLogical[field.VendorName] = field.LogicalName
		logicalFields[index] = field.LogicalName
		if response.Fields[index].Name != field.VendorName {
			return ResultEnvelope{}, deniedCall("splunk_search_results_response_invalid")
		}
	}
	slices.Sort(logicalFields)
	rows := make([]map[string]string, 0, len(response.Results))
	for _, vendorRow := range response.Results {
		if len(vendorRow) == 0 || len(vendorRow) > len(plan.Columns) {
			return ResultEnvelope{}, deniedCall("splunk_search_results_response_invalid")
		}
		row := make(map[string]string, len(vendorRow))
		for vendorName, raw := range vendorRow {
			logicalName, ok := vendorToLogical[vendorName]
			if !ok {
				return ResultEnvelope{}, deniedCall("splunk_search_results_response_invalid")
			}
			var cell string
			if json.Unmarshal(raw, &cell) != nil || len(cell) > 65536 {
				return ResultEnvelope{}, deniedCall("splunk_search_results_response_invalid")
			}
			row[logicalName] = cell
		}
		rows = append(rows, row)
	}
	result := ResultEnvelope{SchemaVersion: ResultEnvelopeVersion, ContractVersion: ContractVersion,
		Offset: request.Offset, Count: request.Count, Total: request.Total, Fields: logicalFields,
		Results: rows, Messages: []string{}, Truncated: false}
	result.ResultDigest = hashValue("COH-SPLUNK-RESULT-ENVELOPE-V1\x00", struct {
		SID, Request, Response string
		Result                 ResultEnvelope
	}{hashValue("COH-SPLUNK-SID-V1\x00", request.SID), receipt.RequestDigest, receipt.ResponseDigest, result})
	encoded, _ := json.Marshal(result)
	validated, err := DecodeResultEnvelope(encoded)
	if err != nil {
		return ResultEnvelope{}, deniedCall("splunk_search_results_response_invalid")
	}
	return validated, nil
}

func validHistoricalRange(earliest, latest string) bool {
	start, startErr := time.Parse(time.RFC3339Nano, earliest)
	end, endErr := time.Parse(time.RFC3339Nano, latest)
	_, startOffset := start.Zone()
	_, endOffset := end.Zone()
	return startErr == nil && endErr == nil && startOffset == 0 && endOffset == 0 && start.Before(end)
}

func ceilingSeconds(milliseconds uint64) string {
	return strconv.FormatUint((milliseconds+999)/1000, 10)
}

func validSID(value string) bool { return sidPattern.MatchString(value) }

func searchJobPath(sid string) string { return "/services/search/jobs/" + sid }

func validLifecyclePlan(config Config, binding CallBinding, candidate splunkparser.Plan) (splunkparser.Plan, error) {
	encoded, _ := json.Marshal(candidate)
	plan, err := splunkparser.DecodePlan(encoded)
	if err != nil || plan.PlanDigest != splunkparser.PlanDigest(plan) || plan.SourceID != config.SourceID ||
		!slices.Equal(plan.ResourceIDs, binding.Scope.ResourceIDs) || plan.Authority.ActorID != binding.Authority.ActorID ||
		plan.Authority.AuthorizationDigest != binding.Authority.AuthorizationDigest ||
		plan.Authority.PolicyDecisionDigest != binding.Authority.PolicyDecisionDigest ||
		plan.Authority.AuditReservationDigest != binding.Authority.AuditReservationDigest ||
		plan.MaximumRows == 0 || plan.MaximumRows > config.HardLimits.MaximumRows || plan.MaximumBytes == 0 ||
		plan.MaximumBytes > config.HardLimits.MaximumBytes || plan.MaximumDurationMillis == 0 ||
		plan.MaximumDurationMillis > config.HardLimits.MaximumDurationMillis ||
		!validHistoricalRange(plan.Earliest, plan.Latest) || !planMatchesConfiguredIndex(config, plan) {
		return splunkparser.Plan{}, deniedCall("splunk_lifecycle_plan_invalid")
	}
	return plan, nil
}

func planMatchesConfiguredIndex(config Config, plan splunkparser.Plan) bool {
	if len(plan.ResourceIDs) != 1 {
		return false
	}
	for _, resource := range config.Resources {
		if resource.ID == plan.ResourceIDs[0] {
			prefix := "search index=" + resource.Index
			return strings.HasPrefix(plan.CanonicalSPL, prefix+" ") || strings.HasPrefix(plan.CanonicalSPL, prefix+" |")
		}
	}
	return false
}
