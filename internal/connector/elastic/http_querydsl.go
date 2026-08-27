package elastic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticquerydsl"
)

const maximumPITKeepAlive = 5 * time.Minute

func (client *HTTPClient) ValidateQuery(ctx context.Context,
	request QueryValidationRequest) (QueryValidationResult, CallReceipt, error) {
	plan, err := client.validQueryDSLRequest(request.Binding, request.Indices, request.Plan, "elastic.query.validate")
	if err != nil {
		return QueryValidationResult{}, CallReceipt{}, err
	}
	payload, _ := json.Marshal(struct {
		Query map[string]any `json:"query"`
	}{Query: plan.CanonicalQuery})
	query := url.Values{"all_shards": []string{"true"}, "allow_no_indices": []string{"false"},
		"explain": []string{"false"}, "rewrite": []string{"false"}}
	requestPath := "/" + strings.Join(request.Indices, ",") + "/_validate/query"
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.MaximumDurationMillis)*time.Millisecond)
	defer cancel()
	body, receipt, err := client.doChecked(callCtx, request.Binding, http.MethodPost, requestPath, "", query, payload,
		queryDSLHeaders)
	if err != nil {
		return QueryValidationResult{}, CallReceipt{}, err
	}
	if uint64(len(body)) > plan.MaximumBytes {
		return QueryValidationResult{}, CallReceipt{}, denied("elastic_querydsl_response_oversized")
	}
	result, err := decodeQueryValidation(body)
	if err != nil {
		return QueryValidationResult{}, CallReceipt{}, err
	}
	result.ResultDigest = digest("COH-ELASTIC-QUERY-DSL-VALIDATION-V1\x00", struct {
		Plan, Request, Response string
	}{request.Plan.Digest(), receipt.RequestDigest, receipt.ResponseDigest})
	return result, receipt, nil
}

func (client *HTTPClient) OpenPIT(ctx context.Context,
	request OpenPITRequest) (PITResult, CallReceipt, error) {
	plan, err := client.validQueryDSLRequest(request.Binding, request.Indices, request.Plan, "elastic.pit.open")
	if err != nil || !validKeepAlive(request.KeepAlive) {
		if err != nil {
			return PITResult{}, CallReceipt{}, err
		}
		return PITResult{}, CallReceipt{}, invalid("elastic_pit_open_request_invalid")
	}
	query := url.Values{"keep_alive": []string{elasticDuration(request.KeepAlive)},
		"allow_partial_search_results": []string{"false"}}
	requestPath := "/" + strings.Join(request.Indices, ",") + "/_pit"
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.MaximumDurationMillis)*time.Millisecond)
	defer cancel()
	body, receipt, err := client.doChecked(callCtx, request.Binding, http.MethodPost, requestPath, "", query, nil,
		queryDSLHeaders)
	if err != nil {
		return PITResult{}, CallReceipt{}, err
	}
	if uint64(len(body)) > plan.MaximumBytes {
		return PITResult{}, CallReceipt{}, denied("elastic_querydsl_response_oversized")
	}
	result, err := decodeOpenPIT(body)
	if err != nil {
		return PITResult{}, CallReceipt{}, err
	}
	result.PITDigest = digest("COH-ELASTIC-PIT-ID-V1\x00", result.ID)
	return result, receipt, nil
}

func (client *HTTPClient) SearchPIT(ctx context.Context,
	request SearchPITRequest) (SearchPITResult, CallReceipt, error) {
	plan, planErr := client.validQueryDSLRequest(request.Binding, request.Indices, request.Plan, "elastic.pit.search")
	if planErr != nil {
		return SearchPITResult{}, CallReceipt{}, planErr
	}
	if request.Size == 0 || request.Size > plan.PageRows+1 || !validPITID(request.PITID) ||
		!validKeepAlive(request.KeepAlive) {
		return SearchPITResult{}, CallReceipt{}, invalid("elastic_pit_search_request_invalid")
	}
	if len(request.SearchAfter) != 0 {
		if _, err := convertSortTuple(plan.Sort, request.SearchAfter); err != nil {
			return SearchPITResult{}, CallReceipt{}, invalid("elastic_search_after_invalid")
		}
	}
	payload := map[string]any{"_source": false, "fields": queryDSLFields(plan.Columns), "pit": map[string]any{
		"id": request.PITID, "keep_alive": elasticDuration(request.KeepAlive)}, "query": plan.CanonicalQuery,
		"size": request.Size, "sort": queryDSLSort(plan.Sort), "timeout": strconv.FormatUint(plan.MaximumDurationMillis, 10) + "ms",
		"track_total_hits": false}
	if len(request.SearchAfter) != 0 {
		payload["search_after"] = append([]any(nil), request.SearchAfter...)
	}
	encoded, _ := json.Marshal(payload)
	query := url.Values{"allow_partial_search_results": []string{"false"}}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.MaximumDurationMillis)*time.Millisecond)
	defer cancel()
	body, receipt, err := client.doChecked(callCtx, request.Binding, http.MethodPost, "/_search", "", query, encoded,
		queryDSLHeaders)
	if err != nil {
		return SearchPITResult{}, CallReceipt{}, err
	}
	if uint64(len(body)) > plan.MaximumBytes {
		return SearchPITResult{}, CallReceipt{}, denied("elastic_querydsl_response_oversized")
	}
	result, err := decodeSearchPIT(body, plan, request.Indices, request.Size)
	if err != nil {
		return SearchPITResult{}, CallReceipt{}, err
	}
	if result.TookMillis > plan.MaximumDurationMillis {
		return SearchPITResult{}, CallReceipt{}, denied("elastic_querydsl_duration_exceeded")
	}
	result.PITDigest = digest("COH-ELASTIC-PIT-ID-V1\x00", result.PITID)
	result.ResultDigest = digest("COH-ELASTIC-PIT-SEARCH-V1\x00", struct {
		Plan, PreviousPIT, CurrentPIT, Request, Response string
	}{request.Plan.Digest(), digest("COH-ELASTIC-PIT-ID-V1\x00", request.PITID), result.PITDigest,
		receipt.RequestDigest, receipt.ResponseDigest})
	return result, receipt, nil
}

func (client *HTTPClient) ClosePIT(ctx context.Context,
	request ClosePITRequest) (ClosePITResult, CallReceipt, error) {
	if !validPITID(request.PITID) || len(request.Indices) == 0 || len(request.Indices) > maximumResources || !slices.IsSorted(request.Indices) ||
		duplicate(request.Indices) || validateHTTPBinding(request.Binding, "elastic.pit.close", request.Indices) != nil {
		return ClosePITResult{}, CallReceipt{}, invalid("elastic_pit_close_request_invalid")
	}
	for _, target := range request.Indices {
		if !safeConcreteIndex(target) {
			return ClosePITResult{}, CallReceipt{}, invalid("elastic_querydsl_target_invalid")
		}
	}
	payload, _ := json.Marshal(struct {
		ID string `json:"id"`
	}{ID: request.PITID})
	body, receipt, err := client.doChecked(ctx, request.Binding, http.MethodDelete, "/_pit", "", nil, payload,
		queryDSLHeaders)
	if err != nil {
		return ClosePITResult{}, CallReceipt{}, err
	}
	result, err := decodeClosePIT(body)
	if err != nil {
		return ClosePITResult{}, CallReceipt{}, err
	}
	result.ResultDigest = digest("COH-ELASTIC-PIT-CLOSE-V1\x00", struct {
		PIT, Request, Response string
	}{digest("COH-ELASTIC-PIT-ID-V1\x00", request.PITID), receipt.RequestDigest, receipt.ResponseDigest})
	return result, receipt, nil
}

func (client *HTTPClient) validQueryDSLRequest(binding CallBinding, indices []string,
	validated elasticquerydsl.ValidatedPlan, operation string) (elasticquerydsl.Plan, error) {
	plan := validated.Value()
	if validated.Digest() == "" || plan.PlanDigest != validated.Digest() || plan.SourceID != client.config.SourceID ||
		len(indices) == 0 || len(indices) > maximumResources || !slices.IsSorted(indices) || duplicate(indices) ||
		len(plan.Columns) == 0 || len(plan.Columns) > 256 || len(plan.Sort) < 3 || plan.MaximumRows == 0 ||
		plan.MaximumRows > client.config.HardLimits.MaximumRows || plan.MaximumPages == 0 ||
		plan.MaximumPages > client.config.HardLimits.MaximumPages || plan.MaximumBytes == 0 ||
		plan.MaximumBytes > client.config.HardLimits.MaximumBytes || plan.MaximumDurationMillis == 0 ||
		plan.MaximumDurationMillis > client.config.HardLimits.MaximumDurationMillis ||
		validateHTTPBinding(binding, operation, indices) != nil {
		return elasticquerydsl.Plan{}, invalid("elastic_querydsl_request_invalid")
	}
	for _, index := range indices {
		if !safeConcreteIndex(index) {
			return elasticquerydsl.Plan{}, invalid("elastic_querydsl_target_invalid")
		}
	}
	return plan, nil
}

func queryDSLHeaders(headers http.Header) error {
	if headers.Get("Warning") != "" || headers.Get("X-Elasticsearch-Async-Id") != "" ||
		headers.Get("X-Elasticsearch-Async-Is-Running") != "" ||
		!strings.HasPrefix(strings.ToLower(headers.Get("Content-Type")), "application/json") {
		return denied("elastic_querydsl_response_warning")
	}
	return nil
}

func validKeepAlive(value time.Duration) bool {
	return value >= time.Second && value <= maximumPITKeepAlive
}
func elasticDuration(value time.Duration) string {
	return strconv.FormatInt(value.Milliseconds(), 10) + "ms"
}

func validPITID(value string) bool {
	if len(value) == 0 || len(value) > 16384 {
		return false
	}
	for _, current := range []byte(value) {
		if current < 0x21 || current > 0x7e {
			return false
		}
	}
	return true
}

func queryDSLFields(columns []elasticquerydsl.Column) []any {
	result := make([]any, len(columns))
	for index, column := range columns {
		if column.Type == "timestamp" {
			result[index] = map[string]any{"field": column.VendorName, "format": "strict_date_optional_time_nanos"}
		} else {
			result[index] = column.VendorName
		}
	}
	return result
}

func queryDSLSort(fields []elasticquerydsl.SortField) []any {
	result := make([]any, len(fields))
	for index, field := range fields {
		body := map[string]any{"order": strings.ToLower(field.Direction)}
		if field.Type == "timestamp" {
			body["format"] = "strict_date_optional_time_nanos"
		}
		result[index] = map[string]any{field.VendorName: body}
	}
	return result
}
