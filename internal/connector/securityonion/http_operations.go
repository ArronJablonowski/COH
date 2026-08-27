package securityonion

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (client *HTTPClient) Inspect(ctx context.Context, request InfoRequest) (InfoResult, CallReceipt, error) {
	if err := client.validateCall(ctx, request.Binding, request.Qualification, "securityonion.inspect", "/connect/info/", nil); err != nil {
		return InfoResult{}, CallReceipt{}, err
	}
	body, receipt, err := client.get(ctx, request.Binding, "/connect/info/", nil, client.config.HardLimits.MaximumBytes)
	if err != nil {
		return InfoResult{}, CallReceipt{}, err
	}
	defer zeroBytes(body)
	var response struct {
		Version        string `json:"version"`
		ElasticVersion string `json:"elasticVersion"`
	}
	if decodeUniqueJSON(body, &response, false) != nil || !safeVendorText(response.Version, 128) ||
		!safeVendorText(response.ElasticVersion, 128) {
		return InfoResult{}, CallReceipt{}, denied("securityonion_info_response_invalid")
	}
	result := InfoResult{Version: response.Version, ElasticVersion: response.ElasticVersion}
	result.ResultDigest = hash("COH-SECURITY-ONION-INFO-RESULT-V1\x00", mustJSONBytes(result))
	return result, receipt, nil
}

func (client *HTTPClient) QueryEvents(ctx context.Context, request EventQueryRequest) (EventQueryResult, CallReceipt, error) {
	plan := request.Plan.Value()
	if request.Plan.Digest() == "" || request.Plan.Digest() != plan.PlanDigest ||
		plan.SourceID != client.config.SourceID || plan.QualificationDigest != request.Qualification.Digest() ||
		len(request.Binding.Targets) != 1 || request.Binding.Targets[0] != plan.ResourceID {
		return EventQueryResult{}, CallReceipt{}, denied("securityonion_query_plan_binding_invalid")
	}
	parameters := url.Values{
		"eventLimit":  []string{strconv.FormatUint(plan.EventLimit, 10)},
		"format":      []string{plan.Format},
		"metricLimit": []string{strconv.FormatUint(plan.MetricLimit, 10)},
		"query":       []string{plan.RenderedQuery},
		"range":       []string{plan.Range},
		"zone":        []string{plan.Zone},
	}
	if err := client.validateCall(ctx, request.Binding, request.Qualification, "securityonion.query_events",
		"/connect/events/", []string{"eventLimit", "format", "metricLimit", "query", "range", "zone"}); err != nil {
		return EventQueryResult{}, CallReceipt{}, err
	}
	deadline, cancel := context.WithTimeout(ctx, time.Duration(plan.MaximumDurationMillis)*time.Millisecond)
	defer cancel()
	body, receipt, err := client.get(deadline, request.Binding, "/connect/events/", parameters, plan.MaximumBytes)
	if err != nil {
		return EventQueryResult{}, CallReceipt{}, err
	}
	defer zeroBytes(body)
	result, err := decodeEventQueryResult(body, plan)
	if err != nil {
		return EventQueryResult{}, CallReceipt{}, err
	}
	return result, receipt, nil
}

func (client *HTTPClient) get(ctx context.Context, binding CallBinding, path string, parameters url.Values,
	maximum uint64) ([]byte, CallReceipt, error) {
	var body []byte
	var operationReceipt CallReceipt
	tokenReceipt, err := client.withToken(ctx, binding, func(token string, tokenReceipt CallReceipt) error {
		requestURL := *client.baseURL
		requestURL.Path, requestURL.RawQuery = path, parameters.Encode()
		requestDigest := hash("COH-SECURITY-ONION-HTTP-REQUEST-V1\x00", mustJSONBytes(struct {
			Method, Path, Query string
		}{http.MethodGet, path, requestURL.RawQuery}))
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return invalid("securityonion_http_request_invalid")
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.client.Do(request)
		request.Header.Del("Authorization")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		transportDigest, err := client.transportDigest(response)
		if err != nil {
			return err
		}
		limit := maximum
		if limit == 0 || limit > queryconnector.MaximumDocumentBytes {
			return invalid("securityonion_response_limit_invalid")
		}
		body, err = io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
		if err != nil || uint64(len(body)) > limit {
			return denied("securityonion_response_oversized")
		}
		operationReceipt = CallReceipt{RequestDigest: requestDigest,
			ResponseDigest: hash("COH-SECURITY-ONION-HTTP-RESPONSE-V1\x00", mustJSONBytes(struct {
				Status int
				Body   []byte
			}{response.StatusCode, body})), TransportDigest: transportDigest}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return denied("securityonion_authentication_or_privilege_denied")
		}
		if response.StatusCode != http.StatusOK {
			return queryconnector.NewError(queryconnector.Unavailable, "securityonion_vendor_unavailable", nil)
		}
		if !jsonMediaType(response.Header.Get("Content-Type")) {
			return denied("securityonion_response_media_type_invalid")
		}
		return nil
	})
	if err != nil {
		return nil, CallReceipt{}, err
	}
	return body, CallReceipt{
		RequestDigest: hash("COH-SECURITY-ONION-CALL-REQUEST-V1\x00", mustJSONBytes([]string{
			tokenReceipt.RequestDigest, operationReceipt.RequestDigest})),
		ResponseDigest: hash("COH-SECURITY-ONION-CALL-RESPONSE-V1\x00", mustJSONBytes([]string{
			tokenReceipt.ResponseDigest, operationReceipt.ResponseDigest})),
		LeaseDecisionDigest: tokenReceipt.LeaseDecisionDigest,
		TransportDigest:     operationReceipt.TransportDigest,
	}, nil
}

func (client *HTTPClient) validateCall(ctx context.Context, binding CallBinding, qualification ValidatedQualification,
	operation, path string, parameters []string) error {
	if client == nil || client.client == nil || nilPort(client.credentials) {
		return invalid("securityonion_http_client_required")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateCallBinding(binding, operation); err != nil {
		return err
	}
	value := qualification.Value()
	if qualification.Digest() == "" || value.Digest != qualification.Digest() || value.SourceID != client.config.SourceID ||
		binding.Scope.SourceID != client.config.SourceID || !allowedTargets(client.config, binding.Targets) ||
		!slices.ContainsFunc(value.Operations, func(candidate Operation) bool {
			return candidate.Method == http.MethodGet && candidate.Path == path &&
				slices.Equal(candidate.RequiredParameters, parameters) && candidate.ResponseMediaType == "application/json"
		}) {
		return denied("securityonion_qualification_binding_invalid")
	}
	return nil
}

func allowedTargets(config Config, targets []string) bool {
	for _, target := range targets {
		if !slices.ContainsFunc(config.Resources, func(resource Resource) bool { return resource.ID == target }) {
			return false
		}
	}
	return true
}

func validateCallBinding(binding CallBinding, operation string) error {
	if !uuidPattern.MatchString(binding.Scope.OrganizationID) || !uuidPattern.MatchString(binding.Scope.TenantID) ||
		!uuidPattern.MatchString(binding.Scope.CaseID) || !uuidPattern.MatchString(binding.Authority.ActorID) ||
		!digestPattern.MatchString(binding.Authority.AuthorizationDigest) ||
		!digestPattern.MatchString(binding.Authority.PolicyDecisionDigest) ||
		!digestPattern.MatchString(binding.Authority.AuditReservationDigest) || binding.Operation != operation ||
		binding.Scope.SourceID == "" || len(binding.Targets) == 0 || !slices.Equal(binding.Targets, binding.Scope.ResourceIDs) {
		return denied("securityonion_call_binding_invalid")
	}
	for _, target := range binding.Targets {
		if !tokenPattern.MatchString(target) {
			return denied("securityonion_call_binding_invalid")
		}
	}
	return nil
}

func decodeEventQueryResult(body []byte, plan OQLPlan) (EventQueryResult, error) {
	var response []eventEnvelope
	if decodeUniqueJSON(body, &response, true) != nil || len(response) != 1 {
		return EventQueryResult{}, denied("securityonion_query_response_invalid")
	}
	envelope := response[0]
	if len(envelope.Errors) != 0 || envelope.Criteria.Query != plan.RenderedQuery ||
		envelope.Criteria.EventLimit != plan.EventLimit || envelope.Criteria.MetricLimit != plan.MetricLimit ||
		envelope.ElapsedMillis > plan.MaximumDurationMillis || !criteriaMatchesRange(envelope.Criteria.BeginTime,
		envelope.Criteria.EndTime, plan.Range) {
		return EventQueryResult{}, denied("securityonion_query_response_mismatch")
	}
	result := EventQueryResult{TotalEvents: envelope.TotalEvents, ElapsedMillis: envelope.ElapsedMillis}
	if plan.Mode == "events" {
		if len(envelope.Events) > int(plan.EventLimit) || len(envelope.Metrics) != 0 ||
			envelope.TotalEvents < uint64(len(envelope.Events)) {
			return EventQueryResult{}, denied("securityonion_event_response_invalid")
		}
		result.Events = make([]EventRecord, len(envelope.Events))
		for index, event := range envelope.Events {
			record, err := projectEvent(event, plan.Columns, plan.TimestampColumn)
			if err != nil {
				return EventQueryResult{}, err
			}
			result.Events[index] = record
		}
		result.EventCapHit = uint64(len(result.Events)) >= plan.EventLimit || envelope.TotalEvents > uint64(len(result.Events))
	} else {
		metrics, capHit, err := projectMetrics(envelope.Metrics, plan.GroupBy, plan.MetricLimit)
		if err != nil || len(envelope.Events) != 0 {
			return EventQueryResult{}, denied("securityonion_metric_response_invalid")
		}
		result.Metrics, result.MetricCapHit = metrics, capHit
	}
	result.ResultDigest = hash("COH-SECURITY-ONION-QUERY-RESULT-V1\x00", mustJSONBytes(result))
	return result, nil
}

type eventEnvelope struct {
	CompleteTime string `json:"completeTime"`
	CreateTime   string `json:"createTime"`
	Criteria     struct {
		BeginTime   string `json:"beginTime"`
		CreateTime  string `json:"createTime"`
		DateRange   string `json:"dateRange"`
		EndTime     string `json:"endTime"`
		EventLimit  uint64 `json:"eventLimit"`
		MetricLimit uint64 `json:"metricLimit"`
		Query       string `json:"query"`
	} `json:"criteria"`
	ElapsedMillis uint64                     `json:"elapsedMs"`
	Errors        []string                   `json:"errors"`
	Events        []vendorEvent              `json:"events"`
	Metrics       map[string]json.RawMessage `json:"metrics"`
	TotalEvents   uint64                     `json:"totalEvents"`
}

type vendorEvent struct {
	ID        string                     `json:"id"`
	Payload   map[string]json.RawMessage `json:"payload"`
	Score     json.RawMessage            `json:"score"`
	Sort      []json.RawMessage          `json:"sort"`
	Source    string                     `json:"source"`
	Time      string                     `json:"time"`
	Timestamp string                     `json:"timestamp"`
	Type      string                     `json:"type"`
}

func projectEvent(event vendorEvent, columns []OQLColumn, timestampColumn string) (EventRecord, error) {
	if !safeVendorText(event.ID, 512) || len(event.Payload) > 4096 {
		return EventRecord{}, denied("securityonion_event_response_invalid")
	}
	payload := make(map[string]any, len(columns))
	for _, column := range columns {
		raw, ok := event.Payload[column.VendorName]
		if !ok {
			return EventRecord{}, denied("securityonion_event_projection_missing")
		}
		value, err := decodeProjectedValue(raw, column.Type)
		if err != nil {
			return EventRecord{}, err
		}
		payload[column.LogicalName] = value
	}
	timestamp, ok := payload[timestampColumn].(string)
	if !ok {
		return EventRecord{}, denied("securityonion_event_timestamp_invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		return EventRecord{}, denied("securityonion_event_timestamp_invalid")
	}
	return EventRecord{ID: event.ID, Timestamp: timestamp, Payload: payload}, nil
}

func decodeProjectedValue(raw json.RawMessage, kind string) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, denied("securityonion_event_field_invalid")
	}
	switch kind {
	case "string", "ip", "timestamp":
		text, ok := value.(string)
		if !ok || !safeVendorText(text, 65536) {
			return nil, denied("securityonion_event_field_type_mismatch")
		}
		if kind == "timestamp" {
			if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
				return nil, denied("securityonion_event_field_type_mismatch")
			}
		} else if kind == "ip" {
			if _, err := netip.ParseAddr(text); err != nil {
				return nil, denied("securityonion_event_field_type_mismatch")
			}
		}
		return text, nil
	case "boolean":
		if typed, ok := value.(bool); ok {
			return typed, nil
		}
	case "integer":
		if number, ok := value.(json.Number); ok && !strings.ContainsAny(number.String(), ".eE") {
			if parsed, err := number.Int64(); err == nil {
				return parsed, nil
			}
		}
	}
	return nil, denied("securityonion_event_field_type_mismatch")
}

func projectMetrics(input map[string]json.RawMessage, groups []OQLColumn, limit uint64) ([]MetricRecord, bool, error) {
	if len(input) != 1 || len(groups) == 0 {
		return nil, false, denied("securityonion_metric_response_invalid")
	}
	var aggregation struct {
		DocCountErrorUpperBound uint64 `json:"doc_count_error_upper_bound"`
		SumOtherDocCount        uint64 `json:"sum_other_doc_count"`
		Buckets                 []struct {
			Key         json.RawMessage `json:"key"`
			KeyAsString string          `json:"key_as_string"`
			DocCount    uint64          `json:"doc_count"`
		} `json:"buckets"`
	}
	for _, raw := range input {
		if decodeUniqueJSON(raw, &aggregation, true) != nil || len(aggregation.Buckets) > int(limit) {
			return nil, false, denied("securityonion_metric_response_invalid")
		}
	}
	result := make([]MetricRecord, len(aggregation.Buckets))
	for index, bucket := range aggregation.Buckets {
		keys, err := decodeMetricKeys(bucket.Key, groups)
		if err != nil || bucket.DocCount == 0 {
			return nil, false, denied("securityonion_metric_response_invalid")
		}
		result[index] = MetricRecord{Keys: keys, Value: bucket.DocCount}
	}
	return result, uint64(len(result)) >= limit || aggregation.SumOtherDocCount != 0 ||
		aggregation.DocCountErrorUpperBound != 0, nil
}

func criteriaMatchesRange(begin, end, planned string) bool {
	parts := strings.Split(planned, " - ")
	if len(parts) != 2 {
		return false
	}
	plannedBegin, beginErr := time.ParseInLocation(connectRangeLayout, parts[0], time.UTC)
	plannedEnd, endErr := time.ParseInLocation(connectRangeLayout, parts[1], time.UTC)
	actualBegin, actualBeginErr := time.Parse(time.RFC3339Nano, begin)
	actualEnd, actualEndErr := time.Parse(time.RFC3339Nano, end)
	return beginErr == nil && endErr == nil && actualBeginErr == nil && actualEndErr == nil &&
		plannedBegin.Equal(actualBegin) && plannedEnd.Equal(actualEnd)
}

func decodeMetricKeys(raw json.RawMessage, groups []OQLColumn) ([]string, error) {
	var values []json.RawMessage
	if len(groups) == 1 {
		values = []json.RawMessage{raw}
	} else if decodeUniqueJSON(raw, &values, false) != nil || len(values) != len(groups) {
		return nil, denied("securityonion_metric_key_invalid")
	}
	result := make([]string, len(values))
	for index, value := range values {
		decoded, err := decodeProjectedValue(value, groups[index].Type)
		if err != nil {
			return nil, err
		}
		result[index] = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(toText(decoded)), "\r", ""), "\n", ""))
		if result[index] == "" {
			return nil, denied("securityonion_metric_key_invalid")
		}
	}
	return result, nil
}

func toText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case int64:
		return strconv.FormatInt(typed, 10)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

func safeVendorText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}
