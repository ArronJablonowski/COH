package elastic

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticesql"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (client *HTTPClient) ExecuteESQL(ctx context.Context, request ESQLRequest) (ESQLResult, CallReceipt, error) {
	plan := request.Plan.Value()
	if request.Plan.Digest() == "" || plan.PlanDigest != request.Plan.Digest() || plan.SourceID != client.config.SourceID ||
		len(request.Indices) == 0 || len(request.Indices) > maximumResources || !slices.IsSorted(request.Indices) ||
		duplicate(request.Indices) || len(plan.Columns) == 0 || len(plan.Columns) > 256 || plan.MaximumRows == 0 ||
		plan.MaximumRows > client.config.HardLimits.MaximumRows || plan.MaximumBytes == 0 ||
		plan.MaximumBytes > client.config.HardLimits.MaximumBytes || plan.MaximumDurationMillis == 0 ||
		plan.MaximumDurationMillis > client.config.HardLimits.MaximumDurationMillis {
		return ESQLResult{}, CallReceipt{}, invalid("elastic_esql_request_invalid")
	}
	if err := validateHTTPBinding(request.Binding, "elastic.esql", request.Indices); err != nil {
		return ESQLResult{}, CallReceipt{}, denied("elastic_esql_binding_invalid")
	}
	for _, index := range request.Indices {
		if !safeConcreteIndex(index) {
			return ESQLResult{}, CallReceipt{}, invalid("elastic_esql_target_invalid")
		}
	}
	prefix := "FROM " + plan.ResourceID
	if !strings.HasPrefix(plan.CanonicalPipeline, prefix+" | ") {
		return ESQLResult{}, CallReceipt{}, denied("elastic_esql_plan_invalid")
	}
	vendorQuery := "FROM " + strings.Join(request.Indices, ",") + strings.TrimPrefix(plan.CanonicalPipeline, prefix)
	parameters := make([]any, len(plan.Parameters))
	for index, parameter := range plan.Parameters {
		parameters[index] = parameter.Value
	}
	payload, err := json.Marshal(struct {
		Query    string         `json:"query"`
		Params   []any          `json:"params"`
		Filter   map[string]any `json:"filter"`
		Columnar bool           `json:"columnar"`
	}{Query: vendorQuery, Params: parameters, Filter: plan.MandatoryFilter, Columnar: false})
	if err != nil {
		return ESQLResult{}, CallReceipt{}, invalid("elastic_esql_request_invalid")
	}
	query := url.Values{"format": []string{"json"}, "allow_partial_results": []string{"false"},
		"drop_null_columns": []string{"false"}}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.MaximumDurationMillis)*time.Millisecond)
	defer cancel()
	body, receipt, err := client.doChecked(callCtx, request.Binding, http.MethodPost, "/_query", "", query, payload,
		func(headers http.Header) error {
			if headers.Get("Warning") != "" || headers.Get("X-Elasticsearch-Async-Id") != "" ||
				headers.Get("X-Elasticsearch-Async-Is-Running") != "" ||
				!strings.HasPrefix(strings.ToLower(headers.Get("Content-Type")), "application/json") {
				return denied("elastic_esql_response_warning")
			}
			return nil
		})
	if err != nil {
		return ESQLResult{}, CallReceipt{}, err
	}
	if uint64(len(body)) > plan.MaximumBytes {
		return ESQLResult{}, CallReceipt{}, denied("elastic_esql_response_oversized")
	}
	result, err := decodeESQLResponse(body, plan)
	if err != nil {
		return ESQLResult{}, CallReceipt{}, err
	}
	if result.TookMillis > plan.MaximumDurationMillis {
		return ESQLResult{}, CallReceipt{}, denied("elastic_esql_duration_exceeded")
	}
	result.ResultDigest = digest("COH-ELASTIC-ESQL-RESULT-V1\x00", struct {
		Plan    string
		Result  ESQLResult
		Receipt CallReceipt
	}{request.Plan.Digest(), result, receipt})
	return result, receipt, nil
}

func decodeESQLResponse(body []byte, plan elasticesql.Plan) (ESQLResult, error) {
	var response struct {
		Took           *uint64 `json:"took"`
		IsPartial      *bool   `json:"is_partial"`
		DocumentsFound uint64  `json:"documents_found"`
		ValuesLoaded   uint64  `json:"values_loaded"`
		Columns        []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"columns"`
		Values     [][]any         `json:"values"`
		AllColumns json.RawMessage `json:"all_columns"`
		Clusters   json.RawMessage `json:"_clusters"`
	}
	if err := decodeVendor(body, &response); err != nil || response.Took == nil || response.IsPartial == nil ||
		*response.IsPartial || len(response.AllColumns) != 0 || len(response.Clusters) != 0 ||
		len(response.Columns) != len(plan.Columns) || uint64(len(response.Values)) > plan.MaximumRows {
		return ESQLResult{}, denied("elastic_esql_response_incomplete")
	}
	result := ESQLResult{Columns: append([]elasticesql.Column(nil), plan.Columns...), Rows: make([]map[string]any, 0, len(response.Values)),
		TookMillis: *response.Took, DocumentsFound: response.DocumentsFound, ValuesLoaded: response.ValuesLoaded}
	seen := make(map[string]struct{}, len(response.Columns))
	for index, column := range response.Columns {
		expected := plan.Columns[index]
		if column.Name != expected.VendorName || !compatibleESQLType(expected.Type, column.Type) {
			return ESQLResult{}, conflict("elastic_esql_column_mismatch")
		}
		if _, exists := seen[column.Name]; exists {
			return ESQLResult{}, conflict("elastic_esql_column_duplicate")
		}
		seen[column.Name] = struct{}{}
	}
	for _, row := range response.Values {
		if len(row) != len(plan.Columns) {
			return ESQLResult{}, denied("elastic_esql_row_shape_invalid")
		}
		converted := make(map[string]any, len(row))
		for index, cell := range row {
			value, err := convertESQLCell(plan.Columns[index].Type, cell)
			if err != nil {
				return ESQLResult{}, err
			}
			converted[plan.Columns[index].LogicalName] = value
		}
		result.Rows = append(result.Rows, converted)
	}
	return result, nil
}

func compatibleESQLType(cohType, vendorType string) bool {
	switch cohType {
	case "string":
		return oneOf(vendorType, "keyword", "text", "version", "constant_keyword", "wildcard")
	case "integer":
		return oneOf(vendorType, "byte", "short", "integer", "long", "unsigned_long")
	case "boolean":
		return vendorType == "boolean"
	case "timestamp":
		return oneOf(vendorType, "date", "date_nanos")
	case "ip":
		return vendorType == "ip"
	default:
		return false
	}
}

func convertESQLCell(cohType string, cell any) (any, error) {
	if cell == nil {
		return nil, nil
	}
	switch cohType {
	case "string":
		value, ok := cell.(string)
		if !ok || len(value) > 262144 {
			return nil, denied("elastic_esql_cell_invalid")
		}
		return value, nil
	case "integer":
		value, ok := cell.(json.Number)
		if !ok {
			return nil, denied("elastic_esql_cell_invalid")
		}
		integer, err := value.Int64()
		if err != nil {
			return nil, denied("elastic_esql_cell_invalid")
		}
		return integer, nil
	case "boolean":
		value, ok := cell.(bool)
		if !ok {
			return nil, denied("elastic_esql_cell_invalid")
		}
		return value, nil
	case "timestamp":
		value, ok := cell.(string)
		if !ok {
			return nil, denied("elastic_esql_cell_invalid")
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, denied("elastic_esql_cell_invalid")
		}
		return parsed.UTC().Format(time.RFC3339Nano), nil
	case "ip":
		value, ok := cell.(string)
		if !ok || net.ParseIP(value) == nil {
			return nil, denied("elastic_esql_cell_invalid")
		}
		return value, nil
	default:
		return nil, queryconnector.NewError(queryconnector.Unsupported, "elastic_esql_cell_type_unsupported", nil)
	}
}
