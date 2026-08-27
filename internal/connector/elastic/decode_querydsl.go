package elastic

import (
	"encoding/json"
	"net"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticquerydsl"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type shardSummary struct {
	Total      uint64            `json:"total"`
	Successful uint64            `json:"successful"`
	Skipped    uint64            `json:"skipped"`
	Failed     uint64            `json:"failed"`
	Failures   []json.RawMessage `json:"failures"`
}

func validShards(value shardSummary) bool {
	return value.Total > 0 && value.Successful == value.Total && value.Skipped == 0 && value.Failed == 0 && len(value.Failures) == 0
}

func decodeQueryValidation(body []byte) (QueryValidationResult, error) {
	var response struct {
		Valid        *bool             `json:"valid"`
		Shards       shardSummary      `json:"_shards"`
		Error        json.RawMessage   `json:"error"`
		Explanations []json.RawMessage `json:"explanations"`
	}
	if decodeVendor(body, &response) != nil || response.Valid == nil || !*response.Valid || !validShards(response.Shards) ||
		len(response.Error) != 0 || len(response.Explanations) != 0 {
		return QueryValidationResult{}, denied("elastic_querydsl_vendor_validation_denied")
	}
	return QueryValidationResult{Valid: true, TotalShards: response.Shards.Total}, nil
}

func decodeOpenPIT(body []byte) (PITResult, error) {
	var response struct {
		ID     string       `json:"id"`
		Shards shardSummary `json:"_shards"`
	}
	if decodeVendor(body, &response) != nil || !validPITID(response.ID) || !validShards(response.Shards) {
		return PITResult{}, denied("elastic_pit_open_response_invalid")
	}
	return PITResult{ID: response.ID, TotalShards: response.Shards.Total}, nil
}

func decodeSearchPIT(body []byte, plan elasticquerydsl.Plan, indices []string, maximumHits uint64) (SearchPITResult, error) {
	var response struct {
		Took         *uint64         `json:"took"`
		TimedOut     *bool           `json:"timed_out"`
		PITID        string          `json:"pit_id"`
		Shards       shardSummary    `json:"_shards"`
		Clusters     json.RawMessage `json:"_clusters"`
		ScrollID     json.RawMessage `json:"_scroll_id"`
		Aggregations json.RawMessage `json:"aggregations"`
		Hits         struct {
			Hits []struct {
				Index       string           `json:"_index"`
				ID          string           `json:"_id"`
				Score       any              `json:"_score"`
				Fields      map[string][]any `json:"fields"`
				Sort        []any            `json:"sort"`
				Source      json.RawMessage  `json:"_source"`
				Ignored     json.RawMessage  `json:"_ignored"`
				IgnoredVals json.RawMessage  `json:"ignored_field_values"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if decodeVendor(body, &response) != nil || response.Took == nil || response.TimedOut == nil || *response.TimedOut ||
		!validPITID(response.PITID) || !validShards(response.Shards) || len(response.Clusters) != 0 ||
		len(response.ScrollID) != 0 || len(response.Aggregations) != 0 || uint64(len(response.Hits.Hits)) > maximumHits {
		return SearchPITResult{}, denied("elastic_pit_search_response_incomplete")
	}
	result := SearchPITResult{PITID: response.PITID, TookMillis: *response.Took,
		TotalShards: response.Shards.Total, Hits: make([]SearchHit, len(response.Hits.Hits))}
	allowed := make(map[string]elasticquerydsl.Column, len(plan.Columns))
	for _, column := range plan.Columns {
		allowed[column.VendorName] = column
	}
	for hitIndex, hit := range response.Hits.Hits {
		if !safeConcreteIndex(hit.Index) || !slices.Contains(indices, hit.Index) || hit.ID == "" || hit.Score != nil || len(hit.Source) != 0 ||
			len(hit.Ignored) != 0 || len(hit.IgnoredVals) != 0 || len(hit.Fields) > len(plan.Columns) {
			return SearchPITResult{}, denied("elastic_pit_search_hit_invalid")
		}
		row := make(map[string]any, len(plan.Columns))
		for vendorName, values := range hit.Fields {
			column, ok := allowed[vendorName]
			if !ok || len(values) != 1 {
				return SearchPITResult{}, denied("elastic_pit_search_fields_invalid")
			}
			converted, err := convertQueryDSLCell(column.Type, values[0])
			if err != nil {
				return SearchPITResult{}, err
			}
			row[column.LogicalName] = converted
		}
		for _, column := range plan.Columns {
			if _, exists := row[column.LogicalName]; !exists {
				row[column.LogicalName] = nil
			}
		}
		sortTuple, err := convertSortTuple(plan.Sort, hit.Sort)
		if err != nil {
			return SearchPITResult{}, err
		}
		result.Hits[hitIndex] = SearchHit{Row: row, Sort: sortTuple}
	}
	return result, nil
}

func decodeClosePIT(body []byte) (ClosePITResult, error) {
	var response struct {
		Succeeded *bool   `json:"succeeded"`
		Freed     *uint64 `json:"num_freed"`
	}
	if decodeVendor(body, &response) != nil || response.Succeeded == nil || response.Freed == nil || !*response.Succeeded {
		return ClosePITResult{}, denied("elastic_pit_close_unconfirmed")
	}
	return ClosePITResult{Succeeded: true, Freed: *response.Freed}, nil
}

func convertSortTuple(fields []elasticquerydsl.SortField, values []any) ([]any, error) {
	if len(fields) != len(values) {
		return nil, denied("elastic_search_after_invalid")
	}
	result := make([]any, len(values))
	for index, value := range values {
		converted, err := convertQueryDSLCell(fields[index].Type, value)
		if err != nil || converted == nil {
			return nil, denied("elastic_search_after_invalid")
		}
		result[index] = converted
	}
	return result, nil
}

func convertQueryDSLCell(kind string, cell any) (any, error) {
	if cell == nil {
		return nil, nil
	}
	switch kind {
	case "string":
		value, ok := cell.(string)
		if !ok || len(value) > 262144 {
			return nil, denied("elastic_querydsl_cell_invalid")
		}
		return value, nil
	case "integer":
		value, ok := cell.(json.Number)
		if !ok {
			return nil, denied("elastic_querydsl_cell_invalid")
		}
		integer, err := value.Int64()
		if err != nil {
			return nil, denied("elastic_querydsl_cell_invalid")
		}
		return integer, nil
	case "boolean":
		value, ok := cell.(bool)
		if !ok {
			return nil, denied("elastic_querydsl_cell_invalid")
		}
		return value, nil
	case "timestamp":
		value, ok := cell.(string)
		if !ok {
			return nil, denied("elastic_querydsl_cell_invalid")
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, denied("elastic_querydsl_cell_invalid")
		}
		return parsed.UTC().Format(time.RFC3339Nano), nil
	case "ip":
		value, ok := cell.(string)
		if !ok || net.ParseIP(value) == nil {
			return nil, denied("elastic_querydsl_cell_invalid")
		}
		return value, nil
	default:
		return nil, queryconnector.NewError(queryconnector.Unsupported, "elastic_querydsl_cell_type_unsupported", nil)
	}
}
