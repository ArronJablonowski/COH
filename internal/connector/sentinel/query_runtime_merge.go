package sentinel

import (
	"slices"
	"sort"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type mergedSentinelRow struct {
	identity        string
	rowDigest       string
	timestamp       string
	keyValues       []interface{}
	keyKinds        []string
	values          []interface{}
	responseDigests []string
	boundaryOrigin  bool
}

type mergedSentinelResult struct {
	columns    []QueryColumn
	rows       [][]interface{}
	statistics queryconnector.Statistics
	provenance string
}

func (runtime *QueryRuntime) mergeResults(job *sentinelQueryJob) (mergedSentinelResult, error) {
	profile, err := runtime.profileForScope(job.query.Scope.ResourceIDs)
	if err != nil {
		return mergedSentinelResult{}, err
	}
	leaves, err := completedLeaves(job.plan)
	if err != nil || len(leaves) != len(job.responses) {
		return mergedSentinelResult{}, deniedCall("sentinel_slice_coverage_invalid")
	}
	requests := make(map[string]QueryTransportRequest, len(job.requests))
	for _, request := range job.requests {
		requests[request.RequestDigest] = request
	}
	responses := make(map[string]QueryTransportResponse, len(job.responses))
	for _, response := range job.responses {
		responses[response.RequestDigest] = response
	}
	var columns []QueryColumn
	seen := map[string]*mergedSentinelRow{}
	var statistics queryconnector.Statistics
	for index, leaf := range leaves {
		request, requestOK := requests[leaf.RequestDigest]
		response, responseOK := responses[leaf.RequestDigest]
		if !requestOK || !responseOK || response.ResponseDigest != leaf.ResponseDigest || response.Error != nil ||
			len(response.Tables) != 1 || !outputSchemaMatches(job.admission.OutputColumns, response.Tables[0].Columns) {
			return mergedSentinelResult{}, conflictCall("sentinel_result_schema_mismatch")
		}
		table := response.Tables[0]
		if columns == nil {
			columns = slices.Clone(table.Columns)
		} else if !slices.Equal(columns, table.Columns) {
			return mergedSentinelResult{}, conflictCall("sentinel_result_schema_mismatch")
		}
		timestampIndex, keyIndices, keyKinds, ok := stableColumnIndices(columns, profile)
		if !ok {
			return mergedSentinelResult{}, deniedCall("sentinel_identical_timestamp_ambiguous")
		}
		if err := mergeSliceRows(seen, table, request, response.ResponseDigest, timestampIndex, keyIndices, keyKinds,
			index == len(leaves)-1); err != nil {
			return mergedSentinelResult{}, err
		}
		statistics.RowsScanned += response.Statistics.RowsScanned
		statistics.BytesReturned += response.Statistics.BytesReturned
		statistics.DurationMillis += response.Statistics.DurationMillis
		statistics.SlicesCompleted++
	}
	if statistics.BytesReturned > job.query.Limits.MaximumBytes ||
		statistics.DurationMillis > job.query.Limits.MaximumDurationMillis {
		return mergedSentinelResult{}, deniedCall("sentinel_aggregate_limit_exceeded")
	}
	ordered := make([]*mergedSentinelRow, 0, len(seen))
	for _, row := range seen {
		slices.Sort(row.responseDigests)
		row.responseDigests = slices.Compact(row.responseDigests)
		if row.boundaryOrigin && len(row.responseDigests) < 2 {
			return mergedSentinelResult{}, deniedCall("sentinel_row_outside_slice")
		}
		ordered = append(ordered, row)
	}
	sort.Slice(ordered, func(left, right int) bool { return compareStableRows(ordered[left], ordered[right]) < 0 })
	rows := make([][]interface{}, len(ordered))
	lineage := make([]interface{}, len(ordered))
	for index, row := range ordered {
		rows[index] = slices.Clone(row.values)
		lineage[index] = struct {
			Identity, RowDigest string
			Responses           []string
		}{row.identity, row.rowDigest, row.responseDigests}
	}
	if uint64(len(rows)) > job.query.Limits.MaximumRows {
		return mergedSentinelResult{}, deniedCall("sentinel_aggregate_limit_exceeded")
	}
	statistics.RowsReturned, statistics.PagesReturned = uint64(len(rows)), 1
	return mergedSentinelResult{columns: columns, rows: rows, statistics: statistics,
		provenance: hashValue("COH-SENTINEL-MERGE-PROVENANCE-V1\x00", struct {
			Plan, Semantics string
			Lineage         []interface{}
		}{job.plan.PlanDigest, runtime.config.SliceSemanticsDigest, lineage})}, nil
}

func completedLeaves(plan SlicePlan) ([]SliceRecord, error) {
	parents := map[uint32]struct{}{}
	for _, record := range plan.Slices {
		if record.Parent != 0 {
			parents[record.Parent] = struct{}{}
		}
	}
	leaves := make([]SliceRecord, 0)
	for _, record := range plan.Slices {
		if _, parent := parents[record.Number]; parent {
			if record.State != "split" {
				return nil, deniedCall("sentinel_slice_coverage_invalid")
			}
			continue
		}
		if record.State != "complete" {
			return nil, deniedCall("sentinel_slice_coverage_invalid")
		}
		leaves = append(leaves, record)
	}
	sort.Slice(leaves, func(left, right int) bool { return leaves[left].TimeRange.Start < leaves[right].TimeRange.Start })
	if len(leaves) == 0 || leaves[0].TimeRange.Start != plan.OriginalTimeRange.Start ||
		leaves[len(leaves)-1].TimeRange.End != plan.OriginalTimeRange.End {
		return nil, deniedCall("sentinel_slice_coverage_invalid")
	}
	for index := 1; index < len(leaves); index++ {
		if leaves[index-1].TimeRange.End != leaves[index].TimeRange.Start {
			return nil, deniedCall("sentinel_slice_coverage_invalid")
		}
	}
	return leaves, nil
}

func (runtime *QueryRuntime) profileForScope(resourceIDs []string) (StableKeyProfile, error) {
	profiles := make(map[string]StableKeyProfile, len(runtime.config.StableKeys))
	for _, profile := range runtime.config.StableKeys {
		profiles[profile.ResourceID] = profile
	}
	var selected StableKeyProfile
	for index, resourceID := range resourceIDs {
		profile, ok := profiles[resourceID]
		if !ok {
			return StableKeyProfile{}, deniedCall("sentinel_identical_timestamp_ambiguous")
		}
		if index == 0 {
			selected = profile
			continue
		}
		if profile.TimestampColumn != selected.TimestampColumn || !slices.Equal(profile.Columns, selected.Columns) {
			return StableKeyProfile{}, deniedCall("sentinel_identical_timestamp_ambiguous")
		}
	}
	if selected.TimestampColumn == "" || len(selected.Columns) == 0 {
		return StableKeyProfile{}, deniedCall("sentinel_identical_timestamp_ambiguous")
	}
	return selected, nil
}

func stableColumnIndices(columns []QueryColumn, profile StableKeyProfile) (int, []int, []string, bool) {
	timestampIndex := -1
	indices := make([]int, len(profile.Columns))
	kinds := make([]string, len(profile.Columns))
	for index := range indices {
		indices[index] = -1
	}
	for index, column := range columns {
		if column.Name == profile.TimestampColumn && column.Type == "datetime" {
			timestampIndex = index
		}
		for keyIndex, name := range profile.Columns {
			if column.Name == name {
				indices[keyIndex] = index
				kinds[keyIndex] = column.Type
			}
		}
	}
	return timestampIndex, indices, kinds, timestampIndex >= 0 && !slices.Contains(indices, -1) &&
		!slices.Contains(kinds, "timespan")
}

func mergeSliceRows(seen map[string]*mergedSentinelRow, table QueryTable, request QueryTransportRequest,
	responseDigest string, timestampIndex int, keyIndices []int, keyKinds []string, finalSlice bool) error {
	start, startOK := queryTime(request.TimeRange.Start)
	end, endOK := queryTime(request.TimeRange.End)
	if !startOK || !endOK || !start.Before(end) {
		return deniedCall("sentinel_slice_coverage_invalid")
	}
	var previous *mergedSentinelRow
	for _, values := range table.Rows {
		timestampText, ok := values[timestampIndex].(string)
		timestamp, timestampOK := queryTime(timestampText)
		if !ok || !timestampOK || timestamp.Before(start) || timestamp.After(end) || finalSlice && !timestamp.Before(end) {
			return deniedCall("sentinel_row_outside_slice")
		}
		keyValues := make([]interface{}, len(keyIndices))
		for index, columnIndex := range keyIndices {
			if values[columnIndex] == nil {
				return deniedCall("sentinel_identical_timestamp_ambiguous")
			}
			keyValues[index] = values[columnIndex]
		}
		candidate := &mergedSentinelRow{timestamp: timestampText, keyValues: keyValues, keyKinds: keyKinds}
		if previous != nil && compareStableRows(previous, candidate) > 0 {
			return deniedCall("sentinel_stable_order_invalid")
		}
		previous = candidate
		identity := hashValue("COH-SENTINEL-STABLE-ROW-IDENTITY-V1\x00", struct {
			Scope     string
			Timestamp string
			Key       []interface{}
		}{request.ScopeDigest, timestampText, keyValues})
		rowDigest := hashValue("COH-SENTINEL-STABLE-ROW-V1\x00", struct {
			Columns []QueryColumn
			Values  []interface{}
		}{table.Columns, values})
		if prior, exists := seen[identity]; exists {
			if prior.rowDigest != rowDigest {
				return conflictCall("sentinel_stable_key_conflict")
			}
			prior.responseDigests = append(prior.responseDigests, responseDigest)
			continue
		}
		seen[identity] = &mergedSentinelRow{identity: identity, rowDigest: rowDigest, timestamp: timestampText,
			keyValues: slices.Clone(keyValues), keyKinds: slices.Clone(keyKinds), values: slices.Clone(values),
			responseDigests: []string{responseDigest}, boundaryOrigin: timestamp.Equal(end)}
	}
	return nil
}

func compareStableRows(left, right *mergedSentinelRow) int {
	if compared := strings.Compare(left.timestamp, right.timestamp); compared != 0 {
		return compared
	}
	for index := range left.keyValues {
		if compared := compareStableValue(left.keyKinds[index], left.keyValues[index], right.keyValues[index]); compared != 0 {
			return compared
		}
	}
	return 0
}

func compareStableValue(kind string, left, right interface{}) int {
	switch kind {
	case "bool":
		leftValue, rightValue := left.(bool), right.(bool)
		if leftValue == rightValue {
			return 0
		}
		if !leftValue {
			return -1
		}
		return 1
	case "int", "long", "real", "decimal":
		leftValue, rightValue := left.(float64), right.(float64)
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
		return 0
	default:
		return strings.Compare(left.(string), right.(string))
	}
}
