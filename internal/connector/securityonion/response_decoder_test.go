package securityonion

import (
	"context"
	"encoding/json"
	"testing"
)

func TestEventDecoderProjectsOnlyTypedColumnsAndReportsTruncation(t *testing.T) {
	compiler, qualification := testOQLCompiler(t)
	_, validated, err := compiler.Validate(context.Background(), testOQLQuery(t,
		`{"mode":"events","filter":{"match_all":{}}}`), testOQLSchema(t), qualification)
	if err != nil || validated == nil {
		t.Fatal(err)
	}
	plan := validated.Value()
	envelope := decoderEnvelope(plan)
	envelope["totalEvents"] = 10
	envelope["events"] = []any{map[string]any{"id": "event-1", "payload": map[string]any{
		"@timestamp": "2026-08-27T17:30:00.000Z", "event.id": "event-1", "message": "allowed",
		"source.ip": "10.0.0.1", "secret.value": "discarded"}, "score": 0,
		"sort": []any{"2026-08-27T17:30:00.000Z", "event-1"}, "source": "so:index",
		"time": "2026-08-27T17:30:00.000Z", "timestamp": "2026-08-27T17:30:00.000Z", "type": ""}}
	encoded, _ := json.Marshal([]any{envelope})
	result, err := decodeEventQueryResult(encoded, plan)
	if err != nil || len(result.Events) != 1 || !result.EventCapHit || len(result.Events[0].Payload) != 4 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, leaked := result.Events[0].Payload["secret.value"]; leaked {
		t.Fatal("unprojected vendor field escaped")
	}
}

func TestMetricDecoderAcceptsOnlyBoundedTermsAggregation(t *testing.T) {
	compiler, qualification := testOQLCompiler(t)
	_, validated, err := compiler.Validate(context.Background(), testOQLQuery(t,
		`{"mode":"metrics","filter":{"match_all":{}} ,"group_by":["source_ip"]}`), testOQLSchema(t), qualification)
	if err != nil || validated == nil {
		t.Fatal(err)
	}
	plan := validated.Value()
	envelope := decoderEnvelope(plan)
	envelope["events"] = []any{}
	envelope["totalEvents"] = 10
	envelope["metrics"] = map[string]any{"groupby_0_source_ip": map[string]any{
		"doc_count_error_upper_bound": 0, "sum_other_doc_count": 3,
		"buckets": []any{map[string]any{"key": "10.0.0.1", "doc_count": 7}}}}
	encoded, _ := json.Marshal([]any{envelope})
	result, err := decodeEventQueryResult(encoded, plan)
	if err != nil || len(result.Metrics) != 1 || result.Metrics[0].Keys[0] != "10.0.0.1" ||
		result.Metrics[0].Value != 7 || !result.MetricCapHit {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestDecoderDeniesAmbiguousDriftedAndMalformedResponses(t *testing.T) {
	compiler, qualification := testOQLCompiler(t)
	_, validated, _ := compiler.Validate(context.Background(), testOQLQuery(t,
		`{"mode":"events","filter":{"match_all":{}}}`), testOQLSchema(t), qualification)
	plan := validated.Value()
	valid := decoderEnvelope(plan)
	valid["events"] = []any{}
	cases := map[string][]byte{}
	queryDrift := cloneDecoderEnvelope(valid)
	queryDrift["criteria"].(map[string]any)["query"] = "*"
	cases["query-drift"], _ = json.Marshal([]any{queryDrift})
	rangeDrift := cloneDecoderEnvelope(valid)
	rangeDrift["criteria"].(map[string]any)["beginTime"] = "2026-08-27T16:00:00Z"
	cases["range-drift"], _ = json.Marshal([]any{rangeDrift})
	errorResult := cloneDecoderEnvelope(valid)
	errorResult["errors"] = []string{"all shards failed"}
	cases["embedded-error"], _ = json.Marshal([]any{errorResult})
	unknown := cloneDecoderEnvelope(valid)
	unknown["unexpected"] = true
	cases["unknown-root"], _ = json.Marshal([]any{unknown})
	cases["duplicate"] = []byte(`[{"criteria":{},"criteria":{}}]`)
	cases["multiple"] = []byte(`[{},{}]`)
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeEventQueryResult(input, plan); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func decoderEnvelope(plan OQLPlan) map[string]any {
	return map[string]any{"completeTime": "2026-08-27T18:00:00Z", "createTime": "2026-08-27T17:59:59Z",
		"criteria": map[string]any{"beginTime": "2026-08-27T17:00:00Z", "createTime": "", "dateRange": "",
			"endTime": "2026-08-27T18:00:00Z", "eventLimit": plan.EventLimit,
			"metricLimit": plan.MetricLimit, "query": plan.RenderedQuery},
		"elapsedMs": 4, "errors": []any{}, "events": []any{}, "metrics": map[string]any{}, "totalEvents": 0}
}

func cloneDecoderEnvelope(value map[string]any) map[string]any {
	encoded, _ := json.Marshal(value)
	var result map[string]any
	_ = json.Unmarshal(encoded, &result)
	return result
}
