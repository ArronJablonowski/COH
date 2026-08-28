package sentinel

import (
	"encoding/json"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestQueryRuntimeContracts(t *testing.T) {
	config := queryTestRuntimeConfig()
	if decoded, err := DecodeQueryRuntimeConfig(encodeQueryContract(config)); err != nil || decoded.Digest != config.Digest {
		t.Fatalf("runtime config err=%v decoded=%+v", err, decoded)
	}
	request := queryTestTransportRequest()
	if decoded, err := DecodeQueryTransportRequest(encodeQueryContract(request)); err != nil || decoded.RequestDigest != request.RequestDigest {
		t.Fatalf("request err=%v decoded=%+v", err, decoded)
	}
	response := queryTestTransportResponse(request)
	if decoded, err := DecodeQueryTransportResponse(encodeQueryContract(response)); err != nil || decoded.ResponseDigest != response.ResponseDigest {
		t.Fatalf("response err=%v decoded=%+v", err, decoded)
	}
	plan := queryTestSlicePlan(request)
	if decoded, err := DecodeSlicePlan(encodeQueryContract(plan)); err != nil || decoded.PlanDigest != plan.PlanDigest {
		t.Fatalf("plan err=%v decoded=%+v", err, decoded)
	}
}

func TestQueryRuntimeContractsDenyTamperAndPartialRows(t *testing.T) {
	tests := []struct {
		name   string
		data   interface{}
		decode func([]byte) error
	}{
		{name: "config digest", data: mutateRuntimeConfig(queryTestRuntimeConfig()), decode: func(input []byte) error { _, err := DecodeQueryRuntimeConfig(input); return err }},
		{name: "request timespan", data: mutateQueryRequest(queryTestTransportRequest()), decode: func(input []byte) error { _, err := DecodeQueryTransportRequest(input); return err }},
		{name: "response partial rows", data: partialRowsResponse(queryTestTransportRequest()), decode: func(input []byte) error { _, err := DecodeQueryTransportResponse(input); return err }},
		{name: "plan parent", data: mutateSlicePlan(queryTestSlicePlan(queryTestTransportRequest())), decode: func(input []byte) error { _, err := DecodeSlicePlan(input); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, _ := json.Marshal(test.data)
			if err := test.decode(encoded); err == nil {
				t.Fatal("tampered contract accepted")
			}
		})
	}
}

func queryTestRuntimeConfig() QueryRuntimeConfig {
	value := QueryRuntimeConfig{SchemaVersion: QueryRuntimeConfigVersion, ContractVersion: ContractVersion,
		DiscoveryConfigDigest: sentinelTestDigest("1"), MinimumSliceDurationMillis: 1000,
		SplitThresholdRows: 500, SplitThresholdBytes: 65536, MaximumResponseBytes: 262144,
		StableKeys: []StableKeyProfile{{ResourceID: "security-events", TimestampColumn: "TimeGenerated", Columns: []string{"EventRecordId"}}}}
	value.Digest = queryRuntimeConfigDigest(value)
	return value
}

func queryTestTransportRequest() QueryTransportRequest {
	value := QueryTransportRequest{SchemaVersion: QueryRequestVersion, ContractVersion: ContractVersion,
		Operation: QueryOperation, QueryID: "018f0000-0000-7000-8000-000000000001",
		AttemptID: "018f0000-0000-7000-8000-000000000002", SliceNumber: 1, SourceID: "sentinel-primary",
		WorkspaceID: "22222222-2222-2222-2222-222222222222", ScopeDigest: sentinelTestDigest("1"),
		AuthorityDigest: sentinelTestDigest("2"), CapabilityDigest: sentinelTestDigest("3"), SchemaDigest: sentinelTestDigest("4"),
		QualificationDigest: sentinelTestDigest("5"), CommonQueryDigest: sentinelTestDigest("6"), ValidationDigest: sentinelTestDigest("7"),
		CanonicalKQL: "SecurityEvent | take 500", PolicyDecisionDigest: sentinelTestDigest("9"), AuditRecordDigest: sentinelTestDigest("a"),
		TimeRange:   queryconnector.TimeRange{Start: "2026-08-27T00:00:00.000000000Z", End: "2026-08-27T01:00:00.000000000Z"},
		MaximumRows: 500, MaximumBytes: 262144, ServerWaitSeconds: 30, TransportIdentityDigest: sentinelTestDigest("b")}
	value.CanonicalKQLDigest = queryCanonicalKQLDigest(value.CanonicalKQL)
	value.RequestDigest = queryTransportRequestDigest(value)
	return value
}

func queryTestTransportResponse(request QueryTransportRequest) QueryTransportResponse {
	value := QueryTransportResponse{SchemaVersion: QueryResponseVersion, ContractVersion: ContractVersion,
		RequestDigest: request.RequestDigest, Tables: []QueryTable{{Name: "PrimaryResult",
			Columns: []QueryColumn{{Name: "TimeGenerated", Type: "datetime"}, {Name: "EventRecordId", Type: "string"}},
			Rows:    [][]interface{}{{"2026-08-27T00:30:00.000000000Z", "event-1"}}}},
		Statistics: QueryStatistics{RowsScanned: 1, RowsReturned: 1, BytesReturned: 96, DurationMillis: 5,
			ResourceUsageDigest: sentinelTestDigest("c")}, Receipt: QueryReceipt{Operation: QueryOperation, HTTPStatus: 200,
			RequestDigest: request.RequestDigest, VendorResponseDigest: sentinelTestDigest("d"), LeaseDecisionDigest: sentinelTestDigest("e"),
			TransportDigest: sentinelTestDigest("f"), TransportIdentityDigest: request.TransportIdentityDigest}}
	value.ResponseDigest = queryTransportResponseDigest(value)
	return value
}

func queryTestSlicePlan(request QueryTransportRequest) SlicePlan {
	value := SlicePlan{SchemaVersion: SlicePlanVersion, ContractVersion: ContractVersion, QueryID: request.QueryID,
		AttemptID: request.AttemptID, OriginalTimeRange: request.TimeRange, MaximumSlices: 8, MinimumDurationMS: 1000,
		SplitThresholdRows: 500, SplitThresholdBytes: 65536,
		Slices: []SliceRecord{{Number: 1, TimeRange: request.TimeRange, State: "planned"}}}
	value.PlanDigest = slicePlanDigest(value)
	return value
}

func mutateRuntimeConfig(value QueryRuntimeConfig) QueryRuntimeConfig {
	value.SplitThresholdRows++
	return value
}
func mutateQueryRequest(value QueryTransportRequest) QueryTransportRequest {
	value.TimeRange.End = value.TimeRange.Start
	return value
}
func mutateSlicePlan(value SlicePlan) SlicePlan {
	value.Slices[0].Parent = 1
	value.PlanDigest = slicePlanDigest(value)
	return value
}

func partialRowsResponse(request QueryTransportRequest) QueryTransportResponse {
	value := queryTestTransportResponse(request)
	value.Error = &QueryAPIError{Code: "PartialError", DetailCodes: []string{"query_timeout"}, MessageDigest: sentinelTestDigest("0")}
	value.ResponseDigest = queryTransportResponseDigest(value)
	return value
}
