package sentinel

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/kustovalidator"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type runtimeValidatorStub struct {
	calls int
}

func (validator *runtimeValidatorStub) Validate(_ context.Context,
	query queryconnector.ValidatedQuery) (kustovalidator.ValidationAdmission, error) {
	validator.calls++
	value := query.Value()
	canonical := value.NativeText + " | take 100"
	validation := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: value.QueryID, Outcome: "accepted",
		ValidatorVersion: kustovalidator.ValidatorVersion, CanonicalQueryDigest: query.Digest(),
		ProvenanceDigest: sentinelTestDigest("7")}
	decision := kustovalidator.PolicyDecision{QueryID: value.QueryID, ActorID: value.Authority.ActorID,
		CapabilityDigest: value.CapabilityDigest, SchemaDigest: value.SchemaDigest,
		PolicyDecisionDigest: value.Authority.PolicyDecisionDigest, Digest: sentinelTestDigest("8")}
	audit := kustovalidator.AuditProof{QueryID: value.QueryID, ActorID: value.Authority.ActorID,
		AuditReservationDigest: value.Authority.AuditReservationDigest, AuditRecordDigest: sentinelTestDigest("9")}
	return kustovalidator.ValidationAdmission{Validation: validation, CanonicalKQL: canonical,
		CanonicalKQLDigest: kustovalidator.CanonicalKQLDigest(canonical),
		OutputColumns: []kustovalidator.OutputColumn{{Name: "TimeGenerated", Type: "datetime"},
			{Name: "EventRecordId", Type: "string"}}, Decision: decision, Audit: audit}, nil
}

type runtimeQueryClientStub struct {
	calls   []QueryCall
	partial bool
}

type slicingQueryClientStub struct {
	calls []QueryCall
}

type retryQueryClientStub struct {
	calls []QueryCall
}

func (client *retryQueryClientStub) Query(_ context.Context, call QueryCall) (QueryTransportResponse, error) {
	client.calls = append(client.calls, call)
	if len(client.calls) == 1 {
		return QueryTransportResponse{}, queryconnector.NewError(queryconnector.Unavailable, "sentinel_test_outage", nil)
	}
	value := queryTestTransportResponse(call.Request)
	value.Receipt.TransportIdentityDigest = call.Request.TransportIdentityDigest
	value.ResponseDigest = queryTransportResponseDigest(value)
	return DecodeQueryTransportResponse(encodeQueryContract(value))
}

func (client *slicingQueryClientStub) Query(_ context.Context, call QueryCall) (QueryTransportResponse, error) {
	client.calls = append(client.calls, call)
	value := queryTestTransportResponse(call.Request)
	value.Receipt.TransportIdentityDigest = call.Request.TransportIdentityDigest
	if call.Request.SliceNumber == 1 {
		value.Statistics.BytesReturned = 65536
	}
	value.ResponseDigest = queryTransportResponseDigest(value)
	return DecodeQueryTransportResponse(encodeQueryContract(value))
}

func (client *runtimeQueryClientStub) Query(_ context.Context, call QueryCall) (QueryTransportResponse, error) {
	client.calls = append(client.calls, call)
	value := queryTestTransportResponse(call.Request)
	value.Receipt.TransportIdentityDigest = call.Request.TransportIdentityDigest
	if client.partial {
		value.Tables = []QueryTable{}
		value.Statistics.RowsReturned = 0
		value.Error = &QueryAPIError{Code: "PartialError", DetailCodes: []string{"query_timeout"},
			MessageDigest: sentinelTestDigest("0")}
	}
	value.ResponseDigest = queryTransportResponseDigest(value)
	return DecodeQueryTransportResponse(encodeQueryContract(value))
}

func TestQueryRuntimeLifecycleUsesQualifiedValidationAndTransport(t *testing.T) {
	runtime, validator, client, config := sentinelTestQueryRuntime(t, false)
	binding := sentinelTestBinding(config)
	capability, err := runtime.Probe(context.Background(), binding.Scope, binding.Authority)
	if err != nil || !capability.Value().Features.Polling || !capability.Value().Features.Cancellation ||
		!capability.Value().Features.Statistics {
		t.Fatalf("capability=%+v err=%v", capability.Value(), err)
	}
	query := sentinelRuntimeQuery(t, capability.Digest(), binding, 1)
	validation, err := runtime.Validate(context.Background(), query)
	if err != nil || validator.calls != 1 || validation.Value().CanonicalQueryDigest != query.Digest() {
		t.Fatalf("validation=%+v calls=%d err=%v", validation.Value(), validator.calls, err)
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || len(client.calls) != 1 || client.calls[0].Request.TimeRange != query.Value().TimeRange ||
		client.calls[0].Request.CanonicalKQLDigest != kustovalidator.CanonicalKQLDigest(client.calls[0].Request.CanonicalKQL) {
		t.Fatalf("execution=%+v calls=%+v err=%v", execution.Value(), client.calls, err)
	}
	poll, err := runtime.Poll(context.Background(), runtimePollRequest(execution, binding.Authority))
	if err != nil || poll.Value().Outcome != "completed" || poll.Value().Page == nil ||
		poll.Value().Completeness.Status != "complete" || !poll.Value().Completeness.VendorConfirmed ||
		poll.Value().Page.Rows[0]["EventRecordId"] != "event-1" {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
	replay, err := runtime.Poll(context.Background(), runtimePollRequest(execution, binding.Authority))
	if err != nil || replay.Digest() != poll.Digest() {
		t.Fatalf("poll replay=%+v err=%v", replay.Value(), err)
	}
}

func TestQueryRuntimeRejectsPartialErrorAndFencesCancellation(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		runtime, _, _, config := sentinelTestQueryRuntime(t, true)
		binding := sentinelTestBinding(config)
		capability, _ := runtime.Probe(context.Background(), binding.Scope, binding.Authority)
		query := sentinelRuntimeQuery(t, capability.Digest(), binding, 2)
		validation, _ := runtime.Validate(context.Background(), query)
		execution, err := runtime.Execute(context.Background(), query, validation)
		if err != nil {
			t.Fatal(err)
		}
		poll, err := runtime.Poll(context.Background(), runtimePollRequest(execution, binding.Authority))
		if err != nil || poll.Value().Outcome != "failed" || poll.Value().Page != nil ||
			!slices.Equal(poll.Value().Completeness.ReasonCodes, []string{"sentinel_partial_error"}) {
			t.Fatalf("poll=%+v err=%v", poll.Value(), err)
		}
	})

	t.Run("cancel before release", func(t *testing.T) {
		runtime, _, _, config := sentinelTestQueryRuntime(t, false)
		binding := sentinelTestBinding(config)
		capability, _ := runtime.Probe(context.Background(), binding.Scope, binding.Authority)
		query := sentinelRuntimeQuery(t, capability.Digest(), binding, 3)
		validation, _ := runtime.Validate(context.Background(), query)
		execution, _ := runtime.Execute(context.Background(), query, validation)
		request := queryconnector.CancelRequest{QueryID: query.Value().QueryID,
			AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: binding.Authority,
			RequestedAt: sentinelTestNow.Add(time.Second).Format(sentinelTimestampLayout)}
		canceled, err := runtime.Cancel(context.Background(), request)
		if err != nil || canceled.Value().Outcome != "confirmed" {
			t.Fatalf("cancel=%+v err=%v", canceled.Value(), err)
		}
		poll, err := runtime.Poll(context.Background(), runtimePollRequest(execution, binding.Authority))
		if err != nil || poll.Value().Outcome != "canceled" || poll.Value().Page != nil {
			t.Fatalf("poll=%+v err=%v", poll.Value(), err)
		}
	})
}

func TestQueryRuntimePlansContiguousHalfOpenSlicesAndWithholdsUnmergedRows(t *testing.T) {
	client := &slicingQueryClientStub{}
	runtime, config := sentinelTestQueryRuntimeWithClient(t, client)
	binding := sentinelTestBinding(config)
	capability, _ := runtime.Probe(context.Background(), binding.Scope, binding.Authority)
	query := sentinelRuntimeQuery(t, capability.Digest(), binding, 4)
	validation, _ := runtime.Validate(context.Background(), query)
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || len(client.calls) != 3 {
		t.Fatalf("execution=%+v calls=%d err=%v", execution.Value(), len(client.calls), err)
	}
	ranges := []queryconnector.TimeRange{client.calls[0].Request.TimeRange, client.calls[1].Request.TimeRange,
		client.calls[2].Request.TimeRange}
	wanted := []queryconnector.TimeRange{query.Value().TimeRange,
		{Start: "2026-08-27T18:30:00.000000000Z", End: "2026-08-27T19:00:00.000000000Z"},
		{Start: "2026-08-27T19:00:00.000000000Z", End: "2026-08-27T19:30:00.000000000Z"}}
	if !slices.Equal(ranges, wanted) || client.calls[1].Request.TimeRange.End != client.calls[2].Request.TimeRange.Start {
		t.Fatalf("ranges=%v", ranges)
	}
	runtime.mu.Lock()
	job := runtime.jobs[execution.Value().Handle.HandleID]
	runtime.mu.Unlock()
	if job == nil || len(job.responses) != 2 || len(job.plan.Slices) != 3 || job.plan.Slices[0].State != "split" ||
		job.plan.Slices[1].State != "complete" || job.plan.Slices[2].State != "complete" {
		t.Fatalf("job=%+v", job)
	}
	poll, err := runtime.Poll(context.Background(), runtimePollRequest(execution, binding.Authority))
	if err != nil || poll.Value().Page != nil ||
		!slices.Equal(poll.Value().Completeness.ReasonCodes, []string{"sentinel_dedupe_required"}) {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
}

func TestQueryRuntimeFailsClosedWhenSliceLimitPreventsSplit(t *testing.T) {
	client := &slicingQueryClientStub{}
	runtime, config := sentinelTestQueryRuntimeWithClient(t, client)
	binding := sentinelTestBinding(config)
	capability, _ := runtime.Probe(context.Background(), binding.Scope, binding.Authority)
	query := sentinelRuntimeQuery(t, capability.Digest(), binding, 5)
	value := query.Value()
	value.Limits.MaximumSlices = 2
	encoded, _ := json.Marshal(value)
	query, _ = queryconnector.DecodeQuery(context.Background(), encoded)
	validation, _ := runtime.Validate(context.Background(), query)
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || len(client.calls) != 1 {
		t.Fatalf("execution=%+v calls=%d err=%v", execution.Value(), len(client.calls), err)
	}
	poll, err := runtime.Poll(context.Background(), runtimePollRequest(execution, binding.Authority))
	if err != nil || poll.Value().Page != nil ||
		!slices.Equal(poll.Value().Completeness.ReasonCodes, []string{"sentinel_slice_limit_exceeded"}) {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
}

func TestQueryRuntimeRetryReplaysExactUnreleasedSlice(t *testing.T) {
	client := &retryQueryClientStub{}
	runtime, config := sentinelTestQueryRuntimeWithClient(t, client)
	binding := sentinelTestBinding(config)
	capability, _ := runtime.Probe(context.Background(), binding.Scope, binding.Authority)
	query := sentinelRuntimeQuery(t, capability.Digest(), binding, 6)
	validation, _ := runtime.Validate(context.Background(), query)
	if _, err := runtime.Execute(context.Background(), query, validation); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("first execute err=%v", err)
	}
	execution, err := runtime.Execute(context.Background(), query, validation)
	if err != nil || len(client.calls) != 2 ||
		client.calls[0].Request.RequestDigest != client.calls[1].Request.RequestDigest {
		t.Fatalf("execution=%+v calls=%+v err=%v", execution.Value(), client.calls, err)
	}
	poll, err := runtime.Poll(context.Background(), runtimePollRequest(execution, binding.Authority))
	if err != nil || poll.Value().Outcome != "completed" {
		t.Fatalf("poll=%+v err=%v", poll.Value(), err)
	}
}

func sentinelTestQueryRuntime(t *testing.T, partial bool) (*QueryRuntime, *runtimeValidatorStub,
	*runtimeQueryClientStub, Config) {
	t.Helper()
	discovery, _, config := sentinelTestAdapter(t, 256)
	runtimeConfig := QueryRuntimeConfig{SchemaVersion: QueryRuntimeConfigVersion, ContractVersion: ContractVersion,
		DiscoveryConfigDigest: hashValue("COH-SENTINEL-CONFIG-V1\x00", config), SliceSemanticsDigest: sentinelTestDigest("a"),
		HalfOpenQualified: true, MinimumSliceDurationMillis: 1000,
		SplitThresholdRows: 500, SplitThresholdBytes: 65536, MaximumResponseBytes: 262144,
		StableKeys: []StableKeyProfile{{ResourceID: "security-events", TimestampColumn: "TimeGenerated", Columns: []string{"EventRecordId"}}}}
	runtimeConfig.Digest = queryRuntimeConfigDigest(runtimeConfig)
	validator, client := &runtimeValidatorStub{}, &runtimeQueryClientStub{partial: partial}
	runtime, err := NewQueryRuntime(discovery, runtimeConfig, validator, client, discovery.clock)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, validator, client, config
}

func sentinelTestQueryRuntimeWithClient(t *testing.T, client QueryClient) (*QueryRuntime, Config) {
	t.Helper()
	discovery, _, config := sentinelTestAdapter(t, 256)
	runtimeConfig := QueryRuntimeConfig{SchemaVersion: QueryRuntimeConfigVersion, ContractVersion: ContractVersion,
		DiscoveryConfigDigest: hashValue("COH-SENTINEL-CONFIG-V1\x00", config), SliceSemanticsDigest: sentinelTestDigest("a"),
		HalfOpenQualified: true, MinimumSliceDurationMillis: 1000,
		SplitThresholdRows: 500, SplitThresholdBytes: 65536, MaximumResponseBytes: 262144,
		StableKeys: []StableKeyProfile{{ResourceID: "security-events", TimestampColumn: "TimeGenerated", Columns: []string{"EventRecordId"}}}}
	runtimeConfig.Digest = queryRuntimeConfigDigest(runtimeConfig)
	runtime, err := NewQueryRuntime(discovery, runtimeConfig, &runtimeValidatorStub{}, client, discovery.clock)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, config
}

func sentinelRuntimeQuery(t *testing.T, capability string, binding CallBinding,
	suffix int) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion,
		ContractVersion: queryconnector.ContractVersion,
		QueryID:         sentinelDeterministicUUID(sentinelTestNow.Add(time.Duration(suffix)*time.Nanosecond), "query"),
		Scope:           binding.Scope, Authority: binding.Authority, CapabilityDigest: capability,
		SchemaDigest: sentinelTestDigest("6"), Language: "kql",
		NativeText: "SecurityEvent | project TimeGenerated, EventRecordId",
		TimeRange: queryconnector.TimeRange{Start: sentinelTestNow.Add(-time.Hour).Format(sentinelTimestampLayout),
			End: sentinelTestNow.Format(sentinelTimestampLayout)}, Limits: queryconnector.Limits{MaximumRows: 100,
			MaximumBytes: 262144, MaximumDurationMillis: 30000, MaximumPages: 1, MaximumSlices: 8,
			MaximumCostMillionths: 1000, RequestsPerMinute: 2}, RequestedAt: sentinelTestNow.Format(sentinelTimestampLayout),
		Deadline: sentinelTestNow.Add(time.Minute).Format(sentinelTimestampLayout)}
	encoded, _ := json.Marshal(value)
	query, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func runtimePollRequest(execution queryconnector.ValidatedExecution,
	authority queryconnector.AuthorityBinding) queryconnector.PollRequest {
	value := execution.Value()
	return queryconnector.PollRequest{QueryID: value.QueryID, AttemptID: value.AttemptID,
		Handle: value.Handle, Authority: authority}
}
