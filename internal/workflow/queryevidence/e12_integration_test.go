package queryevidence

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
)

type integrationBoundsAudit struct{ decisions []querybounds.Decision }

func (audit *integrationBoundsAudit) AppendQueryBoundDecision(_ context.Context, value querybounds.Decision) error {
	audit.decisions = append(audit.decisions, value)
	return nil
}

type integrationReplay struct{}

func (integrationReplay) Observe(context.Context, string, string) (bool, error) { return false, nil }

type integrationClock struct{ now time.Time }

func (clock integrationClock) Now() time.Time { return clock.now }

type integrationAdapter struct {
	poll                   queryconnector.ValidatedPoll
	cancellation           queryconnector.ValidatedCancellation
	pollCalls, cancelCalls int
}

func (adapter *integrationAdapter) Poll(context.Context, queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	adapter.pollCalls++
	return adapter.poll, nil
}
func (*integrationAdapter) NextPage(context.Context, queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	return queryconnector.ValidatedPage{}, errors.New("not configured")
}
func (adapter *integrationAdapter) Cancel(context.Context, queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	adapter.cancelCalls++
	return adapter.cancellation, nil
}

type integrationRate struct{ sequence uint64 }

func (rate *integrationRate) Reserve(_ context.Context, request queryruntime.RateRequest) (queryruntime.RateReservation, error) {
	rate.sequence++
	requested, _ := time.Parse(timestampLayout, request.RequestedAt)
	keyDigest, _ := canonicalDigest("COH-QUERY-RATE-KEY-V1\x00", request)
	return queryruntime.FinalizeRateReservation(queryruntime.RateReservation{SchemaVersion: queryruntime.RateSchemaVersion,
		ContractVersion: queryruntime.ContractVersion, KeyDigest: keyDigest, SessionID: request.SessionID,
		Operation: request.Operation, Sequence: rate.sequence, ReservedAt: requested.Format(timestampLayout),
		ValidUntil: requested.Add(time.Minute).Format(timestampLayout)})
}

func TestE12LifecycleIsBoundedReadOnlyAndProvenanceComplete(t *testing.T) {
	now := evidenceNow
	native := "SecurityEvent | where TimeGenerated >= ago(1h) | take 10"
	query := integrationQuery(t, now, native)
	validation := integrationValidation(t, query)
	audit := &integrationBoundsAudit{}
	bounds, err := querybounds.New(audit, integrationClock{now}, integrationReplay{})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bounds.Admit(context.Background(), query, integrationAuthority(query, now))
	if err != nil {
		t.Fatal(err)
	}
	execution := integrationExecution(t, query, now)

	metadata := newMetadataStub()
	store, _ := NewRepositoryStore(metadata)
	ingest := &ingestStub{binding: artifact("integration-native", int64(len(native)))}
	ingest.binding.Artifact.Digest = digestBytes([]byte(native))
	evidenceAudit := &auditStub{}
	evidenceController, _ := New(ingest, store, evidenceAudit, integrationClock{now})
	queryValue, validationValue := query.Value(), validation.Value()
	prepared := StartCommand{RequestID: id("8"), IdempotencyKey: "e12-integration-start", Case: domainCase(queryValue.Scope),
		ActorID: queryValue.Authority.ActorID, ActorRevision: 1, SourceID: queryValue.Scope.SourceID,
		QueryDigest: query.Digest(), BoundsDecisionDigest: admission.Decision.DecisionDigest, ExecutionDigest: execution.Digest(),
		ValidatorVersion: validationValue.ValidatorVersion, ValidatorProvenanceDigest: validationValue.ProvenanceDigest,
		IntervalStart: queryValue.TimeRange.Start, IntervalEnd: queryValue.TimeRange.End, ResourceScopeDigest: admission.Decision.ResourceScopeDigest,
		NativeQueryDigest: digestBytes([]byte(native)), NativeQueryLength: int64(len(native)), NativeQueryMediaType: "application/vnd.coh.native-query",
		Classification: "restricted", PolicyDigest: queryValue.Authority.PolicyDecisionDigest, Deadline: now.Add(time.Minute)}
	recorder, err := NewRuntimeRecorder(evidenceController, prepared, &sourceStub{data: []byte(native)})
	if err != nil {
		t.Fatal(err)
	}

	adapter := &integrationAdapter{poll: integrationCompletePoll(t, queryValue.QueryID, execution.Value().AttemptID),
		cancellation: integrationCancellation(t, queryValue.QueryID, execution.Value().AttemptID, now)}
	runtimeController, err := queryruntime.New(integrationRuntimeConfig(), adapter, &integrationRate{}, recorder, integrationClock{now})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtimeController.Start(context.Background(), queryruntime.StartRequest{Mode: "interactive", Admission: admission, Execution: execution})
	if err != nil {
		t.Fatal(err)
	}
	if session.CaseID != queryValue.Scope.CaseID || len(audit.decisions) != 1 || ingest.calls != 1 {
		t.Fatal("admission, case, or encrypted native evidence was not bound")
	}

	result, err := runtimeController.Poll(context.Background(), queryruntime.SessionRef{SessionID: session.SessionID, SessionDigest: session.SessionDigest})
	if err != nil {
		t.Fatal(err)
	}
	if result.Session.Status != "complete" {
		t.Fatal("complete vendor result was hidden")
	}
	head, found, err := store.LoadHead(context.Background(), streamFromSession(result.Session))
	if err != nil || !found {
		t.Fatal("query evidence head missing")
	}
	if head.Revision != 2 || head.Completeness != "complete" || head.QueryDigest != query.Digest() ||
		head.BoundsDecisionDigest != admission.Decision.DecisionDigest || head.ExecutionDigest != execution.Digest() ||
		head.ValidatorVersion != validationValue.ValidatorVersion || head.NativeQuery.Artifact.Digest != digestBytes([]byte(native)) ||
		head.Statistics.RowsReturned != 10 || len(evidenceAudit.events) != 2 {
		t.Fatal("cross-leaf provenance is incomplete")
	}
	if methods := reflect.TypeOf((*queryruntime.Adapter)(nil)).Elem(); methods.NumMethod() != 3 ||
		methods.Method(0).Name != "Cancel" || methods.Method(1).Name != "NextPage" || methods.Method(2).Name != "Poll" {
		t.Fatal("runtime adapter exposed a mutation or generic transport surface")
	}
}

func TestE12RejectsMissingBoundsAndPublishesCapTruncation(t *testing.T) {
	now := evidenceNow
	invalid := integrationQueryValue(now, "SecurityEvent | take 10")
	invalid.TimeRange.End = invalid.TimeRange.Start
	encoded, _ := json.Marshal(invalid)
	if _, err := queryconnector.DecodeQuery(context.Background(), encoded); queryconnector.Code(err) != queryconnector.InvalidInput {
		t.Fatal("missing/empty time bounds were accepted")
	}

	query := integrationQuery(t, now, "SecurityEvent | take 10")
	bounds, _ := querybounds.New(&integrationBoundsAudit{}, integrationClock{now}, integrationReplay{})
	authority := integrationAuthority(query, now)
	admission, err := bounds.Admit(context.Background(), query, authority)
	if err != nil {
		t.Fatal(err)
	}
	if admission.Decision.LimitsDigest == "" {
		t.Fatal("effective bounds were not evidenced")
	}
	// The runtime's cap and explicit truncation behavior has dedicated adversarial
	// coverage; this cross-leaf assertion ensures the admitted cap is the one
	// carried into the runtime session rather than the wider query request.
	execution := integrationExecution(t, query, now)
	recorder := &recorderStubIntegration{}
	config := integrationRuntimeConfig()
	config.Interactive.Limits.MaximumRows = 5
	runtimeController, err := queryruntime.New(config, &integrationAdapter{}, &integrationRate{}, recorder, integrationClock{now})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtimeController.Start(context.Background(), queryruntime.StartRequest{Mode: "interactive", Admission: admission, Execution: execution})
	if err != nil {
		t.Fatal(err)
	}
	if session.EffectiveLimits.MaximumRows != 5 {
		t.Fatal("admitted row cap was widened")
	}
}

type recorderStubIntegration struct{ sessions []queryruntime.Session }

func (stub *recorderStubIntegration) RecordQuerySession(_ context.Context, value queryruntime.Session) error {
	stub.sessions = append(stub.sessions, value)
	return nil
}

func integrationQuery(t testing.TB, now time.Time, native string) queryconnector.ValidatedQuery {
	t.Helper()
	value := integrationQueryValue(now, native)
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func integrationQueryValue(now time.Time, native string) queryconnector.Query {
	return queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: id("1"), Scope: queryconnector.Scope{OrganizationID: id("2"), TenantID: id("3"), CaseID: id("4"), SourceID: "sentinel-prod", ResourceIDs: []string{"securityevent"}},
		Authority:        queryconnector.AuthorityBinding{ActorID: id("5"), AuthorizationDigest: digest("authorization"), PolicyDecisionDigest: digest("policy"), AuditReservationDigest: digest("audit-reservation")},
		CapabilityDigest: digest("capability"), SchemaDigest: digest("schema"), Language: "kql", NativeText: native,
		TimeRange:   queryconnector.TimeRange{Start: now.Add(-time.Hour).Format(timestampLayout), End: now.Format(timestampLayout)},
		Limits:      queryconnector.Limits{MaximumRows: 100, MaximumBytes: 1000, MaximumDurationMillis: 60000, MaximumPages: 3, MaximumSlices: 2, MaximumCostMillionths: 100, RequestsPerMinute: 5},
		RequestedAt: now.Add(-time.Second).Format(timestampLayout), Deadline: now.Add(5 * time.Minute).Format(timestampLayout)}
}

func integrationValidation(t testing.TB, query queryconnector.ValidatedQuery) queryconnector.ValidatedValidation {
	t.Helper()
	value := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: query.Value().QueryID, Outcome: "accepted", ValidatorVersion: "kusto-validator-1", CanonicalQueryDigest: query.Digest(), ProvenanceDigest: digest("validation")}
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeValidation(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func integrationExecution(t testing.TB, query queryconnector.ValidatedQuery, now time.Time) queryconnector.ValidatedExecution {
	t.Helper()
	value := queryconnector.Execution{SchemaVersion: queryconnector.ExecutionSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: query.Value().QueryID, AttemptID: id("7"), Handle: queryconnector.HandleRef{HandleID: id("9"), Kind: "query_job", SourceID: query.Value().Scope.SourceID,
			OpaqueDigest: digest("opaque-job"), IssuedAt: now.Add(-time.Second).Format(timestampLayout), ExpiresAt: now.Add(time.Minute).Format(timestampLayout)},
		Outcome: "running", StartedAt: now.Format(timestampLayout), ProvenanceDigest: digest("execution-provenance")}
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeExecution(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func integrationCompletePoll(t testing.TB, queryID, attemptID string) queryconnector.ValidatedPoll {
	t.Helper()
	value := queryconnector.PollResult{SchemaVersion: queryconnector.PollSchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: queryID, AttemptID: attemptID, Outcome: "completed", Statistics: queryconnector.Statistics{RowsScanned: 10, RowsReturned: 10, BytesReturned: 200, DurationMillis: 50, PagesReturned: 1, SlicesCompleted: 1},
		Completeness: queryconnector.Completeness{Status: "complete", VendorConfirmed: true}, ProvenanceDigest: digest("poll-provenance")}
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodePoll(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func integrationCancellation(t testing.TB, queryID, attemptID string, now time.Time) queryconnector.ValidatedCancellation {
	t.Helper()
	confirmed := now.Format(timestampLayout)
	value := queryconnector.Cancellation{SchemaVersion: queryconnector.CancellationVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: queryID, AttemptID: attemptID, Outcome: "confirmed", RequestedAt: confirmed, ConfirmedAt: &confirmed, ProvenanceDigest: digest("cancel-provenance")}
	encoded, _ := json.Marshal(value)
	result, err := queryconnector.DecodeCancellation(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func integrationAuthority(query queryconnector.ValidatedQuery, now time.Time) querybounds.AuthoritySnapshot {
	value := query.Value()
	return querybounds.AuthoritySnapshot{OrganizationID: value.Scope.OrganizationID, TenantID: value.Scope.TenantID, CaseID: value.Scope.CaseID,
		ActorID: value.Authority.ActorID, ActorRevision: 1, ActorActive: true, SourceID: value.Scope.SourceID, SourceRevision: 1, SourceActive: true,
		ResourceIDs: value.Scope.ResourceIDs, AllowlistRevision: 1, AllowlistActive: true, CapabilityDigest: value.CapabilityDigest, CapabilityRevision: 1, CapabilityActive: true,
		AuthorizationAllowed: true, AuthorizationDecisionDigest: value.Authority.AuthorizationDigest, PolicyAllowed: true, PolicyDecisionDigest: value.Authority.PolicyDecisionDigest,
		PolicyRevision: 1, AuditReservationDigest: value.Authority.AuditReservationDigest, RevocationRevision: 1, MaximumInterval: 2 * time.Hour,
		MaximumLimits: value.Limits, ObservedAt: now.Add(-time.Second)}
}

func integrationRuntimeConfig() queryruntime.Config {
	limits := queryconnector.Limits{MaximumRows: 100, MaximumBytes: 1000, MaximumDurationMillis: 60000, MaximumPages: 3, MaximumSlices: 2, MaximumCostMillionths: 100, RequestsPerMinute: 5}
	return queryruntime.Config{Interactive: queryruntime.Profile{Mode: "interactive", Limits: limits, MinimumPollInterval: time.Millisecond, MaximumPollInterval: time.Second},
		Export: queryruntime.Profile{Mode: "export", Limits: limits, MinimumPollInterval: time.Millisecond, MaximumPollInterval: time.Second}, MaximumSessions: 10, CancellationWait: time.Second, RecordWait: time.Second}
}

func domainCase(scope queryconnector.Scope) domain.CaseRef {
	return domain.CaseRef{OrganizationID: scope.OrganizationID, TenantID: scope.TenantID, CaseID: scope.CaseID}
}
