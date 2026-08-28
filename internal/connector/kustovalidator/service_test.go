package kustovalidator

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var serviceNow = time.Date(2026, 8, 28, 2, 0, 30, 0, time.UTC)

type serviceClock struct{ now time.Time }

func (clock serviceClock) Now() time.Time { return clock.now }

type serviceHelper struct {
	calls  int
	fail   error
	denied bool
	wait   bool
	delay  time.Duration
	mu     sync.Mutex
}

func (helper *serviceHelper) Validate(ctx context.Context, request HelperRequest) (HelperResponse, error) {
	helper.mu.Lock()
	helper.calls++
	helper.mu.Unlock()
	if helper.delay > 0 {
		time.Sleep(helper.delay)
	}
	if helper.wait {
		<-ctx.Done()
		return HelperResponse{}, ctx.Err()
	}
	if helper.fail != nil {
		return HelperResponse{}, helper.fail
	}
	canonical := request.Query + " | take 500"
	response := HelperResponse{SchemaVersion: HelperResponseVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, RequestDigest: request.RequestDigest, Outcome: "accepted",
		ReasonCodes: []string{}, Diagnostics: []Diagnostic{}, CanonicalKQL: canonical,
		CanonicalKQLDigest: CanonicalKQLDigest(canonical), OriginalTreeDigest: repeatDigest("4"),
		BoundedTreeDigest: repeatDigest("5"), Semantic: SemanticInventory{Tables: []string{"SecurityEvent"},
			Columns:   []string{"SecurityEvent.Computer", "SecurityEvent.EventID", "SecurityEvent.TimeGenerated"},
			Operators: []string{"project", "take", "where"}, Functions: []string{}},
		OutputColumns: []OutputColumn{{Name: "TimeGenerated", Type: "datetime"}, {Name: "Computer", Type: "string"}, {Name: "EventID", Type: "int"}},
		TerminalTake:  min(uint64(500), request.RequestedRows), SchemaDigest: request.SchemaDigest,
		RegistryDigest: request.Policy.RegistryDigest, HelperIdentity: request.HelperIdentityExpectation,
		ProvenanceDigest: repeatDigest("6")}
	if helper.denied {
		response.Outcome, response.ReasonCodes = "denied", []string{"semantic_diagnostic"}
		response.CanonicalKQL, response.CanonicalKQLDigest = "", ""
		response.OriginalTreeDigest, response.BoundedTreeDigest = "", ""
		response.Semantic, response.OutputColumns, response.TerminalTake = SemanticInventory{}, nil, 0
	}
	response.ResponseDigest = HelperResponseDigest(response)
	return response, nil
}

type serviceAdmission struct {
	phases    []string
	denyPhase string
	mu        sync.Mutex
}

func (gate *serviceAdmission) CheckKustoValidation(_ context.Context, check AdmissionCheck) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.phases = append(gate.phases, check.Phase)
	if gate.denyPhase == check.Phase {
		return errors.New("denied")
	}
	return nil
}

type serviceTrust struct{ err error }

func (trust serviceTrust) VerifyKustoHelper(context.Context, HelperAttestation) error {
	return trust.err
}

type serviceRevocation struct {
	phases    []string
	denyPhase string
	mu        sync.Mutex
}

func (gate *serviceRevocation) CheckKustoRevocation(_ context.Context, check RevocationCheck) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.phases = append(gate.phases, check.Phase)
	if gate.denyPhase == check.Phase {
		return errors.New("revoked")
	}
	return nil
}

type serviceAudit struct {
	calls int
	err   error
	mu    sync.Mutex
}

func (audit *serviceAudit) CommitKustoValidation(_ context.Context, proof AuditProof) (AuditProof, error) {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.calls++
	return proof, audit.err
}

type serviceReplay struct {
	mu       sync.Mutex
	reserved map[string]string
	records  map[string]ReplayRecord
}

func newServiceReplay() *serviceReplay {
	return &serviceReplay{reserved: map[string]string{}, records: map[string]ReplayRecord{}}
}
func (store *serviceReplay) BeginKustoValidation(_ context.Context, key, digest string) (ReplayRecord, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if prior, ok := store.reserved[key]; ok && prior != digest {
		return ReplayRecord{}, false, ErrChangedReplay
	}
	store.reserved[key] = digest
	record, ok := store.records[key]
	return record, ok, nil
}
func (store *serviceReplay) CompleteKustoValidation(_ context.Context, key string, record ReplayRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[key] = record
	return nil
}
func (store *serviceReplay) AbandonKustoValidation(_ context.Context, key, digest string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.reserved[key] == digest {
		delete(store.reserved, key)
	}
}

func TestServiceRechecksAuthorityAndAuditsBeforeReleasingKQL(t *testing.T) {
	input := serviceInput(t)
	helper, authority, revocation, audit := &serviceHelper{}, &serviceAdmission{}, &serviceRevocation{}, &serviceAudit{}
	service, err := NewService(helper, authority, serviceTrust{}, revocation, audit, newServiceReplay(), serviceClock{serviceNow})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := service.Validate(context.Background(), input)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if admission.CanonicalKQL == "" || admission.Audit.AuditRecordDigest == "" || audit.calls != 1 {
		t.Fatal("accepted KQL was not bound to a durable audit proof")
	}
	queryBytes, _ := json.Marshal(input.Query)
	validatedQuery, queryErr := queryconnector.DecodeQuery(context.Background(), queryBytes)
	validationBytes, _ := json.Marshal(admission.Validation)
	validatedDecision, validationErr := queryconnector.DecodeValidation(context.Background(), validationBytes)
	if queryErr != nil || validationErr != nil || queryconnector.AdmitExecution(context.Background(), validatedQuery, validatedDecision) != nil ||
		admission.CanonicalKQLDigest != CanonicalKQLDigest(admission.CanonicalKQL) {
		t.Fatal("common query and bounded KQL digests were not independently bound")
	}
	if want := []string{"pre_helper", "post_helper"}; !equalStrings(authority.phases, want) || !equalStrings(revocation.phases, want) {
		t.Fatalf("gate phases authority=%v revocation=%v", authority.phases, revocation.phases)
	}
}

func TestAuditFailureWithholdsSuccess(t *testing.T) {
	helper, audit := &serviceHelper{}, &serviceAudit{err: errors.New("offline")}
	service, _ := NewService(helper, &serviceAdmission{}, serviceTrust{}, &serviceRevocation{}, audit, newServiceReplay(), serviceClock{serviceNow})
	admission, err := service.Validate(context.Background(), serviceInput(t))
	if queryconnector.Code(err) != queryconnector.Unavailable || admission.CanonicalKQL != "" {
		t.Fatalf("audit failure returned admission=%+v err=%v", admission, err)
	}
}

func TestServicePostHelperRevocationWithholdsSuccess(t *testing.T) {
	helper, revocation, audit := &serviceHelper{}, &serviceRevocation{denyPhase: "post_helper"}, &serviceAudit{}
	service, _ := NewService(helper, &serviceAdmission{}, serviceTrust{}, revocation, audit, newServiceReplay(), serviceClock{serviceNow})
	admission, err := service.Validate(context.Background(), serviceInput(t))
	if queryconnector.Code(err) != queryconnector.Denied || admission.CanonicalKQL != "" || audit.calls != 0 {
		t.Fatalf("revocation race returned admission=%+v err=%v audit=%d", admission, err, audit.calls)
	}
}

func TestServiceAuditsSemanticDenialWithoutReleasingKQL(t *testing.T) {
	helper, audit := &serviceHelper{denied: true}, &serviceAudit{}
	service, _ := NewService(helper, &serviceAdmission{}, serviceTrust{}, &serviceRevocation{}, audit, newServiceReplay(), serviceClock{serviceNow})
	admission, err := service.Validate(context.Background(), serviceInput(t))
	if queryconnector.Code(err) != queryconnector.Denied || admission.CanonicalKQL != "" || audit.calls != 1 {
		t.Fatalf("semantic denial admission=%+v err=%v audit=%d", admission, err, audit.calls)
	}
}

func TestTimeoutCancellationAndRecovery(t *testing.T) {
	input, helper, replay := serviceInput(t), &serviceHelper{wait: true}, newServiceReplay()
	service, _ := NewService(helper, &serviceAdmission{}, serviceTrust{}, &serviceRevocation{}, &serviceAudit{}, replay, serviceClock{serviceNow})
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := service.Validate(ctx, input); queryconnector.Code(err) != queryconnector.Timeout {
		t.Fatalf("timeout error = %v", err)
	}
	helper.wait = false
	if admission, err := service.Validate(context.Background(), input); err != nil || admission.CanonicalKQL == "" {
		t.Fatalf("recovery admission=%+v err=%v", admission, err)
	}
	canceledInput := serviceInput(t)
	canceledInput.IdempotencyKey = testIdempotency("canceled")
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := service.Validate(canceled, canceledInput); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("cancellation error = %v", err)
	}
	outageInput := serviceInput(t)
	outageInput.IdempotencyKey = testIdempotency("outage")
	helper.fail = errors.New("offline")
	if _, err := service.Validate(context.Background(), outageInput); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("outage error = %v", err)
	}
	helper.fail = nil
	if admission, err := service.Validate(context.Background(), outageInput); err != nil || admission.CanonicalKQL == "" {
		t.Fatalf("outage recovery admission=%+v err=%v", admission, err)
	}
}

func TestServiceExactReplayRechecksCurrentState(t *testing.T) {
	input, replay := serviceInput(t), newServiceReplay()
	helper, authority := &serviceHelper{}, &serviceAdmission{}
	service, _ := NewService(helper, authority, serviceTrust{}, &serviceRevocation{}, &serviceAudit{}, replay, serviceClock{serviceNow})
	first, err := service.Validate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Validate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if helper.calls != 1 || !second.Replayed || first.CanonicalKQL != second.CanonicalKQL || authority.phases[len(authority.phases)-1] != "replay" {
		t.Fatalf("invalid exact replay helper=%d replayed=%v phases=%v", helper.calls, second.Replayed, authority.phases)
	}
	changed := input
	changed.Query.NativeText += " | where Computer != ''"
	if _, err := service.Validate(context.Background(), changed); queryconnector.Code(err) != queryconnector.Conflict {
		t.Fatalf("changed replay error = %v", err)
	}
}

func serviceInput(t *testing.T) ValidateRequest {
	t.Helper()
	var fixture HelperRequest
	unmarshalFixture(t, "helper-request.json", &fixture)
	var registry SemanticRegistry
	unmarshalFixture(t, "semantic-registry.json", &registry)
	var attestation HelperAttestation
	unmarshalFixture(t, "helper-attestation.json", &attestation)
	stamp := func(value time.Time) string { return value.Format("2006-01-02T15:04:05.000000000Z") }
	capability := queryconnector.CapabilitySnapshot{SchemaVersion: queryconnector.CapabilitySchemaVersion,
		ContractVersion: queryconnector.ContractVersion, SnapshotID: "018f0000-0000-7000-8000-000000000010",
		SourceID: fixture.SourceID, AdapterVersion: "sentinel-1.0.0", ObservedAt: stamp(serviceNow.Add(-time.Minute)),
		ValidUntil: stamp(serviceNow.Add(time.Hour)), QueryLanguages: []string{"kql"},
		Features: queryconnector.Features{ReadOnly: true, SchemaDiscovery: true, Validation: true},
		HardLimits: queryconnector.Limits{MaximumRows: 1000, MaximumBytes: 1 << 20, MaximumDurationMillis: 5000,
			MaximumPages: 1, MaximumSlices: 1, MaximumCostMillionths: 1, RequestsPerMinute: 1},
		SourceIdentityDigest: repeatDigest("1")}
	capabilityBytes, _ := json.Marshal(capability)
	validatedCapability, err := queryconnector.DecodeCapability(context.Background(), capabilityBytes)
	if err != nil {
		t.Fatal(err)
	}
	query := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: fixture.RequestID, Scope: queryconnector.Scope{OrganizationID: "018f0000-0000-7000-8000-000000000011",
			TenantID: "018f0000-0000-7000-8000-000000000012", CaseID: "018f0000-0000-7000-8000-000000000013",
			SourceID: fixture.SourceID, ResourceIDs: fixture.ResourceIDs},
		Authority: queryconnector.AuthorityBinding{ActorID: "018f0000-0000-7000-8000-000000000014",
			AuthorizationDigest: repeatDigest("7"), PolicyDecisionDigest: repeatDigest("8"), AuditReservationDigest: repeatDigest("9")},
		CapabilityDigest: validatedCapability.Digest(), SchemaDigest: repeatDigest("2"), Language: "kql", NativeText: fixture.Query,
		TimeRange: queryconnector.TimeRange{Start: stamp(serviceNow.Add(-time.Hour)), End: stamp(serviceNow)},
		Limits:    capability.HardLimits, RequestedAt: stamp(serviceNow.Add(-time.Second)), Deadline: stamp(serviceNow.Add(time.Minute))}
	return ValidateRequest{Query: query, Capability: capability, Schema: fixture.Schema,
		WorkspaceIdentityDigest: fixture.WorkspaceIdentityDigest, QualificationDigest: fixture.QualificationDigest,
		Registry: registry, Policy: fixture.Policy, Helper: attestation, IdempotencyKey: testIdempotency("1")}
}

func testIdempotency(suffix string) string { return "kusto-validation-" + suffix }

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
