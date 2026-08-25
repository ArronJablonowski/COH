package secretresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

const (
	testOrganizationID = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	testTenantID       = "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16"
	testCaseID         = "0198d6c4-7618-7d31-8e0a-9da53cae8ca2"
	testActorID        = "0198d6c4-1111-7111-8111-111111111111"
	testSecret         = "credential-value-that-must-never-escape"
)

type backendStub struct {
	name   string
	record Record
	err    error
	last   []byte
}

func (backend *backendStub) Name() string { return backend.name }

func (backend *backendStub) Fetch(_ context.Context, _ secretref.Reference) (Record, error) {
	record := backend.record
	record.CaseIDs = append([]string(nil), backend.record.CaseIDs...)
	record.Value = append([]byte(nil), backend.record.Value...)
	backend.last = record.Value
	return record, backend.err
}

type auditStub struct {
	decisions []secretref.Decision
	err       error
}

func (audit *auditStub) AppendSecretDecision(_ context.Context, decision secretref.Decision) error {
	if audit.err != nil {
		return audit.err
	}
	audit.decisions = append(audit.decisions, decision)
	return nil
}

type replayStub struct {
	records map[string]ReplayRecord
	err     error
}

func (replay *replayStub) CheckAndStore(_ context.Context, record ReplayRecord) (ReplayResult, error) {
	if replay.err != nil {
		return "", replay.err
	}
	key := record.OrganizationID + "\x00" + record.ActorID + "\x00" + record.IdempotencyKey
	previous, exists := replay.records[key]
	if !exists {
		replay.records[key] = record
		return ReplayNew, nil
	}
	if previous.RequestDigest == record.RequestDigest {
		return ReplayExact, nil
	}
	return ReplayConflict, nil
}

func TestResolveReturnsScopedSecretAfterAuditAndZeroesBackendBuffer(t *testing.T) {
	resolver, backend, audit, _ := resolverFixture(t)
	secret, decision, err := resolver.Resolve(context.Background(), validRequest())
	if err != nil || secret == nil || decision.Outcome != "allowed" || decision.Replayed || len(audit.decisions) != 1 || audit.decisions[0] != decision {
		t.Fatalf("decision = %+v, audit = %+v, err = %v", decision, audit.decisions, err)
	}
	if !allZero(backend.last) {
		t.Fatalf("backend return buffer retained secret: %q", backend.last)
	}
	var observed []byte
	var transient []byte
	if err := secret.Use(func(value []byte) error {
		transient = value
		observed = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if string(observed) != testSecret {
		t.Fatalf("resolved value = %q", observed)
	}
	if !allZero(transient) {
		t.Fatalf("temporary consumer buffer retained secret: %q", transient)
	}
	encoded, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testSecret) || strings.Contains(string(encoded), backend.record.EntryID) {
		t.Fatalf("decision exposes secret or entry ID: %s", encoded)
	}
	secret.Destroy()
	secret.Destroy()
	if err := secret.Use(func([]byte) error { return nil }); secretref.Code(err) != secretref.Denied || reason(err) != "secret_destroyed" {
		t.Fatalf("destroyed secret err = %v", err)
	}
}

func TestResolveDeniesScopeStaleRevokedAndInvalidRecords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*backendStub, *secretref.ResolutionRequest)
		reason string
	}{
		{"organization", func(backend *backendStub, _ *secretref.ResolutionRequest) {
			backend.record.OrganizationID = "0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
		}, "secret_scope_denied"},
		{"tenant", func(backend *backendStub, _ *secretref.ResolutionRequest) {
			backend.record.TenantID = "0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
		}, "secret_scope_denied"},
		{"case", func(backend *backendStub, _ *secretref.ResolutionRequest) {
			backend.record.CaseIDs = []string{"0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa"}
		}, "secret_scope_denied"},
		{"class", func(backend *backendStub, _ *secretref.ResolutionRequest) {
			backend.record.CredentialClass = "siem.mutation"
		}, "secret_scope_denied"},
		{"stale", func(backend *backendStub, _ *secretref.ResolutionRequest) { backend.record.Version++ }, "stale_reference"},
		{"revoked", func(backend *backendStub, _ *secretref.ResolutionRequest) { backend.record.Active = false }, "secret_revoked"},
		{"mismatched-entry", func(backend *backendStub, _ *secretref.ResolutionRequest) { backend.record.EntryID = "other.entry" }, "reference_mismatch"},
		{"empty-value", func(backend *backendStub, _ *secretref.ResolutionRequest) { backend.record.Value = nil }, "backend_record_invalid"},
		{"ambiguous-grant", func(backend *backendStub, _ *secretref.ResolutionRequest) { backend.record.AllCases = true }, "backend_record_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, backend, audit, _ := resolverFixture(t)
			request := validRequest()
			test.mutate(backend, &request)
			secret, decision, err := resolver.Resolve(context.Background(), request)
			if secret != nil || secretref.Code(err) != secretref.Denied || reason(err) != test.reason || decision.Outcome != "denied" || len(audit.decisions) != 1 {
				t.Fatalf("secret = %v, decision = %+v, audit = %+v, err = %v", secret, decision, audit.decisions, err)
			}
			if !allZero(backend.last) {
				t.Fatalf("failure retained backend value: %q", backend.last)
			}
		})
	}
}

func TestResolveDetectsExactReplayAndChangedRequest(t *testing.T) {
	resolver, _, audit, _ := resolverFixture(t)
	request := validRequest()
	first, firstDecision, err := resolver.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, replayed, err := resolver.Resolve(context.Background(), request)
	if err != nil || second == nil || !replayed.Replayed || replayed.DecisionDigest == firstDecision.DecisionDigest {
		t.Fatalf("replayed = %+v, err = %v", replayed, err)
	}
	second.Destroy()
	request.ActionDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	secret, conflict, err := resolver.Resolve(context.Background(), request)
	if secret != nil || secretref.Code(err) != secretref.Conflict || reason(err) != "idempotency_conflict" || conflict.Outcome != "denied" || len(audit.decisions) != 3 {
		t.Fatalf("secret = %v, conflict = %+v, audit = %+v, err = %v", secret, conflict, audit.decisions, err)
	}
}

func TestResolveFailsClosedAndRedactsBackendAuditAndReplayErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*backendStub, *auditStub, *replayStub)
		reason string
	}{
		{"backend", func(backend *backendStub, _ *auditStub, _ *replayStub) {
			backend.err = errors.New("private backend detail")
		}, "backend_unavailable"},
		{"audit", func(_ *backendStub, audit *auditStub, _ *replayStub) { audit.err = errors.New("private audit detail") }, "audit_unavailable"},
		{"replay", func(_ *backendStub, _ *auditStub, replay *replayStub) {
			replay.err = errors.New("private replay detail")
		}, "replay_store_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, backend, audit, replay := resolverFixture(t)
			test.mutate(backend, audit, replay)
			secret, decision, err := resolver.Resolve(context.Background(), validRequest())
			if secret != nil || secretref.Code(err) != secretref.Unavailable || reason(err) != test.reason || decision.Outcome != "unavailable" {
				t.Fatalf("secret = %v, decision = %+v, err = %v", secret, decision, err)
			}
			if !allZero(backend.last) {
				t.Fatalf("failure retained backend value: %q", backend.last)
			}
			for _, private := range []error{backend.err, audit.err, replay.err} {
				if private != nil && errors.Is(err, private) {
					t.Fatalf("public error unwraps private detail: %v", err)
				}
			}
		})
	}
}

func TestResolveCancellationTimeoutAndRecovery(t *testing.T) {
	resolver, _, audit, _ := resolverFixture(t)
	request := validRequest()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, decision, err := resolver.Resolve(canceled, request)
	if secretref.Code(err) != secretref.Canceled || decision.Outcome != "canceled" {
		t.Fatalf("canceled decision = %+v, err = %v", decision, err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_, decision, err = resolver.Resolve(expired, request)
	if secretref.Code(err) != secretref.Timeout || decision.Outcome != "timeout" {
		t.Fatalf("timeout decision = %+v, err = %v", decision, err)
	}
	secret, decision, err := resolver.Resolve(context.Background(), request)
	if err != nil || secret == nil || decision.Outcome != "allowed" || len(audit.decisions) != 3 {
		t.Fatalf("recovery decision = %+v, audit = %+v, err = %v", decision, audit.decisions, err)
	}
	secret.Destroy()
}

func TestInvalidCallerValuesAreOmittedFromAudit(t *testing.T) {
	resolver, _, audit, _ := resolverFixture(t)
	request := validRequest()
	secretValue := "secret-value-in-malformed-field"
	request.CredentialClass = secretValue
	request.Context.ActorID = secretValue
	secret, decision, err := resolver.Resolve(context.Background(), request)
	if secret != nil || secretref.Code(err) != secretref.InvalidInput || decision.Outcome != "invalid" || len(audit.decisions) != 1 {
		t.Fatalf("secret = %v, decision = %+v, audit = %+v, err = %v", secret, decision, audit.decisions, err)
	}
	encoded, marshalErr := json.Marshal(audit.decisions)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), secretValue) {
		t.Fatalf("audit contains malformed caller value: %s", encoded)
	}
}

func resolverFixture(t *testing.T) (*Resolver, *backendStub, *auditStub, *replayStub) {
	t.Helper()
	backend := &backendStub{name: "protected-file", record: validRecord()}
	audit := &auditStub{}
	replay := &replayStub{records: make(map[string]ReplayRecord)}
	resolver, err := New([]Backend{backend}, audit, replay)
	if err != nil {
		t.Fatal(err)
	}
	return resolver, backend, audit, replay
}

func validRequest() secretref.ResolutionRequest {
	return secretref.ResolutionRequest{
		SchemaVersion: secretref.SchemaVersion, ContractVersion: secretref.ContractVersion,
		RequestID: "0198d6c4-5555-7555-8555-555555555555", IdempotencyKey: "resolve-one",
		Context:         secretref.Context{OrganizationID: testOrganizationID, TenantID: testTenantID, CaseID: testCaseID, ActorID: testActorID},
		ActionDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CredentialClass: "siem.readonly",
		Reference: secretref.Reference{
			SchemaVersion: secretref.SchemaVersion, ContractVersion: secretref.ContractVersion,
			Backend: "protected-file", EntryID: "siem.primary", Version: 7,
		},
	}
}

func validRecord() Record {
	return Record{
		Backend: "protected-file", EntryID: "siem.primary", Version: 7, Revision: 3, Active: true,
		OrganizationID: testOrganizationID, TenantID: testTenantID, CaseIDs: []string{testCaseID},
		CredentialClass: "siem.readonly", Value: []byte(testSecret),
	}
}

func allZero(value []byte) bool { return bytes.Equal(value, make([]byte, len(value))) }
