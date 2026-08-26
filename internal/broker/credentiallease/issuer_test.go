package credentiallease

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/broker/secretresolver"
	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type auditStub struct {
	mu        sync.Mutex
	decisions []leasecontract.Decision
	err       error
}

type resolverStub struct{}

func (*resolverStub) Resolve(context.Context, secretref.ResolutionRequest, secretref.AuthoritySnapshot) (*secretresolver.Secret, secretref.Decision, error) {
	panic("resolver is not used by issuance tests")
}

func (audit *auditStub) AppendCredentialLeaseDecision(_ context.Context, decision leasecontract.Decision) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.decisions = append(audit.decisions, decision)
	return audit.err
}

func TestIssueBindsScopeAndReturnsOpaqueCapability(t *testing.T) {
	broker, store, audit, request, authority := issueFixture(t)
	handle, decision, err := broker.Issue(context.Background(), request, authority)
	if err != nil || handle == nil || decision.Outcome != "allowed" || decision.ReasonCode != "lease_issued" {
		t.Fatalf("handle = %+v, decision = %+v, err = %v", handle, decision, err)
	}
	if decision.ExpiresAt.Sub(decision.IssuedAt) != 60*time.Second || decision.LeaseID != handle.LeaseID ||
		decision.CredentialReferenceDigest == "" || decision.DecisionDigest == "" {
		t.Fatalf("decision binding = %+v", decision)
	}
	record := store.records[handle.LeaseID]
	if record.Request.ActionDigest != request.ActionDigest || record.Request.TaskID != request.TaskID ||
		record.Authority.Audience.TransportIdentityDigest != request.Audience.TransportIdentityDigest || record.Revoked {
		t.Fatalf("record = %+v", record)
	}
	encoded, marshalErr := json.Marshal(handle)
	if marshalErr != nil || strings.Contains(string(encoded), "token") || strings.Contains(string(encoded), request.Reference.EntryID) {
		t.Fatalf("serialized handle = %s, err = %v", encoded, marshalErr)
	}
	if len(audit.decisions) != 1 || strings.Contains(mustJSON(t, audit.decisions[0]), request.Reference.EntryID) {
		t.Fatalf("audit decisions = %+v", audit.decisions)
	}
	handle.Destroy()
	if !handle.dead || handle.token != nil {
		t.Fatalf("destroyed handle = %+v", handle)
	}
}

func TestIssueClampsBrokerMaximumLifetime(t *testing.T) {
	broker, _, _, request, authority := issueFixture(t)
	broker.maxTTL = 30 * time.Second
	_, decision, err := broker.Issue(context.Background(), request, authority)
	if err != nil || decision.ExpiresAt.Sub(decision.IssuedAt) != 30*time.Second {
		t.Fatalf("decision = %+v, err = %v", decision, err)
	}
}

func TestIssueRejectsAuthorityFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*leasecontract.IssuanceAuthority)
		reason string
	}{
		{"scope", func(authority *leasecontract.IssuanceAuthority) { authority.Context.ActorID = uuid("9") }, "authority_scope_mismatch"},
		{"actor", func(authority *leasecontract.IssuanceAuthority) { authority.Active = false }, "actor_revoked"},
		{"authorization", func(authority *leasecontract.IssuanceAuthority) { authority.AuthorizationAllowed = false }, "authorization_denied"},
		{"policy", func(authority *leasecontract.IssuanceAuthority) { authority.PolicyAllowed = false }, "policy_denied"},
		{"approval", func(authority *leasecontract.IssuanceAuthority) { authority.ApprovalAllowed = false }, "approval_denied"},
		{"audience", func(authority *leasecontract.IssuanceAuthority) { authority.Audience.Active = false }, "audience_revoked"},
		{"transport", func(authority *leasecontract.IssuanceAuthority) { authority.Audience.MutualTLS = false }, "mutual_tls_required"},
		{"stale", func(authority *leasecontract.IssuanceAuthority) {
			authority.Audience.ObservedAt = authority.Audience.ObservedAt.Add(-time.Minute)
		}, "audience_state_stale"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broker, store, _, request, authority := issueFixture(t)
			test.mutate(&authority)
			handle, decision, err := broker.Issue(context.Background(), request, authority)
			if handle != nil || leasecontract.Code(err) != leasecontract.Denied || reason(err) != test.reason || decision.Outcome != "denied" || len(store.records) != 0 {
				t.Fatalf("handle = %+v, decision = %+v, err = %v", handle, decision, err)
			}
		})
	}
}

func TestIssueRejectsReplayAndIdempotencyConflict(t *testing.T) {
	broker, store, _, request, authority := issueFixture(t)
	first, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	second, replayDecision, replayErr := broker.Issue(context.Background(), request, authority)
	if second != nil || leasecontract.Code(replayErr) != leasecontract.Conflict || reason(replayErr) != "issuance_replay" || replayDecision.Outcome != "denied" {
		t.Fatalf("replay handle = %+v, decision = %+v, err = %v", second, replayDecision, replayErr)
	}
	changed := request
	changed.ActionDigest = digest("c")
	third, conflictDecision, conflictErr := broker.Issue(context.Background(), changed, authority)
	if third != nil || leasecontract.Code(conflictErr) != leasecontract.Conflict || reason(conflictErr) != "idempotency_conflict" || conflictDecision.Outcome != "denied" {
		t.Fatalf("conflict handle = %+v, decision = %+v, err = %v", third, conflictDecision, conflictErr)
	}
	if len(store.records) != 1 || store.records[first.LeaseID].Revoked {
		t.Fatalf("records = %+v", store.records)
	}
}

func TestIssueAuditFailureRevokesCapability(t *testing.T) {
	broker, store, audit, request, authority := issueFixture(t)
	audit.err = errors.New("private audit failure")
	handle, decision, err := broker.Issue(context.Background(), request, authority)
	if handle != nil || leasecontract.Code(err) != leasecontract.Unavailable || reason(err) != "audit_unavailable" || decision.ReasonCode != "audit_unavailable" {
		t.Fatalf("handle = %+v, decision = %+v, err = %v", handle, decision, err)
	}
	if len(store.records) != 1 {
		t.Fatalf("records = %+v", store.records)
	}
	for _, record := range store.records {
		if !record.Revoked || record.RevokeReason != "audit_unavailable" {
			t.Fatalf("record = %+v", record)
		}
	}
	if strings.Contains(err.Error(), audit.err.Error()) {
		t.Fatalf("private error leaked: %v", err)
	}
}

func TestIssueInvalidInputAuditRedactsFreeformFields(t *testing.T) {
	broker, _, audit, request, authority := issueFixture(t)
	request.Operation = "secret-material-that-must-not-be-audited"
	request.RequestedTTLSeconds = 0
	_, decision, err := broker.Issue(context.Background(), request, authority)
	if leasecontract.Code(err) != leasecontract.InvalidInput || decision.Operation != "" || decision.AudienceID != "" || decision.CredentialClass != "" {
		t.Fatalf("decision = %+v, err = %v", decision, err)
	}
	if strings.Contains(mustJSON(t, audit.decisions[0]), "secret-material") {
		t.Fatalf("invalid input leaked to audit: %+v", audit.decisions[0])
	}
}

func TestIssueCancellationIsFailClosedAndAudited(t *testing.T) {
	broker, store, audit, request, authority := issueFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	handle, decision, err := broker.Issue(ctx, request, authority)
	if handle != nil || leasecontract.Code(err) != leasecontract.Canceled || decision.Outcome != "canceled" || len(store.records) != 0 || len(audit.decisions) != 1 {
		t.Fatalf("handle = %+v, decision = %+v, records = %d, audit = %d, err = %v", handle, decision, len(store.records), len(audit.decisions), err)
	}
}

func TestIssueChecksAuthoritativeStopBeforeCreatingCapability(t *testing.T) {
	broker, store, _, request, authority := issueFixture(t)
	guard := &mutableStopGuard{err: stopcontract.NewError(stopcontract.Denied, "emergency_stop_active")}
	broker.stop = guard

	handle, decision, err := broker.Issue(context.Background(), request, authority)
	if handle != nil || leasecontract.Code(err) != leasecontract.Denied || reason(err) != "emergency_stop_active" ||
		decision.Outcome != "denied" || len(store.records) != 0 {
		t.Fatalf("handle = %+v, decision = %+v, records = %d, err = %v", handle, decision, len(store.records), err)
	}
	want := [3]string{request.Context.OrganizationID, request.Context.TenantID, request.Context.CaseID}
	if len(guard.calls) != 1 || guard.calls[0] != want {
		t.Fatalf("stop checks = %#v, want %#v", guard.calls, want)
	}
}

func TestIssueFailsClosedWhenStopStateUnavailable(t *testing.T) {
	broker, store, _, request, authority := issueFixture(t)
	broker.stop = &mutableStopGuard{err: errors.New("private stop store failure")}
	handle, decision, err := broker.Issue(context.Background(), request, authority)
	if handle != nil || leasecontract.Code(err) != leasecontract.Unavailable || reason(err) != "stop_state_unavailable" ||
		decision.Outcome != "unavailable" || len(store.records) != 0 || strings.Contains(err.Error(), "private stop") {
		t.Fatalf("handle = %+v, decision = %+v, records = %d, err = %v", handle, decision, len(store.records), err)
	}
}

func TestConcurrentIssueHasSingleWinner(t *testing.T) {
	store := NewMemoryStore()
	audit := &auditStub{}
	request, authority := validIssueInput()
	broker, err := NewWithDependencies(store, audit, &resolverStub{}, allowStopGuard{}, fixedClock{now: authority.Audience.ObservedAt.Add(time.Second)}, rand.Reader, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 16
	var wait sync.WaitGroup
	wait.Add(attempts)
	results := make(chan *Handle, attempts)
	for range attempts {
		go func() {
			defer wait.Done()
			handle, _, _ := broker.Issue(context.Background(), request, authority)
			results <- handle
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	for handle := range results {
		if handle != nil {
			winners++
			handle.Destroy()
		}
	}
	if winners != 1 || len(store.records) != 1 || len(audit.decisions) != attempts {
		t.Fatalf("winners = %d, records = %d, decisions = %d", winners, len(store.records), len(audit.decisions))
	}
}

func issueFixture(t *testing.T) (*Broker, *MemoryStore, *auditStub, leasecontract.IssuanceRequest, leasecontract.IssuanceAuthority) {
	t.Helper()
	store := NewMemoryStore()
	audit := &auditStub{}
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
	clock := fixedClock{now: time.Date(2026, 8, 25, 22, 0, 0, 0, time.UTC)}
	broker, err := NewWithDependencies(store, audit, &resolverStub{}, allowStopGuard{}, clock, random, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, authority := validIssueInput()
	return broker, store, audit, request, authority
}

func validIssueInput() (leasecontract.IssuanceRequest, leasecontract.IssuanceAuthority) {
	contextScope := secretref.Context{OrganizationID: uuid("1"), TenantID: uuid("2"), CaseID: uuid("3"), ActorID: uuid("4")}
	audience := leasecontract.Audience{Kind: "runner", ID: "runner.primary", TransportIdentityDigest: digest("b")}
	request := leasecontract.IssuanceRequest{
		SchemaVersion: leasecontract.SchemaVersion, ContractVersion: leasecontract.ContractVersion,
		RequestID: uuid("5"), IdempotencyKey: "issue-action", Context: contextScope, TaskID: uuid("6"),
		ActionDigest: digest("a"), TargetDigests: []string{digest("1"), digest("2")}, Operation: "tool.invoke",
		Audience: audience, CredentialClass: "runner.execution",
		Reference:           secretref.Reference{SchemaVersion: secretref.SchemaVersion, ContractVersion: secretref.ContractVersion, Backend: "protected-file", EntryID: "broker.private-entry", Version: 7},
		RequestedTTLSeconds: 60,
	}
	authority := leasecontract.IssuanceAuthority{
		Context: contextScope, Active: true, ActorRevision: 3, AuthorizationAllowed: true,
		AuthorizationDecisionDigest: digest("c"), PolicyAllowed: true, PolicyDecisionDigest: digest("d"),
		ApprovalRequired: true, ApprovalAllowed: true, ApprovalDecisionDigest: digest("e"),
		Audience: leasecontract.AudienceAuthority{Audience: audience, Active: true, Revision: 4, Remote: true, MutualTLS: true, ObservedAt: time.Date(2026, 8, 25, 21, 59, 59, 0, time.UTC)},
	}
	return request, authority
}

func uuid(fill string) string {
	return "0198d6c4-" + fill + fill + fill + fill + "-7" + fill + fill + fill + "-8" + fill + fill + fill + "-" + strings.Repeat(fill, 12)
}
func digest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
