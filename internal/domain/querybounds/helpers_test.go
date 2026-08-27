package querybounds

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var testNow = time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)

type clockStub struct{ now time.Time }

func (clock clockStub) Now() time.Time { return clock.now }

type auditStub struct {
	mu        sync.Mutex
	decisions []Decision
	err       error
}

func (audit *auditStub) AppendQueryBoundDecision(_ context.Context, decision Decision) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.err != nil {
		return audit.err
	}
	audit.decisions = append(audit.decisions, decision)
	return nil
}

func (audit *auditStub) values() []Decision {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	return append([]Decision(nil), audit.decisions...)
}

type replayStub struct {
	mu          sync.Mutex
	values      map[string]string
	unavailable bool
}

func (guard *replayStub) Observe(_ context.Context, id, digest string) (bool, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.unavailable {
		return false, errors.New("secret vendor detail")
	}
	if guard.values == nil {
		guard.values = make(map[string]string)
	}
	if existing, found := guard.values[id]; found {
		if existing != digest {
			return false, ErrChangedReplay
		}
		return true, nil
	}
	guard.values[id] = digest
	return false, nil
}

func validEngine(t *testing.T) (*Engine, *auditStub, *replayStub) {
	t.Helper()
	audit, replay := &auditStub{}, &replayStub{}
	engine, err := New(audit, clockStub{testNow}, replay)
	if err != nil {
		t.Fatal(err)
	}
	return engine, audit, replay
}

func validQuery(t testing.TB) queryconnector.ValidatedQuery {
	t.Helper()
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: id("1"), Scope: queryconnector.Scope{OrganizationID: id("2"), TenantID: id("3"), CaseID: id("4"),
			SourceID: "sentinel-prod", ResourceIDs: []string{"securityevent"}},
		Authority: queryconnector.AuthorityBinding{ActorID: id("5"), AuthorizationDigest: digest("b"),
			PolicyDecisionDigest: digest("c"), AuditReservationDigest: digest("d")},
		CapabilityDigest: digest("e"), SchemaDigest: digest("f"), Language: "kql",
		NativeText: "SecurityEvent | take 10",
		TimeRange:  queryconnector.TimeRange{Start: "2026-08-27T17:00:00.000000000Z", End: "2026-08-27T18:00:00.000000000Z"},
		Limits: queryconnector.Limits{MaximumRows: 1000, MaximumBytes: 1048576, MaximumDurationMillis: 60000,
			MaximumPages: 10, MaximumSlices: 4, MaximumCostMillionths: 1000000, RequestsPerMinute: 12},
		RequestedAt: "2026-08-27T17:59:59.000000000Z", Deadline: "2026-08-27T18:01:00.000000000Z"}
	return decodeQuery(t, value)
}

func decodeQuery(t testing.TB, value queryconnector.Query) queryconnector.ValidatedQuery {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func validAuthority(query queryconnector.ValidatedQuery) AuthoritySnapshot {
	value := query.Value()
	return AuthoritySnapshot{OrganizationID: value.Scope.OrganizationID, TenantID: value.Scope.TenantID, CaseID: value.Scope.CaseID,
		ActorID: value.Authority.ActorID, ActorRevision: 1, ActorActive: true,
		SourceID: value.Scope.SourceID, SourceRevision: 1, SourceActive: true,
		ResourceIDs: append([]string(nil), value.Scope.ResourceIDs...), AllowlistRevision: 1, AllowlistActive: true,
		CapabilityDigest: value.CapabilityDigest, CapabilityRevision: 1, CapabilityActive: true,
		AuthorizationAllowed: true, AuthorizationDecisionDigest: value.Authority.AuthorizationDigest,
		PolicyAllowed: true, PolicyDecisionDigest: value.Authority.PolicyDecisionDigest, PolicyRevision: 1,
		AuditReservationDigest: value.Authority.AuditReservationDigest, RevocationRevision: 1,
		MaximumInterval: 2 * time.Hour, MaximumLimits: value.Limits, ObservedAt: testNow.Add(-time.Second)}
}

func approvalAuthority(query queryconnector.ValidatedQuery) AuthoritySnapshot {
	authority := validAuthority(query)
	authority.ApprovalRequired, authority.ApprovalAllowed = true, true
	authority.ApprovalDecisionDigest = digest("a")
	authority.ApprovalQueryDigest = query.Digest()
	authority.ApprovalPolicyDecisionDigest = authority.PolicyDecisionDigest
	authority.ApprovalExpiresAt = testNow.Add(time.Minute)
	return authority
}

func id(character string) string     { return "0198e300-1000-7000-8000-00000000000" + character }
func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
