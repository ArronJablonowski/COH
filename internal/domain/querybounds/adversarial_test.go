package querybounds

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestAuthorityAndScopeAdversarialMatrix(t *testing.T) {
	query := validQuery(t)
	tests := []struct {
		name   string
		code   ErrorCode
		reason string
		mutate func(*AuthoritySnapshot)
	}{
		{"invalid authority", InvalidInput, "authority_invalid", func(a *AuthoritySnapshot) { a.ActorRevision = 0 }},
		{"stale authority", Denied, "authority_stale", func(a *AuthoritySnapshot) { a.ObservedAt = testNow.Add(-time.Minute) }},
		{"future authority", Denied, "authority_stale", func(a *AuthoritySnapshot) { a.ObservedAt = testNow.Add(6 * time.Second) }},
		{"tenant", Denied, "scope_denied", func(a *AuthoritySnapshot) { a.TenantID = id("9") }},
		{"resource", Denied, "scope_denied", func(a *AuthoritySnapshot) { a.ResourceIDs = []string{"other"} }},
		{"actor", Denied, "scope_denied", func(a *AuthoritySnapshot) { a.ActorID = id("9") }},
		{"capability binding", Denied, "capability_mismatch", func(a *AuthoritySnapshot) { a.CapabilityDigest = digest("9") }},
		{"authorization binding", Denied, "authority_binding_mismatch", func(a *AuthoritySnapshot) { a.AuthorizationDecisionDigest = digest("9") }},
		{"policy binding", Denied, "authority_binding_mismatch", func(a *AuthoritySnapshot) { a.PolicyDecisionDigest = digest("9") }},
		{"audit binding", Denied, "authority_binding_mismatch", func(a *AuthoritySnapshot) { a.AuditReservationDigest = digest("9") }},
		{"actor revoked", Denied, "actor_revoked", func(a *AuthoritySnapshot) { a.ActorActive = false }},
		{"source revoked", Denied, "source_revoked", func(a *AuthoritySnapshot) { a.SourceActive = false }},
		{"allowlist revoked", Denied, "allowlist_revoked", func(a *AuthoritySnapshot) { a.AllowlistActive = false }},
		{"capability revoked", Denied, "capability_revoked", func(a *AuthoritySnapshot) { a.CapabilityActive = false }},
		{"estop", Denied, "emergency_stop", func(a *AuthoritySnapshot) { a.EmergencyStopActive = true }},
		{"authorization denied", Denied, "authorization_denied", func(a *AuthoritySnapshot) { a.AuthorizationAllowed = false }},
		{"policy denied", Denied, "policy_denied", func(a *AuthoritySnapshot) { a.PolicyAllowed = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, audit, _ := validEngine(t)
			authority := validAuthority(query)
			test.mutate(&authority)
			result, err := engine.Admit(context.Background(), query, authority)
			if Code(err) != test.code || Reason(err) != test.reason || result.Decision.ReasonCode != test.reason || len(audit.values()) != 1 {
				t.Fatalf("decision=%+v code=%s reason=%s err=%v", result.Decision, Code(err), Reason(err), err)
			}
		})
	}
}

func TestUTCIntervalDeadlineAndLimitMatrix(t *testing.T) {
	base := validQuery(t)
	tests := []struct {
		name   string
		reason string
		mutate func(*queryconnector.Query, *AuthoritySnapshot)
	}{
		{"interval excessive", "interval_excessive", func(q *queryconnector.Query, _ *AuthoritySnapshot) {
			q.TimeRange.Start = "2026-08-27T15:00:00.000000000Z"
		}},
		{"future end", "future_unsafe", func(q *queryconnector.Query, _ *AuthoritySnapshot) {
			q.TimeRange.End = "2026-08-27T18:00:01.000000000Z"
		}},
		{"future request", "future_unsafe", func(q *queryconnector.Query, _ *AuthoritySnapshot) { q.RequestedAt = "2026-08-27T18:00:01.000000000Z" }},
		{"deadline elapsed", "query_deadline_elapsed", func(q *queryconnector.Query, _ *AuthoritySnapshot) { q.Deadline = "2026-08-27T18:00:00.000000000Z" }},
		{"rows excessive", "limits_excessive", func(q *queryconnector.Query, a *AuthoritySnapshot) {
			a.MaximumLimits.MaximumRows = q.Limits.MaximumRows - 1
		}},
		{"bytes excessive", "limits_excessive", func(q *queryconnector.Query, a *AuthoritySnapshot) {
			a.MaximumLimits.MaximumBytes = q.Limits.MaximumBytes - 1
		}},
		{"duration excessive", "limits_excessive", func(q *queryconnector.Query, a *AuthoritySnapshot) {
			a.MaximumLimits.MaximumDurationMillis = q.Limits.MaximumDurationMillis - 1
		}},
		{"pages excessive", "limits_excessive", func(q *queryconnector.Query, a *AuthoritySnapshot) {
			a.MaximumLimits.MaximumPages = q.Limits.MaximumPages - 1
		}},
		{"slices excessive", "limits_excessive", func(q *queryconnector.Query, a *AuthoritySnapshot) {
			a.MaximumLimits.MaximumSlices = q.Limits.MaximumSlices - 1
		}},
		{"cost excessive", "limits_excessive", func(q *queryconnector.Query, a *AuthoritySnapshot) {
			a.MaximumLimits.MaximumCostMillionths = q.Limits.MaximumCostMillionths - 1
		}},
		{"rate excessive", "limits_excessive", func(q *queryconnector.Query, a *AuthoritySnapshot) {
			a.MaximumLimits.RequestsPerMinute = q.Limits.RequestsPerMinute - 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base.Value()
			authority := validAuthority(base)
			test.mutate(&value, &authority)
			query := decodeQuery(t, value)
			if value.CapabilityDigest == authority.CapabilityDigest {
				authority.CapabilityDigest = query.Value().CapabilityDigest
			}
			engine, audit, _ := validEngine(t)
			result, err := engine.Admit(context.Background(), query, authority)
			if Code(err) != Denied || Reason(err) != test.reason || result.Decision.ReasonCode != test.reason || len(audit.values()) != 1 {
				t.Fatalf("decision=%+v err=%v", result.Decision, err)
			}
		})
	}
}

func TestReplayDependencyFailureIsRedactedAndAudited(t *testing.T) {
	engine, audit, replay := validEngine(t)
	replay.unavailable = true
	result, err := engine.Admit(context.Background(), validQuery(t), validAuthority(validQuery(t)))
	if Code(err) != Unavailable || Reason(err) != "replay_guard_unavailable" ||
		result.Decision.ReasonCode != "replay_guard_unavailable" || len(audit.values()) != 1 {
		t.Fatalf("decision=%+v err=%v", result.Decision, err)
	}
}

func TestMissingOpenEndedAndNonUTCQueriesNeverReachAdmission(t *testing.T) {
	base := validQuery(t).Value()
	mutations := map[string]func(*queryconnector.Query){
		"missing start": func(value *queryconnector.Query) { value.TimeRange.Start = "" },
		"open end":      func(value *queryconnector.Query) { value.TimeRange.End = "" },
		"non UTC":       func(value *queryconnector.Query) { value.TimeRange.Start = "2026-08-27T17:00:00.000000000-07:00" },
		"equal bound":   func(value *queryconnector.Query) { value.TimeRange.Start = value.TimeRange.End },
		"zero limit":    func(value *queryconnector.Query) { value.Limits.MaximumRows = 0 },
		"empty scope":   func(value *queryconnector.Query) { value.Scope.ResourceIDs = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Scope.ResourceIDs = append([]string(nil), base.Scope.ResourceIDs...)
			mutate(&value)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := queryconnector.DecodeQuery(context.Background(), encoded); queryconnector.Code(err) != queryconnector.InvalidInput {
				t.Fatalf("unsafe query accepted err=%v", err)
			}
		})
	}
}
