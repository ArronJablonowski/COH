package querybounds

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAdmissionAllowsBoundedQueryAndExactReauthorization(t *testing.T) {
	engine, audit, _ := validEngine(t)
	query := validQuery(t)
	authority := validAuthority(query)
	first, err := engine.Admit(context.Background(), query, authority)
	if err != nil || first.Query.Digest() != query.Digest() || first.Decision.Outcome != "allowed" || first.Decision.Replayed {
		t.Fatalf("first=%+v err=%v", first.Decision, err)
	}
	if _, err := VerifyDecision(first.Decision); err != nil {
		t.Fatal(err)
	}
	second, err := engine.Admit(context.Background(), query, authority)
	if err != nil || !second.Decision.Replayed || second.Decision.QueryDigest != first.Decision.QueryDigest ||
		second.Decision.AuthorityDigest != first.Decision.AuthorityDigest || len(audit.values()) != 2 {
		t.Fatalf("replay=%+v audit=%d err=%v", second.Decision, len(audit.values()), err)
	}
}

func TestChangedReplayAndCurrentRevocationFailClosed(t *testing.T) {
	engine, audit, _ := validEngine(t)
	query := validQuery(t)
	authority := validAuthority(query)
	if _, err := engine.Admit(context.Background(), query, authority); err != nil {
		t.Fatal(err)
	}
	changedValue := query.Value()
	changedValue.NativeText = "SecurityEvent | take 11"
	changed := decodeQuery(t, changedValue)
	if result, err := engine.Admit(context.Background(), changed, authority); Code(err) != Conflict ||
		Reason(err) != "changed_replay" || result.Decision.ReasonCode != "changed_replay" {
		t.Fatalf("changed replay=%+v err=%v", result.Decision, err)
	}
	revoked := authority
	revoked.ActorActive = false
	if result, err := engine.Admit(context.Background(), query, revoked); Code(err) != Denied ||
		Reason(err) != "actor_revoked" || result.Decision.Replayed {
		t.Fatalf("revoked replay=%+v err=%v", result.Decision, err)
	}
	if len(audit.values()) != 3 {
		t.Fatalf("audit decisions=%d", len(audit.values()))
	}
}

func TestApprovalIsExactQueryPolicyAndExpiryBound(t *testing.T) {
	query := validQuery(t)
	for name, mutate := range map[string]func(*AuthoritySnapshot){
		"not allowed": func(value *AuthoritySnapshot) { value.ApprovalAllowed = false },
		"expired":     func(value *AuthoritySnapshot) { value.ApprovalExpiresAt = testNow },
		"query":       func(value *AuthoritySnapshot) { value.ApprovalQueryDigest = digest("9") },
		"policy":      func(value *AuthoritySnapshot) { value.ApprovalPolicyDecisionDigest = digest("8") },
	} {
		t.Run(name, func(t *testing.T) {
			engine, audit, _ := validEngine(t)
			authority := approvalAuthority(query)
			mutate(&authority)
			result, err := engine.Admit(context.Background(), query, authority)
			if Code(err) != Denied || Reason(err) != "approval_denied" || result.Decision.ApprovalDecisionDigest == "" || len(audit.values()) != 1 {
				t.Fatalf("decision=%+v err=%v", result.Decision, err)
			}
		})
	}
	engine, _, _ := validEngine(t)
	if result, err := engine.Admit(context.Background(), query, approvalAuthority(query)); err != nil || !result.Decision.ApprovalRequired {
		t.Fatalf("approved=%+v err=%v", result.Decision, err)
	}
}

func TestCancellationTimeoutAuditFailureAndRecovery(t *testing.T) {
	query := validQuery(t)
	authority := validAuthority(query)
	engine, audit, _ := validEngine(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := engine.Admit(canceled, query, authority); Code(err) != Canceled ||
		result.Decision.ReasonCode != "request_canceled" || len(audit.values()) != 1 {
		t.Fatalf("canceled=%+v err=%v", result.Decision, err)
	}
	//lint:ignore SA1012 The boundary explicitly proves nil context fails closed and audits safely.
	if result, err := engine.Admit(nil, query, authority); Code(err) != InvalidInput ||
		result.Decision.ReasonCode != "context_required" || len(audit.values()) != 2 {
		t.Fatalf("nil context=%+v err=%v", result.Decision, err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if result, err := engine.Admit(deadline, query, authority); Code(err) != Timeout || result.Decision.ReasonCode != "request_timeout" {
		t.Fatalf("timeout=%+v err=%v", result.Decision, err)
	}

	brokenEngine, brokenAudit, _ := validEngine(t)
	brokenAudit.err = errors.New("password=should-not-escape")
	if result, err := brokenEngine.Admit(context.Background(), query, authority); Code(err) != Unavailable ||
		Reason(err) != "audit_unavailable" || result.Decision.ReasonCode != "audit_unavailable" ||
		strings.Contains(result.Decision.ReasonCode, "password") {
		t.Fatalf("audit failure=%+v err=%v", result.Decision, err)
	}
	brokenAudit.err = nil
	if recovered, err := brokenEngine.Admit(context.Background(), query, authority); err != nil || !recovered.Decision.Replayed {
		t.Fatalf("recovery=%+v err=%v", recovered.Decision, err)
	}
}

func TestEngineRequiresAllSecurityDependencies(t *testing.T) {
	audit, replay := &auditStub{}, &replayStub{}
	if _, err := New(nil, clockStub{testNow}, replay); Reason(err) != "dependencies_required" {
		t.Fatalf("nil audit err=%v", err)
	}
	if _, err := New(audit, nil, replay); Reason(err) != "dependencies_required" {
		t.Fatalf("nil clock err=%v", err)
	}
	if _, err := New(audit, clockStub{testNow}, nil); Reason(err) != "dependencies_required" {
		t.Fatalf("nil replay err=%v", err)
	}
}

func TestConcurrentExactAdmissionIsRaceSafe(t *testing.T) {
	engine, audit, _ := validEngine(t)
	query := validQuery(t)
	authority := validAuthority(query)
	const workers = 16
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := engine.Admit(context.Background(), query, authority)
			if err != nil || result.Decision.Outcome != "allowed" {
				errorsFound <- err
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent admission err=%v", err)
	}
	if len(audit.values()) != workers {
		t.Fatalf("audit decisions=%d", len(audit.values()))
	}
}
