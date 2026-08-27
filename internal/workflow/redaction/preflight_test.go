package redaction

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestPreflightReverifiesAfterApprovalBeforeAuthority(t *testing.T) {
	fixture := newBindingFixture(t)
	dependencies, calls := preflightDependencies(fixture)
	service, err := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
		dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.authorize(context.Background(), fixture.command)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"case", "plan", "rule", "source", "head", "approval_authorize", "approval_verify",
		"case", "plan", "rule", "source", "head", "approval_verify", "authority"}
	if !reflect.DeepEqual(*calls, wantCalls) {
		t.Fatalf("calls=%v want=%v", *calls, wantCalls)
	}
	if state.IntentDigest != fixture.authorization.IntentDigest || state.Authorization.AuthorizationDigest != fixture.authorization.AuthorizationDigest ||
		state.Decision.DecisionDigest != fixture.decision.DecisionDigest || state.Source != fixture.authorizationSource() {
		t.Fatal("authorized state lost an exact binding")
	}
}

func TestPreflightFailsClosedBeforeApproval(t *testing.T) {
	tests := []struct {
		name, reason string
		mutate       func(*preflightDeps)
	}{
		{"stale case", string(ReasonStaleCase), func(d *preflightDeps) { d.cases.snapshot.Revision++ }},
		{"closed case", string(ReasonCaseStateDenied), func(d *preflightDeps) { d.cases.snapshot.State = "closed" }},
		{"invalid plan", string(ReasonPlanInvalid), func(d *preflightDeps) { d.plans.plan.Spans[1].SourceStart = 19 }},
		{"source drift", string(ReasonSourceInvalid), func(d *preflightDeps) { d.sources.value.Reference.Artifact.Digest = testDigest("1") }},
		{"stale custody", string(ReasonStaleCustody), func(d *preflightDeps) { d.custody.head.ChainHash = testDigest("2") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBindingFixture(t)
			dependencies, calls := preflightDependencies(fixture)
			test.mutate(&dependencies)
			service, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
				dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
			_, err := service.authorize(context.Background(), fixture.command)
			if err == nil || Reason(err) != test.reason {
				t.Fatalf("err=%v reason=%s", err, Reason(err))
			}
			if containsCall(*calls, "approval_authorize") || containsCall(*calls, "authority") {
				t.Fatalf("consequential call reached: %v", *calls)
			}
		})
	}
}

func TestPreflightWithholdsAuthorityWhenPostApprovalStateDrifts(t *testing.T) {
	fixture := newBindingFixture(t)
	dependencies, calls := preflightDependencies(fixture)
	dependencies.sources.onCall = func(call int, value *VerifiedSource) {
		if call == 2 {
			value.Reference.Artifact.Digest = testDigest("1")
		}
	}
	service, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
		dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
	_, err := service.authorize(context.Background(), fixture.command)
	if err == nil || Reason(err) != string(ReasonSourceInvalid) {
		t.Fatalf("err=%v", err)
	}
	if !containsCall(*calls, "approval_authorize") || containsCall(*calls, "authority") {
		t.Fatalf("calls=%v", *calls)
	}
}

func TestPreflightRejectsRevokedApprovalAndChangedDecision(t *testing.T) {
	t.Run("revoked approval", func(t *testing.T) {
		fixture := newBindingFixture(t)
		dependencies, calls := preflightDependencies(fixture)
		dependencies.approvals.verifyErr = newError(Denied, string(ReasonRevoked), false, nil)
		service, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
			dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
		_, err := service.authorize(context.Background(), fixture.command)
		if err == nil || Reason(err) != string(ReasonRevoked) || containsCall(*calls, "authority") {
			t.Fatalf("err=%v calls=%v", err, *calls)
		}
	})
	t.Run("authority denial", func(t *testing.T) {
		fixture := newBindingFixture(t)
		fixture.decision.Outcome, fixture.decision.ReasonCode = Deny, ReasonRevoked
		fixture.decision.DecisionDigest = mustDigest(t, func() (string, error) { return DecisionBindingDigest(fixture.decision) })
		dependencies, calls := preflightDependencies(fixture)
		service, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
			dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
		_, err := service.authorize(context.Background(), fixture.command)
		if err == nil || Reason(err) != string(ReasonRevoked) || !containsCall(*calls, "authority") {
			t.Fatalf("err=%v calls=%v", err, *calls)
		}
	})
	t.Run("changed decision", func(t *testing.T) {
		fixture := newBindingFixture(t)
		dependencies, calls := preflightDependencies(fixture)
		dependencies.authority.decision.ActorRevision++
		service, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
			dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
		_, err := service.authorize(context.Background(), fixture.command)
		if err == nil || Reason(err) != "decision_binding_invalid" || !containsCall(*calls, "authority") {
			t.Fatalf("err=%v calls=%v", err, *calls)
		}
	})
}

func TestPreflightHonorsCancellationWithoutDependencies(t *testing.T) {
	fixture := newBindingFixture(t)
	dependencies, calls := preflightDependencies(fixture)
	service, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
		dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.authorize(ctx, fixture.command)
	if CodeOf(err) != Canceled || len(*calls) != 0 {
		t.Fatalf("err=%v calls=%v", err, *calls)
	}
}

type preflightDeps struct {
	authority *authorityStub
	approvals *approvalStub
	cases     *caseStub
	plans     *planStub
	sources   *sourceStub
	custody   *custodyStub
	clock     clockStub
}

func preflightDependencies(fixture bindingFixture) (preflightDeps, *[]string) {
	calls := []string{}
	log := func(value string) { calls = append(calls, value) }
	return preflightDeps{
		&authorityStub{fixture.decision, log}, &approvalStub{fixture.approval, nil, log},
		&caseStub{fixture.authorizationCase(), log}, &planStub{fixture.plan, fixture.rule, log},
		&sourceStub{fixture.authorizationSource(), 0, nil, log}, &custodyStub{fixture.command.ExpectedCustodyHead, log},
		clockStub{fixture.decision.IssuedAt},
	}, &calls
}

func (fixture bindingFixture) authorizationCase() CaseSnapshot {
	return CaseSnapshot{Case: fixture.command.Case, State: fixture.authorization.CaseState,
		Classification: fixture.authorization.CaseClassification, Revision: fixture.authorization.CaseRevision,
		ProvenanceDigest: fixture.authorization.CaseProvenanceDigest}
}

func (fixture bindingFixture) authorizationSource() VerifiedSource {
	return VerifiedSource{Reference: fixture.command.Source, SourceIdentityDigest: testDigest("c"),
		VerificationDigest: fixture.authorization.SourceVerificationDigest}
}

type authorityStub struct {
	decision Decision
	log      func(string)
}

func (stub *authorityStub) AuthorizeRedaction(_ context.Context, _ AuthorizationRequest) (Decision, error) {
	stub.log("authority")
	return stub.decision, nil
}

type approvalStub struct {
	proof     ApprovalUseProof
	verifyErr error
	log       func(string)
}

func (stub *approvalStub) AuthorizeUse(_ context.Context, _ ApprovalUseRequest) (ApprovalUseProof, bool, error) {
	stub.log("approval_authorize")
	return stub.proof, false, nil
}
func (stub *approvalStub) VerifyUse(_ context.Context, _ ApprovalUseProof) error {
	stub.log("approval_verify")
	return stub.verifyErr
}

type caseStub struct {
	snapshot CaseSnapshot
	log      func(string)
}

func (stub *caseStub) LoadCase(_ context.Context, _ domain.CaseRef) (CaseSnapshot, bool, error) {
	stub.log("case")
	return stub.snapshot, true, nil
}

type planStub struct {
	plan ApprovedPlan
	rule RuleSet
	log  func(string)
}

func (stub *planStub) ResolvePlan(_ context.Context, _ domain.CaseRef, _ string) (ApprovedPlan, bool, error) {
	stub.log("plan")
	return clonePlan(stub.plan), true, nil
}
func (stub *planStub) ResolveRule(_ context.Context, _ string) (RuleSet, bool, error) {
	stub.log("rule")
	return cloneRule(stub.rule), true, nil
}

type sourceStub struct {
	value  VerifiedSource
	calls  int
	onCall func(int, *VerifiedSource)
	log    func(string)
}

func (stub *sourceStub) ResolveSource(_ context.Context, _ domain.CaseRef, _ EvidenceReference) (VerifiedSource, error) {
	stub.calls++
	stub.log("source")
	value := stub.value
	if stub.onCall != nil {
		stub.onCall(stub.calls, &value)
	}
	return value, nil
}

type custodyStub struct {
	head CustodyHead
	log  func(string)
}

func (stub *custodyStub) LoadCustodyHead(_ context.Context, _ domain.CaseRef) (CustodyHead, error) {
	stub.log("head")
	return cloneHead(stub.head), nil
}
func (stub *custodyStub) RecordRedaction(context.Context, CustodyRequest) (CustodyProof, bool, error) {
	return CustodyProof{}, false, errors.New("unexpected")
}
func (stub *custodyStub) VerifyRedaction(context.Context, CustodyProof) error {
	return errors.New("unexpected")
}

type clockStub struct{ value time.Time }

func (stub clockStub) Now() time.Time { return stub.value }

func containsCall(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
