package estop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

const (
	testOrg     = "018f47a6-4b2c-7a1e-8a12-123456789abc"
	testTenant  = "018f47a6-4b2c-7a1e-8a12-123456789abd"
	testCase    = "018f47a6-4b2c-7a1e-8a12-123456789abe"
	testOther   = "018f47a6-4b2c-7a1e-8a12-123456789abf"
	testActor   = "018f47a6-4b2c-7a1e-8a12-123456789ac0"
	testRequest = "018f47a6-4b2c-7a1e-8a12-123456789ac1"
)

type fixedClock struct{ now time.Time }

func (clock *fixedClock) Now() time.Time { return clock.now }

type fakeAudit struct {
	mu        sync.Mutex
	fail      bool
	decisions []stopcontract.Decision
}

func (audit *fakeAudit) AppendEmergencyStopDecision(_ context.Context, decision stopcontract.Decision) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.fail {
		return errors.New("audit unavailable")
	}
	audit.decisions = append(audit.decisions, decision)
	return nil
}

type fakeControl struct {
	id    string
	kind  string
	err   error
	calls atomic.Int32
}

func (control *fakeControl) ID() string   { return control.id }
func (control *fakeControl) Kind() string { return control.kind }
func (control *fakeControl) Apply(_ context.Context, request stopcontract.ControlRequest) (string, error) {
	control.calls.Add(1)
	if request.Epoch == 0 {
		return "", errors.New("missing epoch")
	}
	if control.err != nil {
		return "", control.err
	}
	return digest("evidence-" + control.id), nil
}

func TestGlobalActivationAppliesEveryControlAndGuard(t *testing.T) {
	controller, _, audit, controls, _ := setup(t)
	command, authority := fixture(false)
	result, decision, err := controller.Activate(context.Background(), command, authority)
	if err != nil || decision.Outcome != "allowed" || result.State.Epoch != 1 || len(result.Acknowledgements) != 5 || result.AuditPending {
		t.Fatalf("result=%#v decision=%#v err=%v", result, decision, err)
	}
	for _, control := range controls {
		if control.calls.Load() != 1 {
			t.Fatalf("control %s calls=%d", control.id, control.calls.Load())
		}
	}
	if len(audit.decisions) != 6 {
		t.Fatalf("audit decisions=%d", len(audit.decisions))
	}
	if state, err := controller.Check(context.Background(), testOrg, testTenant, testCase); stopcontract.Reason(err) != "emergency_stop_active" || state.Epoch != 1 {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	for _, ack := range result.Acknowledgements {
		if ack.Outcome != "applied" || ack.ElapsedNanos >= ack.ObjectiveNanos {
			t.Fatalf("ack=%#v", ack)
		}
	}
}

func TestCaseScopeDoesNotStopOtherCase(t *testing.T) {
	controller, _, _, _, _ := setup(t)
	command, authority := fixture(true)
	if _, _, err := controller.Activate(context.Background(), command, authority); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Check(context.Background(), testOrg, testTenant, testCase); stopcontract.Code(err) != stopcontract.Denied {
		t.Fatalf("target case err=%v", err)
	}
	if _, err := controller.Check(context.Background(), testOrg, testTenant, testOther); err != nil {
		t.Fatalf("other case err=%v", err)
	}
}

func TestExactReplayAndChangedCollision(t *testing.T) {
	controller, _, _, controls, _ := setup(t)
	command, authority := fixture(false)
	first, _, err := controller.Activate(context.Background(), command, authority)
	if err != nil {
		t.Fatal(err)
	}
	replayed, _, err := controller.Activate(context.Background(), command, authority)
	if err != nil || replayed.State != first.State || len(replayed.Acknowledgements) != 0 {
		t.Fatalf("replay=%#v err=%v", replayed, err)
	}
	for _, control := range controls {
		if control.calls.Load() != 1 {
			t.Fatalf("control %s calls=%d", control.id, control.calls.Load())
		}
	}
	command.ReasonCode = "incident_containment"
	if _, _, err = controller.Activate(context.Background(), command, authority); stopcontract.Code(err) != stopcontract.Conflict {
		t.Fatalf("collision err=%v", err)
	}
}

func TestAuditFailureDoesNotUndoStopAndRecoversOutbox(t *testing.T) {
	controller, _, audit, controls, _ := setup(t)
	audit.fail = true
	command, authority := fixture(false)
	result, _, err := controller.Activate(context.Background(), command, authority)
	if stopcontract.Reason(err) != "audit_delivery_pending" || !result.AuditPending {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if _, checkErr := controller.Check(context.Background(), testOrg, testTenant, testCase); stopcontract.Reason(checkErr) != "emergency_stop_active" {
		t.Fatalf("check err=%v", checkErr)
	}
	for _, control := range controls {
		if control.calls.Load() != 1 {
			t.Fatalf("control %s was skipped", control.id)
		}
	}
	audit.fail = false
	delivered, err := controller.RecoverAudit(context.Background(), 32)
	if err != nil || delivered != 6 || len(audit.decisions) != 6 {
		t.Fatalf("delivered=%d audit=%d err=%v", delivered, len(audit.decisions), err)
	}
}

func TestControlFailureIsRecordedAndStopRemainsActive(t *testing.T) {
	controller, _, _, controls, _ := setup(t)
	controls[1].err = errors.New("egress unavailable")
	command, authority := fixture(false)
	result, _, err := controller.Activate(context.Background(), command, authority)
	if stopcontract.Reason(err) != "containment_incomplete" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	failed := 0
	for _, ack := range result.Acknowledgements {
		if ack.Outcome == "failed" {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("failed=%d acks=%#v", failed, result.Acknowledgements)
	}
	if _, checkErr := controller.Check(context.Background(), testOrg, testTenant, testCase); stopcontract.Code(checkErr) != stopcontract.Denied {
		t.Fatalf("check err=%v", checkErr)
	}
}

func TestDeniedCanceledAndConcurrentActivation(t *testing.T) {
	controller, _, audit, controls, _ := setup(t)
	command, authority := fixture(false)
	denied := authority
	denied.PolicyAllowed = false
	if _, decision, err := controller.Activate(context.Background(), command, denied); stopcontract.Code(err) != stopcontract.Denied || decision.Outcome != "denied" {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	command.IdempotencyKey, command.RequestID = "stop-canceled", "018f47a6-4b2c-7a1e-8a12-123456789ac2"
	if _, decision, err := controller.Activate(canceled, command, authority); stopcontract.Code(err) != stopcontract.Canceled || decision.Outcome != "canceled" {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	command.IdempotencyKey, command.RequestID = "stop-concurrent", "018f47a6-4b2c-7a1e-8a12-123456789ac3"
	var wait sync.WaitGroup
	var success atomic.Int32
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			if _, _, err := controller.Activate(context.Background(), command, authority); err == nil {
				success.Add(1)
			}
		}()
	}
	wait.Wait()
	if success.Load() != 2 { // one activation plus one exact replay
		t.Fatalf("success=%d", success.Load())
	}
	for _, control := range controls {
		if control.calls.Load() != 1 {
			t.Fatalf("control %s calls=%d", control.id, control.calls.Load())
		}
	}
	if len(audit.decisions) < 3 {
		t.Fatalf("audit decisions=%d", len(audit.decisions))
	}
}

func setup(t *testing.T) (*Controller, *MemoryStore, *fakeAudit, []*fakeControl, *fixedClock) {
	t.Helper()
	clock := &fixedClock{now: time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC)}
	store, audit := NewMemoryStore(), &fakeAudit{}
	controls := []*fakeControl{{id: "credential-revoker", kind: "credential"}, {id: "runner-egress", kind: "egress"},
		{id: "remote-jobs", kind: "remote_job"}, {id: "workflow-signal", kind: "workflow"},
		{id: "cooperative-work", kind: "cooperative"}}
	ports := make([]Control, len(controls))
	for index := range controls {
		ports[index] = controls[index]
	}
	controller, err := NewWithDependencies(store, audit, clock, ports...)
	if err != nil {
		t.Fatal(err)
	}
	return controller, store, audit, controls, clock
}

func fixture(caseScoped bool) (stopcontract.Command, stopcontract.Authority) {
	scope := stopcontract.Scope{Kind: "global", OrganizationID: testOrg, TenantID: testTenant}
	if caseScoped {
		scope.Kind, scope.CaseID = "case", testCase
	}
	command := stopcontract.Command{SchemaVersion: stopcontract.CommandSchemaVersion,
		ContractVersion: stopcontract.ContractVersion, RequestID: testRequest, IdempotencyKey: "stop-1",
		Scope: scope, ActorID: testActor, ReasonCode: "operator_emergency"}
	authority := stopcontract.Authority{Scope: scope, ActorID: testActor, ActorRevision: 4, ActorActive: true,
		AuthorizationAllowed: true, AuthorizationDecisionDigest: digest("authorization"), PolicyAllowed: true,
		PolicyDecisionDigest: digest("policy"), ObservedAt: time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC)}
	return command, authority
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
