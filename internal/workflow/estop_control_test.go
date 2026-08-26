package workflow

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

const (
	stopTestOrg    = "0198d6c4-1111-7111-8111-111111111111"
	stopTestTenant = "0198d6c4-2222-7222-8222-222222222222"
	stopTestCase   = "0198d6c4-3333-7333-8333-333333333333"
	stopOtherCase  = "0198d6c4-4444-7444-8444-444444444444"
)

type mutableWorkflowStopGuard struct {
	mu  sync.Mutex
	err error
}

func (guard *mutableWorkflowStopGuard) Allow(context.Context, string, string, string) error {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.err
}

func (guard *mutableWorkflowStopGuard) set(err error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.err = err
}

type workflowDriverStub struct {
	mu        sync.Mutex
	startHook func()
	signals   []WorkflowSignal
	cancels   []WorkflowCancel
}

func (driver *workflowDriverStub) Start(_ context.Context, request WorkflowStart) (WorkflowHandle, error) {
	if driver.startHook != nil {
		driver.startHook()
	}
	return WorkflowHandle{Target: WorkflowTarget{Case: request.Operation.Case, WorkflowID: request.Operation.ID,
		RunID: "run-1"}, Definition: OperationWorkflowV1, Version: "v1"}, nil
}

func (driver *workflowDriverStub) Signal(_ context.Context, request WorkflowSignal) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.signals = append(driver.signals, request)
	return nil
}

func (driver *workflowDriverStub) Query(context.Context, WorkflowQuery) (WorkflowSnapshot, error) {
	return WorkflowSnapshot{}, errors.New("not used")
}

func (driver *workflowDriverStub) Cancel(_ context.Context, request WorkflowCancel) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.cancels = append(driver.cancels, request)
	return nil
}

func (driver *workflowDriverStub) Replay(context.Context, WorkflowReplay) (WorkflowReplayResult, error) {
	return WorkflowReplayResult{}, errors.New("not used")
}

func TestGuardedEngineSignalsAndCancelsOnlyStoppedCase(t *testing.T) {
	driver, guard := &workflowDriverStub{}, &mutableWorkflowStopGuard{}
	engine, err := GuardEngine(driver, guard, NewMemoryWorkflowIndex())
	if err != nil {
		t.Fatal(err)
	}
	startWorkflowForStop(t, engine, stopTestCase, "0198d6c4-5555-7555-8555-555555555555")
	startWorkflowForStop(t, engine, stopOtherCase, "0198d6c4-6666-7666-8666-666666666666")
	guard.set(stopcontract.NewError(stopcontract.Denied, "emergency_stop_active"))
	request := stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case", OrganizationID: stopTestOrg,
		TenantID: stopTestTenant, CaseID: stopTestCase}, Epoch: 7}
	first, err := engine.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Apply(context.Background(), request)
	if err != nil || first == "" || second != first {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(driver.signals) != 1 || len(driver.cancels) != 1 || driver.signals[0].Kind != "emergency_stop" ||
		driver.signals[0].Target.Case.CaseID != stopTestCase || driver.cancels[0].Target.Case.CaseID != stopTestCase {
		t.Fatalf("signals=%+v cancels=%+v", driver.signals, driver.cancels)
	}
}

func TestGuardedEngineClosesStartActivationRace(t *testing.T) {
	guard := &mutableWorkflowStopGuard{}
	driver := &workflowDriverStub{startHook: func() {
		guard.set(stopcontract.NewError(stopcontract.Denied, "emergency_stop_active"))
	}}
	engine, err := GuardEngine(driver, guard, NewMemoryWorkflowIndex())
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Start(context.Background(), workflowStartForStop(stopTestCase, "0198d6c4-7777-7777-8777-777777777777"))
	if EngineCode(err) != EngineDenied {
		t.Fatalf("err=%v", err)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(driver.cancels) != 1 || driver.cancels[0].Target.Case.CaseID != stopTestCase {
		t.Fatalf("cancels=%+v", driver.cancels)
	}
}

func startWorkflowForStop(t *testing.T, engine *GuardedEngine, caseID, operationID string) {
	t.Helper()
	if _, err := engine.Start(context.Background(), workflowStartForStop(caseID, operationID)); err != nil {
		t.Fatal(err)
	}
}

func workflowStartForStop(caseID, operationID string) WorkflowStart {
	return WorkflowStart{ContractVersion: WorkflowContractVersion, IdempotencyKey: "start-" + operationID,
		Operation: domain.Operation{ID: operationID, Case: domain.CaseRef{OrganizationID: stopTestOrg,
			TenantID: stopTestTenant, CaseID: caseID}, Kind: "operation", Version: OperationWorkflowV1},
		InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}
