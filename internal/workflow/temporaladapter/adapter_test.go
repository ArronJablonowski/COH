package temporaladapter

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	temporalworkflow "go.temporal.io/sdk/workflow"

	"github.com/ArronJablonowski/COH/internal/domain"
	core "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	testOrganization = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	testTenant       = "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16"
	testCase         = "0198d6c4-7618-7d31-8e0a-9da53cae8ca2"
	testOperation    = "0198d6c4-8888-7888-8888-888888888888"
	testRun          = "d2dce302-1a1a-4e72-9ca4-0f12e890c511"
	testDigest       = "sha256:72c84ba99d77ee766e9468a0d7b1f94664b05b24d4c9b96b6230675f3efc0f6c"
	testDigestTwo    = "sha256:9d6f965ac832e40a5df6c06afe983e3b5d646a0adf735e08c289de018a2bf09f"
)

func TestAdapterRuntimeAndIdempotency(t *testing.T) {
	request := testStart()
	startDigest, err := digestValue(request)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeTemporalClient{snapshot: core.WorkflowSnapshot{
		Target:     core.WorkflowTarget{Case: request.Operation.Case, WorkflowID: request.Operation.ID, RunID: testRun},
		Definition: core.OperationWorkflowV1, Version: workflowVersion, State: core.WorkflowRunning, StartDigest: startDigest,
	}}
	adapter, err := New(backend, Config{TaskQueue: "coh-workstation", ExecutionTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := core.GuardEngine(adapter, allowStopGuard{}, core.NewMemoryWorkflowIndex())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := engine.Start(context.Background(), request)
	if err != nil || handle.Replayed || handle.Target.RunID != testRun {
		t.Fatalf("start = %+v, err = %v", handle, err)
	}
	backend.duplicate = true
	handle, err = engine.Start(context.Background(), request)
	if err != nil || !handle.Replayed {
		t.Fatalf("replay start = %+v, err = %v", handle, err)
	}
	changed := request
	changed.InputDigest = testDigestTwo
	if _, err := engine.Start(context.Background(), changed); core.EngineCode(err) != core.EngineConflict {
		t.Fatalf("changed start code = %q, err = %v", core.EngineCode(err), err)
	}

	signal := core.WorkflowSignal{ContractVersion: core.WorkflowContractVersion, IdempotencyKey: "advance-1", Target: handle.Target, Kind: "advance", PayloadDigest: testDigest}
	if err := engine.Signal(context.Background(), signal); err != nil {
		t.Fatal(err)
	}
	if backend.signal.IdempotencyDigest == digestBytes([]byte(signal.IdempotencyKey)) && backend.signal.IdempotencyDigest != signal.IdempotencyKey && backend.signal.PayloadDigest == signal.PayloadDigest {
		// Expected: only hashes and registered tokens cross into history.
	} else {
		t.Fatalf("signal payload = %+v", backend.signal)
	}
	snapshot, err := engine.Query(context.Background(), core.WorkflowQuery{ContractVersion: core.WorkflowContractVersion, Target: handle.Target, Kind: "snapshot"})
	if err != nil || snapshot.Target != handle.Target {
		t.Fatalf("query = %+v, err = %v", snapshot, err)
	}
	cancel := core.WorkflowCancel{ContractVersion: core.WorkflowContractVersion, IdempotencyKey: "cancel-1", Target: handle.Target, ReasonDigest: testDigestTwo}
	if err := engine.Cancel(context.Background(), cancel); err != nil || !backend.canceled || backend.signal.Kind != "cancel" || backend.signal.PayloadDigest != cancel.ReasonDigest {
		t.Fatalf("cancel err = %v, backend = %+v", err, backend)
	}
}

func TestGuardRejectsInvalidAndCanceledRequests(t *testing.T) {
	backend := &fakeTemporalClient{}
	adapter, err := New(backend, Config{TaskQueue: "coh-workstation"})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := core.GuardEngine(adapter, allowStopGuard{}, core.NewMemoryWorkflowIndex())
	if err != nil {
		t.Fatal(err)
	}
	invalid := testStart()
	invalid.InputDigest = "raw-value"
	if _, err := engine.Start(context.Background(), invalid); core.EngineCode(err) != core.EngineInvalidInput || backend.executeCalls != 0 {
		t.Fatalf("invalid start code = %q, calls = %d", core.EngineCode(err), backend.executeCalls)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Start(canceled, testStart()); core.EngineCode(err) != core.EngineCanceled || backend.executeCalls != 0 {
		t.Fatalf("canceled start code = %q, calls = %d", core.EngineCode(err), backend.executeCalls)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := engine.Start(expired, testStart()); core.EngineCode(err) != core.EngineTimeout {
		t.Fatalf("expired start code = %q", core.EngineCode(err))
	}
	if _, err := engine.Start(context.Background(), testStart()); err != nil {
		t.Fatalf("clean-context recovery: %v", err)
	}
	backend.executeErr = errors.New("secret temporal endpoint detail")
	if _, err := engine.Start(context.Background(), testStart()); core.EngineCode(err) != core.EngineUnavailable || strings.Contains(err.Error(), "secret temporal") {
		t.Fatalf("backend redaction code = %q, err = %v", core.EngineCode(err), err)
	}
}

func TestOperationWorkflowLifecycleAndSignalReplay(t *testing.T) {
	request := testStart()
	startDigest, _ := digestValue(request)
	input := inputFromStart(request, startDigest)
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	environment.RegisterWorkflowWithOptions(OperationWorkflow, temporalworkflow.RegisterOptions{Name: core.OperationWorkflowV1})
	first := lifecycleSignal{IdempotencyDigest: digestBytes([]byte("advance-1")), RequestDigest: testDigest, Kind: "advance", PayloadDigest: testDigest}
	environment.RegisterDelayedCallback(func() { environment.SignalWorkflow(signalLifecycle, first) }, time.Second)
	environment.RegisterDelayedCallback(func() { environment.SignalWorkflow(signalLifecycle, first) }, 2*time.Second)
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(signalLifecycle, lifecycleSignal{IdempotencyDigest: digestBytes([]byte("complete-1")), RequestDigest: testDigestTwo, Kind: "complete", PayloadDigest: testDigestTwo})
	}, 3*time.Second)
	environment.ExecuteWorkflow(core.OperationWorkflowV1, input)
	if err := environment.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var result core.WorkflowSnapshot
	if err := environment.GetWorkflowResult(&result); err != nil {
		t.Fatal(err)
	}
	if result.State != core.WorkflowCompleted || result.Sequence != 2 || result.LastSignalDigest != testDigestTwo || result.StartDigest != startDigest {
		t.Fatalf("workflow result = %+v", result)
	}
}

func TestOperationWorkflowDeniesChangedSignalReplay(t *testing.T) {
	request := testStart()
	startDigest, _ := digestValue(request)
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	environment.RegisterWorkflowWithOptions(OperationWorkflow, temporalworkflow.RegisterOptions{Name: core.OperationWorkflowV1})
	idempotency := digestBytes([]byte("same-signal"))
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(signalLifecycle, lifecycleSignal{IdempotencyDigest: idempotency, RequestDigest: testDigest, Kind: "advance", PayloadDigest: testDigest})
	}, time.Second)
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(signalLifecycle, lifecycleSignal{IdempotencyDigest: idempotency, RequestDigest: testDigestTwo, Kind: "advance", PayloadDigest: testDigestTwo})
	}, 2*time.Second)
	var observed core.WorkflowSnapshot
	environment.RegisterDelayedCallback(func() {
		value, err := environment.QueryWorkflow(querySnapshot)
		if err == nil {
			err = value.Get(&observed)
		}
		if err != nil {
			t.Errorf("query: %v", err)
		}
		environment.CancelWorkflow()
	}, 3*time.Second)
	environment.ExecuteWorkflow(core.OperationWorkflowV1, inputFromStart(request, startDigest))
	if err := environment.GetWorkflowError(); !temporal.IsCanceledError(err) {
		t.Fatalf("workflow error = %v", err)
	}
	if observed.State != core.WorkflowDenied || observed.Sequence != 1 || observed.LastSignalDigest != testDigest {
		t.Fatalf("denied snapshot = %+v", observed)
	}
}

func TestRetainedHistoryReplay(t *testing.T) {
	history, err := os.ReadFile("testdata/coh-operation-v1-history.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(history)
	adapter, err := New(&fakeTemporalClient{}, Config{
		TaskQueue: "coh-workstation",
		Histories: map[string]RetainedHistory{
			"operation-v1": {Definition: core.OperationWorkflowV1, Version: workflowVersion, Digest: digest, JSON: history},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := core.GuardEngine(adapter, allowStopGuard{}, core.NewMemoryWorkflowIndex())
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Replay(context.Background(), core.WorkflowReplay{ContractVersion: core.WorkflowContractVersion, FixtureID: "operation-v1"})
	if err != nil || !result.Replayed || result.HistoryDigest != digest {
		t.Fatalf("replay = %+v, err = %v", result, err)
	}
	tampered := append([]byte(nil), history...)
	tampered[len(tampered)-2] ^= 1
	if _, err := New(&fakeTemporalClient{}, Config{TaskQueue: "coh-workstation", Histories: map[string]RetainedHistory{
		"operation-v1": {Definition: core.OperationWorkflowV1, Version: workflowVersion, Digest: digest, JSON: tampered},
	}}); core.EngineCode(err) != core.EngineDenied {
		t.Fatalf("tampered registration code = %q, err = %v", core.EngineCode(err), err)
	}
}

func testStart() core.WorkflowStart {
	return core.WorkflowStart{
		ContractVersion: core.WorkflowContractVersion,
		IdempotencyKey:  "start-operation",
		Operation: domain.Operation{
			ID:   testOperation,
			Case: domain.CaseRef{OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase},
			Kind: "case", Version: core.OperationWorkflowV1,
		},
		InputDigest: testDigest,
	}
}

type allowStopGuard struct{}

func (allowStopGuard) Allow(context.Context, string, string, string) error { return nil }

type fakeTemporalClient struct {
	duplicate    bool
	executeCalls int
	executeErr   error
	snapshot     core.WorkflowSnapshot
	signal       lifecycleSignal
	canceled     bool
}

func (fake *fakeTemporalClient) ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error) {
	fake.executeCalls++
	if fake.executeErr != nil {
		return nil, fake.executeErr
	}
	if fake.duplicate {
		return nil, serviceerror.NewWorkflowExecutionAlreadyStarted("duplicate", "request", testRun)
	}
	return fakeWorkflowRun{id: testOperation, runID: testRun}, nil
}

func (fake *fakeTemporalClient) SignalWorkflow(_ context.Context, _, _, _ string, arg interface{}) error {
	payload, ok := arg.(lifecycleSignal)
	if !ok {
		return errors.New("unexpected signal")
	}
	fake.signal = payload
	return nil
}

func (fake *fakeTemporalClient) QueryWorkflow(context.Context, string, string, string, ...interface{}) (converter.EncodedValue, error) {
	payload, err := converter.GetDefaultDataConverter().ToPayloads(fake.snapshot)
	if err != nil {
		return nil, err
	}
	return client.NewValue(payload), nil
}

func (fake *fakeTemporalClient) CancelWorkflow(context.Context, string, string) error {
	fake.canceled = true
	return nil
}

type fakeWorkflowRun struct{ id, runID string }

func (run fakeWorkflowRun) GetID() string                          { return run.id }
func (run fakeWorkflowRun) GetRunID() string                       { return run.runID }
func (run fakeWorkflowRun) GetFirstExecutionRunID() string         { return run.runID }
func (run fakeWorkflowRun) Get(context.Context, interface{}) error { return nil }
func (run fakeWorkflowRun) GetWithOptions(context.Context, interface{}, client.WorkflowRunGetOptions) error {
	return nil
}
