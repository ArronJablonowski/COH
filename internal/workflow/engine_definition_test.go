package workflow

import (
	"context"
	"testing"
)

type definitionDriver struct {
	definition string
	target     WorkflowTarget
}

func (driver definitionDriver) Start(_ context.Context, request WorkflowStart) (WorkflowHandle, error) {
	target := driver.target
	if target.WorkflowID == "" {
		target = WorkflowTarget{Case: request.Operation.Case, WorkflowID: request.Operation.ID, RunID: "run-definition"}
	}
	return WorkflowHandle{Target: target, Definition: driver.definition, Version: "v1"}, nil
}

func (definitionDriver) Signal(context.Context, WorkflowSignal) error { return nil }

func (driver definitionDriver) Query(context.Context, WorkflowQuery) (WorkflowSnapshot, error) {
	return WorkflowSnapshot{Target: driver.target, Definition: driver.definition, Version: "v1",
		State: WorkflowRunning, StartDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}

func (definitionDriver) Cancel(context.Context, WorkflowCancel) error { return nil }

func (driver definitionDriver) Replay(_ context.Context, request WorkflowReplay) (WorkflowReplayResult, error) {
	return WorkflowReplayResult{FixtureID: request.FixtureID, Definition: driver.definition, Version: "v1",
		HistoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Replayed: true}, nil
}

func TestGuardedEngineAcceptsRegisteredAgentLoopResults(t *testing.T) {
	request := workflowStartForStop(stopTestCase, "0198d6c4-7777-7777-8777-777777777777")
	request.Operation.Kind, request.Operation.Version = "agent_loop", AgentLoopWorkflowV1
	target := WorkflowTarget{Case: request.Operation.Case, WorkflowID: request.Operation.ID, RunID: "run-definition"}
	engine, err := GuardEngine(definitionDriver{definition: AgentLoopWorkflowV1, target: target},
		&mutableWorkflowStopGuard{}, NewMemoryWorkflowIndex())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := engine.Start(context.Background(), request)
	if err != nil || handle.Definition != AgentLoopWorkflowV1 {
		t.Fatalf("handle=%+v err=%v", handle, err)
	}
	snapshot, err := engine.Query(context.Background(), WorkflowQuery{ContractVersion: WorkflowContractVersion,
		Target: target, Kind: "snapshot"})
	if err != nil || snapshot.Definition != AgentLoopWorkflowV1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	replay, err := engine.Replay(context.Background(), WorkflowReplay{ContractVersion: WorkflowContractVersion,
		FixtureID: "agent-loop-v1"})
	if err != nil || replay.Definition != AgentLoopWorkflowV1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
}

func TestGuardedEngineDeniesUnregisteredResultDefinitions(t *testing.T) {
	request := workflowStartForStop(stopTestCase, "0198d6c4-8888-7888-8888-888888888888")
	target := WorkflowTarget{Case: request.Operation.Case, WorkflowID: request.Operation.ID, RunID: "run-definition"}
	engine, err := GuardEngine(definitionDriver{definition: "coh.unregistered.v1", target: target},
		&mutableWorkflowStopGuard{}, NewMemoryWorkflowIndex())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Start(context.Background(), request); EngineCode(err) != EngineDenied {
		t.Fatalf("start err=%v", err)
	}
	if _, err = engine.Query(context.Background(), WorkflowQuery{ContractVersion: WorkflowContractVersion,
		Target: target, Kind: "snapshot"}); EngineCode(err) != EngineDenied {
		t.Fatalf("query err=%v", err)
	}
	if _, err = engine.Replay(context.Background(), WorkflowReplay{ContractVersion: WorkflowContractVersion,
		FixtureID: "unregistered-v1"}); EngineCode(err) != EngineDenied {
		t.Fatalf("replay err=%v", err)
	}
}

var _ EngineDriver = definitionDriver{}
