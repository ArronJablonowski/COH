package nativeexecutor

import (
	"context"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/broker/executionstop"
	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

func TestEmergencyStopCooperativelyCancelsNativeExecution(t *testing.T) {
	tracker, err := executionstop.New("native-executions", allowStopGuard{})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	resolver := &fakeResolver{capability: testCapability()}
	artifacts := &fakeArtifacts{prepared: PreparedArtifact{Path: "/private/staged/tool", Digest: testDigest,
		Cleanup: func() error { return nil }}}
	sandbox := &fakeSandbox{execute: func(ctx context.Context, _ Plan) (SandboxResult, error) {
		close(started)
		<-ctx.Done()
		return SandboxResult{ExitCode: -1}, ctx.Err()
	}}
	executor, err := New(resolver, testAuthorizer(), artifacts, sandbox, tracker,
		fixedClock{time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC)}, []Registration{{Tool: testRequest().Tool,
			Operation: "execute", ExecutablePath: "/approved/tool", FixedArguments: []string{"--query"},
			FixedEnvironment: []EnvironmentVariable{{Name: "LANG", Value: "C"}}}})
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(context.Background(), testRequest())
		completed <- executeErr
	}()
	<-started
	request := testRequest()
	evidence, err := tracker.Apply(context.Background(), stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case",
		OrganizationID: request.OrganizationID, TenantID: request.TenantID, CaseID: request.CaseID}, Epoch: 13})
	if err != nil || evidence == "" {
		t.Fatalf("evidence=%q err=%v", evidence, err)
	}
	if executeErr := <-completed; Code(executeErr) != Canceled {
		t.Fatalf("execute err=%v", executeErr)
	}
}
