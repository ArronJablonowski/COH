package ociexecutor

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/broker/executionstop"
	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

func TestEmergencyStopCooperativelyCancelsOCIExecution(t *testing.T) {
	executor, _, _, _, runtime := testExecutor()
	tracker, err := executionstop.New("oci-executions", &mutableStopGuard{})
	if err != nil {
		t.Fatal(err)
	}
	executor.execution = tracker
	runtime.started = make(chan struct{})
	runtime.block = make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(context.Background(), testRequest())
		completed <- executeErr
	}()
	<-runtime.started
	request := testRequest()
	evidence, err := tracker.Apply(context.Background(), stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case",
		OrganizationID: request.OrganizationID, TenantID: request.TenantID, CaseID: request.CaseID}, Epoch: 14})
	if err != nil || evidence == "" {
		t.Fatalf("evidence=%q err=%v", evidence, err)
	}
	if executeErr := <-completed; Code(executeErr) != Canceled {
		t.Fatalf("execute err=%v", executeErr)
	}
}
