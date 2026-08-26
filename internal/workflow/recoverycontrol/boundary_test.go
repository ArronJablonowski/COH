package recoverycontrol

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type controlStub struct {
	request InvokeRequest
	result  Result
	err     error
}

func (*controlStub) Recover(context.Context, RecoverRequest) (Result, error) { return Result{}, nil }
func (*controlStub) Cancel(context.Context, CancelRequest) (Result, error)   { return Result{}, nil }
func (stub *controlStub) Invoke(_ context.Context, request InvokeRequest) (Result, error) {
	stub.request = request
	return stub.result, stub.err
}

func TestRoutedModelCarriesExactWorkflowBindingsIntoFallbackControl(t *testing.T) {
	control := &controlStub{result: Result{Status: Completed, Artifact: validArtifactRef()}}
	model, err := NewRoutedModel(control)
	if err != nil {
		t.Fatal(err)
	}
	request := workflowbase.ModelRequest{RunID: testRun,
		Operation:    domain.Operation{ID: testTask, Case: validScope(), Kind: "agent_plan", Version: "coh.agent-loop.v1"},
		PolicyDigest: testDigest1, ProviderRoute: "connected", InputRefs: []string{testDigest1, testDigest2},
		BudgetReservationDigest: testDigest3, CreatedAt: testNow.Add(-1), Deadline: testNow.Add(1)}
	artifact, err := model.Invoke(context.Background(), request)
	if err != nil || artifact != validArtifactRef() || control.request.ControlID != testTask ||
		control.request.RunID != testRun || control.request.PolicyDigest != testDigest1 ||
		control.request.RequestedRoute != "connected" || control.request.BudgetReservationDigest != testDigest3 ||
		!reflect.DeepEqual(control.request.InputRefs, request.InputRefs) {
		t.Fatalf("artifact=%+v request=%+v err=%v", artifact, control.request, err)
	}
}

func TestPublicRecoverySurfaceHasNoPolicyExecutorConnectorOrGenericCallbackCapability(t *testing.T) {
	for _, value := range []any{WorkSnapshot{}, CancelTarget{}, CancellationAck{}, CapabilityProfile{},
		RouteBinding{}, ProviderAttempt{}, Record{}, RecoverRequest{}, CancelRequest{}, InvokeRequest{},
		Result{}, WorkLookup{}, WorkResume{}, CancelCommand{}, RouteApprovalRequest{}, AttemptRequest{}, AttemptReceipt{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{"prompt", "instruction", "credential", "secret", "policyauthority",
				"toolauthority", "connector", "executor", "callback", "function"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("unsafe public field %s.%s", typeOf.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface {
				t.Fatalf("executable public field %s.%s: %v", typeOf.Name(), field.Name, field.Type)
			}
		}
	}
	control := reflect.TypeOf((*Control)(nil)).Elem()
	if control.NumMethod() != 3 {
		t.Fatalf("control methods=%d", control.NumMethod())
	}
}
