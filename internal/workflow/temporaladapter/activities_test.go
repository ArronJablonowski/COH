package temporaladapter

import (
	"context"
	"reflect"
	"testing"

	"go.temporal.io/sdk/activity"

	"github.com/ArronJablonowski/COH/internal/domain"
	core "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

type activityRegistration struct {
	handler any
	name    string
}

type activityRegistryStub struct {
	registrations []activityRegistration
}

func (registry *activityRegistryStub) RegisterActivityWithOptions(handler any, options activity.RegisterOptions) {
	registry.registrations = append(registry.registrations, activityRegistration{handler: handler, name: options.Name})
}

type activityModelStub struct{}

func (activityModelStub) Invoke(context.Context, core.ModelRequest) (domain.ArtifactRef, error) {
	return domain.ArtifactRef{}, nil
}

type activityAuthorityStub struct{}

func (activityAuthorityStub) Submit(context.Context, domain.ToolIntent) (domain.ActionReceipt, error) {
	return domain.ActionReceipt{}, nil
}

func TestRegisterAgentLoopActivitiesUsesExactTypedV1Names(t *testing.T) {
	activities, err := agentloop.NewActivities(activityModelStub{}, activityAuthorityStub{})
	if err != nil {
		t.Fatal(err)
	}
	registry := &activityRegistryStub{}
	if err := RegisterAgentLoopActivities(registry, activities); err != nil {
		t.Fatal(err)
	}
	if len(registry.registrations) != 2 ||
		registry.registrations[0].name != agentloop.PlanningActivityName ||
		registry.registrations[1].name != agentloop.AuthorizedActionActivityName {
		t.Fatalf("registrations=%+v", registry.registrations)
	}
	planningType := reflect.TypeOf((func(context.Context, agentloop.PlanningRequest) (agentloop.PlanningResult, error))(nil))
	actionType := reflect.TypeOf((func(context.Context, agentloop.AuthorizedActionRequest) (agentloop.AuthorizedActionResult, error))(nil))
	if reflect.TypeOf(registry.registrations[0].handler) != planningType ||
		reflect.TypeOf(registry.registrations[1].handler) != actionType {
		t.Fatalf("handler types=%v %v", reflect.TypeOf(registry.registrations[0].handler), reflect.TypeOf(registry.registrations[1].handler))
	}
	if err := RegisterAgentLoopActivities(nil, activities); core.EngineCode(err) != core.EngineInvalidInput {
		t.Fatalf("nil registry err=%v", err)
	}
}
