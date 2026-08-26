package temporaladapter

import (
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/worker"

	core "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

// AgentLoopActivityRegistry is the minimum Temporal worker registration
// capability needed by the agent loop.
type AgentLoopActivityRegistry interface {
	RegisterActivityWithOptions(any, activity.RegisterOptions)
}

var _ AgentLoopActivityRegistry = (worker.Worker)(nil)

// RegisterAgentLoopActivities binds the immutable v1 activity names to the
// typed planning and broker-authorized action boundaries.
func RegisterAgentLoopActivities(registry AgentLoopActivityRegistry, activities *agentloop.Activities) error {
	if registry == nil || activities == nil {
		return engineError(core.EngineInvalidInput, "register_agent_loop", "dependencies", "activity registry and activities are required")
	}
	registry.RegisterActivityWithOptions(activities.Plan, activity.RegisterOptions{Name: agentloop.PlanningActivityName})
	registry.RegisterActivityWithOptions(activities.Act, activity.RegisterOptions{Name: agentloop.AuthorizedActionActivityName})
	return nil
}
