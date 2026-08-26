package agentloop

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/toolroute"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	PlanningActivityName         = "coh.agent-loop.plan.v2"
	AuthorizedActionActivityName = "coh.agent-loop.authorized-action.v1"
)

// PlanningRequest is the bounded, reference-only input to model planning.
type PlanningRequest struct {
	Operation               domain.Operation
	RunID                   string
	PolicyDigest            string
	ProviderRoute           string
	InputRefs               []string
	BudgetReservationDigest string
	CreatedAt               time.Time
	Deadline                time.Time
}

// PlanningResult returns only an immutable artifact reference.
type PlanningResult struct {
	Artifact domain.ArtifactRef
}

// AuthorizedActionRequest binds an exact tool intent to its canonical digest.
type AuthorizedActionRequest struct {
	Intent       domain.ToolIntent
	IntentDigest string
}

// AuthorizedActionResult returns only the broker-owned receipt.
type AuthorizedActionResult struct {
	Receipt domain.ActionReceipt
}

// Activities is the complete executable surface available to the durable loop.
// It deliberately exposes no connector, runner, credential, shell, HTTP, or
// generic callback capability.
type Activities struct {
	models  workflowbase.ModelProvider
	actions workflowbase.ActionAuthority
}

func NewActivities(models workflowbase.ModelProvider, actions workflowbase.ActionAuthority) (*Activities, error) {
	if models == nil || actions == nil {
		return nil, newError(InvalidInput, "new_activities", "dependencies_required", false, nil)
	}
	return &Activities{models: models, actions: actions}, nil
}

func (activities *Activities) Plan(ctx context.Context, request PlanningRequest) (PlanningResult, error) {
	if activities == nil || activities.models == nil {
		return PlanningResult{}, newError(InvalidInput, "plan_activity", "activity_required", false, nil)
	}
	if err := validateContext(ctx, "plan_activity"); err != nil {
		return PlanningResult{}, err
	}
	if !uuidV7Pattern.MatchString(request.Operation.ID) || !validateCase(request.Operation.Case) ||
		request.Operation.Kind != "agent_plan" || request.Operation.Version != WorkflowDefinition ||
		!uuidV7Pattern.MatchString(request.RunID) || !digestPattern.MatchString(request.PolicyDigest) ||
		!tokenPattern.MatchString(request.ProviderRoute) || !validateReferences(request.InputRefs) ||
		!digestPattern.MatchString(request.BudgetReservationDigest) || !validTimes(request.CreatedAt, request.Deadline) {
		return PlanningResult{}, newError(InvalidInput, "plan_activity", "request_invalid", false, nil)
	}
	artifact, err := activities.models.Invoke(ctx, workflowbase.ModelRequest{RunID: request.RunID,
		Operation: request.Operation, PolicyDigest: request.PolicyDigest, ProviderRoute: request.ProviderRoute,
		InputRefs: append([]string{}, request.InputRefs...), BudgetReservationDigest: request.BudgetReservationDigest,
		CreatedAt: request.CreatedAt, Deadline: request.Deadline})
	if err != nil {
		return PlanningResult{}, err
	}
	if !validArtifact(artifact) {
		return PlanningResult{}, newError(Denied, "plan_activity", "model_artifact_invalid", false, nil)
	}
	return PlanningResult{Artifact: artifact}, nil
}

func (activities *Activities) Act(ctx context.Context, request AuthorizedActionRequest) (AuthorizedActionResult, error) {
	if activities == nil || activities.actions == nil {
		return AuthorizedActionResult{}, newError(InvalidInput, "action_activity", "activity_required", false, nil)
	}
	if err := validateContext(ctx, "action_activity"); err != nil {
		return AuthorizedActionResult{}, err
	}
	digest, err := toolIntentDigest(request.Intent)
	if err != nil || digest != request.IntentDigest || !validToolIntent(request.Intent) {
		return AuthorizedActionResult{}, newError(Denied, "action_activity", "intent_binding_invalid", false, nil)
	}
	receipt, err := activities.actions.Submit(ctx, request.Intent)
	if err != nil {
		return AuthorizedActionResult{}, err
	}
	if !validReceipt(receipt, request.IntentDigest) {
		return AuthorizedActionResult{}, newError(Denied, "action_activity", "broker_receipt_invalid", false, nil)
	}
	return AuthorizedActionResult{Receipt: receipt}, nil
}

func validToolIntent(value domain.ToolIntent) bool {
	return toolroute.ValidateIntent(value) == nil
}
