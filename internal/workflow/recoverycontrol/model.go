package recoverycontrol

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

// RoutedModel adapts recovery control to the ordinary workflow model port.
// The task UUID is also the unique fallback control identity; the dedicated
// recovery-control store prevents collision with unrelated workflow records.
type RoutedModel struct{ control Control }

func NewRoutedModel(control Control) (*RoutedModel, error) {
	if control == nil {
		return nil, newError(InvalidInput, "control_required", false, false, nil)
	}
	return &RoutedModel{control: control}, nil
}

func (model *RoutedModel) Invoke(ctx context.Context, request workflowbase.ModelRequest) (domain.ArtifactRef, error) {
	if model == nil || model.control == nil {
		return domain.ArtifactRef{}, newError(InvalidInput, "routed_model_required", false, false, nil)
	}
	result, err := model.control.Invoke(ctx, InvokeRequest{IdempotencyKey: "model:" + request.RunID + ":" + request.Operation.ID,
		ControlID: request.Operation.ID, Case: request.Operation.Case, RunID: request.RunID,
		TaskID: request.Operation.ID, PolicyDigest: request.PolicyDigest, RequestedRoute: request.ProviderRoute,
		Operation: request.Operation, InputRefs: append([]string{}, request.InputRefs...),
		BudgetReservationDigest: request.BudgetReservationDigest,
		CreatedAt:               request.CreatedAt, Deadline: request.Deadline})
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	if result.Status != Completed || !validArtifact(result.Artifact) {
		return domain.ArtifactRef{}, newError(DeniedCode, "routed_model_result_invalid", false, false, nil)
	}
	return result.Artifact, nil
}

var _ workflowbase.ModelProvider = (*RoutedModel)(nil)
