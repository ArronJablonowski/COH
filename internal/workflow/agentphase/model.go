package agentphase

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type phaseModel struct {
	models  workflowbase.ModelProvider
	results ResultResolver
}

func (model *phaseModel) Invoke(ctx context.Context, operation domain.Operation) (domain.ArtifactRef, error) {
	phase, err := phaseFromStepID(operation.ID)
	if err != nil || phase == ActPhase {
		return domain.ArtifactRef{}, newError(Denied, "phase_model", "phase_identity_invalid", false, nil)
	}
	operation.Kind = "agent_" + string(phase)
	operation.Version = ContractVersion
	artifact, err := model.models.Invoke(ctx, operation)
	if err != nil {
		return domain.ArtifactRef{}, mapContextOrUnavailable("phase_model", err)
	}
	if !validArtifact(artifact) {
		return domain.ArtifactRef{}, newError(Denied, "phase_model", "artifact_invalid", false, nil)
	}
	output, err := model.results.Resolve(ctx, artifact.Digest, phase)
	if err != nil {
		return domain.ArtifactRef{}, mapContextOrUnavailable("phase_model", err)
	}
	if err := validatePhaseOutput(output); err != nil || output.Phase != phase || output.ArtifactDigest != artifact.Digest {
		return domain.ArtifactRef{}, newError(Denied, "phase_model", "structured_output_invalid", false, nil)
	}
	return artifact, nil
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && validateOpaque(value.MediaType, 256) &&
		tokenPattern.MatchString(value.Classification) && value.Length >= 0
}

func mapContextOrUnavailable(operation string, err error) error {
	if errors.Is(err, context.Canceled) {
		return newError(Canceled, operation, "dependency_canceled", false, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, operation, "dependency_timeout", false, context.DeadlineExceeded)
	}
	var phaseError *Error
	if errors.As(err, &phaseError) {
		return newError(phaseError.Code, operation, phaseError.Reason, phaseError.Retryable, nil)
	}
	return newError(Unavailable, operation, "dependency_unavailable", true, nil)
}
