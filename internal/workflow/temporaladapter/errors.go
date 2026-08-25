package temporaladapter

import (
	"context"
	"errors"

	"go.temporal.io/api/serviceerror"

	core "github.com/ArronJablonowski/COH/internal/workflow"
)

func engineError(code core.EngineErrorCode, operation, field, detail string) error {
	return core.NewEngineError(code, operation, field, detail, nil)
}

func normalizeError(operation, field string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return core.NewEngineError(core.EngineCanceled, operation, field, "operation canceled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return core.NewEngineError(core.EngineTimeout, operation, field, "operation timed out", err)
	}
	var invalid *serviceerror.InvalidArgument
	if errors.As(err, &invalid) {
		return engineError(core.EngineInvalidInput, operation, field, "Temporal rejected the request")
	}
	var missing *serviceerror.NotFound
	if errors.As(err, &missing) {
		return engineError(core.EngineNotFound, operation, field, "workflow execution was not found")
	}
	return engineError(core.EngineUnavailable, operation, field, "Temporal operation failed")
}
