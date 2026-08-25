package temporaladapter

import (
	"github.com/ArronJablonowski/COH/internal/domain"

	core "github.com/ArronJablonowski/COH/internal/workflow"
)

type operationInput struct {
	OperationID string
	Case        domain.CaseRef
	Kind        string
	Version     string
	InputDigest string
	StartDigest string
}

type lifecycleSignal struct {
	IdempotencyDigest string
	RequestDigest     string
	Kind              string
	PayloadDigest     string
}

func inputFromStart(request core.WorkflowStart, startDigest string) operationInput {
	return operationInput{
		OperationID: request.Operation.ID,
		Case:        request.Operation.Case,
		Kind:        request.Operation.Kind,
		Version:     request.Operation.Version,
		InputDigest: request.InputDigest,
		StartDigest: startDigest,
	}
}
