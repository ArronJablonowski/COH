package workflow

import (
	"context"
	"strings"
)

func ValidateWorkflowStart(value WorkflowStart) error {
	if err := validateEngineContextlessContract("start", value.ContractVersion); err != nil {
		return err
	}
	if !validOpaque(value.IdempotencyKey, 1, 256) {
		return engineInvalid("start", "idempotency_key", "bounded UTF-8 key is required")
	}
	if err := validateCase("start", "operation.case", value.Operation.Case, false); err != nil {
		return engineInvalid("start", "operation.case", "organization, tenant, and case must be UUIDv7 identifiers")
	}
	if !uuidV7Pattern.MatchString(value.Operation.ID) || !tokenPattern.MatchString(value.Operation.Kind) || value.Operation.Version != OperationWorkflowV1 && value.Operation.Version != AgentLoopWorkflowV1 {
		return engineInvalid("start", "operation", "operation identity, kind, and registered version are required")
	}
	if value.Operation.Version == AgentLoopWorkflowV1 && value.Operation.Kind != "agent_loop" || value.Operation.Kind == "agent_loop" && value.Operation.Version != AgentLoopWorkflowV1 {
		return engineInvalid("start", "operation", "agent loop kind and workflow definition must be bound")
	}
	if !digestPattern.MatchString(value.InputDigest) {
		return engineInvalid("start", "input_digest", "expected a sha256 digest")
	}
	return nil
}

func registeredWorkflowDefinition(value string) bool {
	return value == OperationWorkflowV1 || value == AgentLoopWorkflowV1
}

func ValidateWorkflowSignal(value WorkflowSignal) error {
	if err := validateEngineContextlessContract("signal", value.ContractVersion); err != nil {
		return err
	}
	if err := validateWorkflowTarget("signal", value.Target); err != nil {
		return err
	}
	if !validOpaque(value.IdempotencyKey, 1, 256) ||
		(value.Kind != "advance" && value.Kind != "complete" && value.Kind != "emergency_stop") ||
		!digestPattern.MatchString(value.PayloadDigest) {
		return engineInvalid("signal", "signal", "idempotency key, registered kind, and payload digest are required")
	}
	return nil
}

func ValidateWorkflowQuery(value WorkflowQuery) error {
	if err := validateEngineContextlessContract("query", value.ContractVersion); err != nil {
		return err
	}
	if err := validateWorkflowTarget("query", value.Target); err != nil {
		return err
	}
	if value.Kind != "snapshot" {
		return engineInvalid("query", "kind", "query kind is not registered")
	}
	return nil
}

func ValidateWorkflowCancel(value WorkflowCancel) error {
	if err := validateEngineContextlessContract("cancel", value.ContractVersion); err != nil {
		return err
	}
	if err := validateWorkflowTarget("cancel", value.Target); err != nil {
		return err
	}
	if !validOpaque(value.IdempotencyKey, 1, 256) || !digestPattern.MatchString(value.ReasonDigest) {
		return engineInvalid("cancel", "cancel", "idempotency key and reason digest are required")
	}
	return nil
}

func ValidateWorkflowReplay(value WorkflowReplay) error {
	if err := validateEngineContextlessContract("replay", value.ContractVersion); err != nil {
		return err
	}
	if !tokenPattern.MatchString(value.FixtureID) {
		return engineInvalid("replay", "fixture_id", "registered fixture identifier is required")
	}
	return nil
}

func validateWorkflowTarget(operation string, target WorkflowTarget) error {
	if err := validateCase(operation, "target.case", target.Case, false); err != nil {
		return engineInvalid(operation, "target.case", "organization, tenant, and case must be UUIDv7 identifiers")
	}
	if !uuidV7Pattern.MatchString(target.WorkflowID) || !validOpaque(target.RunID, 1, 128) || strings.ContainsAny(target.RunID, "\r\n\t") {
		return engineInvalid(operation, "target", "workflow and run identifiers are invalid")
	}
	return nil
}

func validateEngineContext(ctx context.Context, operation string) error {
	if ctx == nil {
		return engineInvalid(operation, "context", "context is required")
	}
	if errors := ctx.Err(); errors != nil {
		if errors == context.DeadlineExceeded {
			return NewEngineError(EngineTimeout, operation, "context", "operation timed out", errors)
		}
		return NewEngineError(EngineCanceled, operation, "context", "operation canceled", errors)
	}
	return nil
}

func validateEngineContextlessContract(operation, version string) error {
	if version != WorkflowContractVersion {
		return engineInvalid(operation, "contract_version", "unsupported workflow contract")
	}
	return nil
}

func engineInvalid(operation, field, detail string) error {
	return NewEngineError(EngineInvalidInput, operation, field, detail, nil)
}
