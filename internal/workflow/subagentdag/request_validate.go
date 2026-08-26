package subagentdag

import (
	"math"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

func validateCreateRequest(value CreateRequest, now time.Time) error {
	if !uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey) ||
		!uuidPattern.MatchString(value.GraphID) || !uuidPattern.MatchString(value.RunID) ||
		!uuidPattern.MatchString(value.RootTaskID) || !validCase(value.Case) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		!digestPattern.MatchString(value.PolicyDigest) || !tokenPattern.MatchString(value.ProviderRoute) ||
		validateLimits(value.Limits) != nil || !validDigestSet(value.InputRefs, true) ||
		!validTime(value.Deadline) || !value.Deadline.After(now) ||
		value.BudgetPlan.SchemaVersion != runbudget.SchemaVersion || value.BudgetPlan.ContractVersion != runbudget.ContractVersion ||
		value.BudgetPlan.RunID != value.RunID || value.BudgetPlan.Case != value.Case ||
		value.BudgetPlan.PolicyDigest != value.PolicyDigest || value.BudgetPlan.ProviderRoute != value.ProviderRoute ||
		value.BudgetPlan.CreatedAt.After(now) || value.BudgetPlan.ExpiresAt.Before(value.Deadline) ||
		value.Limits.MaximumDepth > value.BudgetPlan.Limits.DelegationDepth ||
		value.Limits.MaximumFanout > value.BudgetPlan.Limits.Fanout ||
		value.Limits.MaximumConcurrency > value.BudgetPlan.Limits.Concurrency {
		return newError(InvalidInput, "create_request_invalid", false, nil)
	}
	if _, err := runbudget.CanonicalPlan(value.BudgetPlan); err != nil {
		return newError(InvalidInput, "budget_plan_invalid", false, err)
	}
	return nil
}

func validateDelegateRequest(value DelegateRequest, now time.Time) error {
	if !uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey) ||
		!uuidPattern.MatchString(value.GraphID) || !uuidPattern.MatchString(value.TaskID) ||
		len(value.ParentTaskIDs) == 0 || len(value.ParentTaskIDs) > MaximumParents ||
		!validUUIDSet(value.ParentTaskIDs) || !validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) ||
		value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 || !validRole(value.Role) ||
		value.Role == CoordinatorRole || !validDigestSet(value.InputRefs, true) ||
		!digestPattern.MatchString(value.PolicyDigest) || !validTime(value.Deadline) || !value.Deadline.After(now) {
		return newError(InvalidInput, "delegate_request_invalid", false, nil)
	}
	return nil
}

func validateExecuteRequest(value ExecuteRequest) error {
	if !uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey) ||
		!uuidPattern.MatchString(value.GraphID) || !uuidPattern.MatchString(value.TaskID) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 ||
		value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.PolicyDigest) {
		return newError(InvalidInput, "execute_request_invalid", false, nil)
	}
	return nil
}

func validateCancelRequest(value CancelRequest) error {
	if !uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey) ||
		!uuidPattern.MatchString(value.GraphID) || !uuidPattern.MatchString(value.TaskID) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 ||
		value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.PolicyDigest) ||
		!digestPattern.MatchString(value.ReasonDigest) {
		return newError(InvalidInput, "cancel_request_invalid", false, nil)
	}
	return nil
}

func validateRecoverRequest(value RecoverRequest) error {
	if !uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey) ||
		!uuidPattern.MatchString(value.GraphID) || !uuidPattern.MatchString(value.TaskID) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 ||
		value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.PolicyDigest) {
		return newError(InvalidInput, "recover_request_invalid", false, nil)
	}
	return nil
}
