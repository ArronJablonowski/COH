package runbudget

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

const maximumUintBudget = uint64(math.MaxInt64)

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", false, nil)
	}
	if err := ctx.Err(); err != nil {
		return mapContext(err)
	}
	return nil
}

func validatePlan(value Plan) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RunID) || !validCase(value.Case) ||
		!digestPattern.MatchString(value.PolicyDigest) || !tokenPattern.MatchString(value.ProviderRoute) ||
		!validLimitVector(value.Limits) || !validTime(value.CreatedAt) || !validTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.CreatedAt) {
		return newError(InvalidInput, "budget_plan_invalid", false, nil)
	}
	return nil
}

func validateReservationRequest(value ReservationRequest, now time.Time) error {
	if !validOpaque(value.IdempotencyKey, 256) || !uuidPattern.MatchString(value.RunID) ||
		!uuidPattern.MatchString(value.TaskID) || value.ParentTaskID != "" && !uuidPattern.MatchString(value.ParentTaskID) ||
		value.ParentTaskID == value.TaskID || !validCase(value.Case) || !tokenPattern.MatchString(value.Activity) ||
		!digestPattern.MatchString(value.PolicyDigest) || !tokenPattern.MatchString(value.ProviderRoute) ||
		!validTime(value.Deadline) || !value.Deadline.After(now) || !validLimitVector(value.TaskLimits) ||
		!validClaimVector(value.Claim) || !vectorWithin(value.Claim, value.TaskLimits) {
		return newError(InvalidInput, "budget_reservation_invalid", false, nil)
	}
	if value.Plan != nil {
		if err := validatePlan(*value.Plan); err != nil || value.Plan.RunID != value.RunID || value.Plan.Case != value.Case ||
			value.Plan.PolicyDigest != value.PolicyDigest || value.Plan.ProviderRoute != value.ProviderRoute ||
			value.Plan.CreatedAt.After(now) || !now.Before(value.Plan.ExpiresAt) || value.Deadline.After(value.Plan.ExpiresAt) ||
			!vectorWithin(value.TaskLimits, value.Plan.Limits) {
			return newError(InvalidInput, "budget_plan_binding_invalid", false, nil)
		}
	}
	remaining := value.Deadline.Sub(now)
	if remaining <= 0 || uint64(remaining) > value.Claim.WallTimeNanoseconds {
		return newError(Denied, "budget_deadline_exceeds_claim", false, nil)
	}
	return nil
}

func validateSettlementRequest(value SettlementRequest) error {
	if !validOpaque(value.IdempotencyKey, 256) || !uuidPattern.MatchString(value.RunID) ||
		!uuidPattern.MatchString(value.TaskID) || !validCase(value.Case) ||
		!digestPattern.MatchString(value.ReservationDigest) || !validOutcome(value.Outcome) ||
		value.Actual != nil && !validActualVector(*value.Actual) {
		return newError(InvalidInput, "budget_settlement_invalid", false, nil)
	}
	return nil
}

func validateLedger(value Ledger) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RunID) || !validCase(value.Case) ||
		!digestPattern.MatchString(value.PlanDigest) || !digestPattern.MatchString(value.PolicyDigest) ||
		!tokenPattern.MatchString(value.ProviderRoute) || !validLimitVector(value.Limits) ||
		!validChargedVector(value.Charged) || value.ActiveConcurrency > value.Limits.Concurrency ||
		len(value.Reservations) == 0 || len(value.Reservations) > MaximumRecords ||
		!tokenPattern.MatchString(value.ReasonCode) || !digestPattern.MatchString(value.ProvenanceDigest) ||
		value.PreviousProvenanceDigest != "" && !digestPattern.MatchString(value.PreviousProvenanceDigest) ||
		!validTime(value.CreatedAt) || !validTime(value.ExpiresAt) || !validTime(value.UpdatedAt) ||
		!value.ExpiresAt.After(value.CreatedAt) || value.UpdatedAt.Before(value.CreatedAt) ||
		value.Revision == 0 || value.Revision > maximumUintBudget {
		return newError(Denied, "budget_ledger_invalid", false, nil)
	}
	plan := Plan{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion, RunID: value.RunID,
		Case: value.Case, PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute,
		Limits: value.Limits, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt}
	boundPlan, err := planDigest(plan)
	if err != nil || boundPlan != value.PlanDigest {
		return newError(Denied, "budget_plan_digest_invalid", false, nil)
	}
	charged := Vector{}
	var active uint64
	seen := make(map[string]struct{}, len(value.Reservations))
	children := make(map[string]uint32, len(value.Reservations))
	for index := range value.Reservations {
		record := value.Reservations[index]
		if index > 0 && value.Reservations[index-1].TaskID >= record.TaskID {
			return newError(Denied, "budget_reservation_order_invalid", false, nil)
		}
		if err := validateReservationRecord(value, record); err != nil {
			return err
		}
		if _, duplicate := seen[record.TaskID]; duplicate {
			return newError(Denied, "budget_task_duplicate", false, nil)
		}
		seen[record.TaskID] = struct{}{}
		if record.ParentTaskID != "" {
			children[record.ParentTaskID]++
		}
		var ok bool
		charged, ok = addCharged(charged, record.Claim)
		if !ok {
			return newError(Denied, "budget_ledger_overflow", false, nil)
		}
		if record.Status == ReservationActive {
			active += uint64(record.Claim.Concurrency)
			if active > math.MaxUint32 {
				return newError(Denied, "budget_concurrency_overflow", false, nil)
			}
		}
	}
	for _, record := range value.Reservations {
		if record.ParentTaskID == "" {
			if record.Claim.DelegationDepth != 0 {
				return newError(Denied, "budget_root_hierarchy_invalid", false, nil)
			}
			continue
		}
		parentIndex := slices.IndexFunc(value.Reservations,
			func(candidate ReservationRecord) bool { return candidate.TaskID == record.ParentTaskID })
		if parentIndex < 0 || value.Reservations[parentIndex].Claim.DelegationDepth == ^uint32(0) ||
			record.Claim.DelegationDepth != value.Reservations[parentIndex].Claim.DelegationDepth+1 {
			return newError(Denied, "budget_delegation_hierarchy_invalid", false, nil)
		}
	}
	for parent, count := range children {
		index := slices.IndexFunc(value.Reservations,
			func(candidate ReservationRecord) bool { return candidate.TaskID == parent })
		if index < 0 || count > value.Reservations[index].Claim.Fanout {
			return newError(Denied, "budget_fanout_state_invalid", false, nil)
		}
	}
	if charged != value.Charged || uint32(active) != value.ActiveConcurrency || !vectorWithin(charged, value.Limits) {
		return newError(Denied, "budget_ledger_totals_invalid", false, nil)
	}
	expected, err := provenanceDigest(value.PreviousProvenanceDigest, value.ReasonCode, value)
	if err != nil || expected != value.ProvenanceDigest {
		return newError(Denied, "budget_provenance_invalid", false, nil)
	}
	return nil
}

func validateReservationRecord(ledger Ledger, value ReservationRecord) error {
	if !digestPattern.MatchString(value.ReservationDigest) || !digestPattern.MatchString(value.ClaimDigest) ||
		!digestPattern.MatchString(value.IdempotencyDigest) || !uuidPattern.MatchString(value.TaskID) ||
		value.ParentTaskID != "" && !uuidPattern.MatchString(value.ParentTaskID) || value.ParentTaskID == value.TaskID ||
		!tokenPattern.MatchString(value.Activity) || value.PolicyDigest != ledger.PolicyDigest ||
		value.ProviderRoute != ledger.ProviderRoute || !validTime(value.Deadline) || value.Deadline.After(ledger.ExpiresAt) ||
		!validLimitVector(value.TaskLimits) || !vectorWithin(value.TaskLimits, ledger.Limits) ||
		!validClaimVector(value.Claim) || !vectorWithin(value.Claim, value.TaskLimits) || !validTime(value.CreatedAt) ||
		value.CreatedAt.Before(ledger.CreatedAt) || !value.Deadline.After(value.CreatedAt) ||
		uint64(value.Deadline.Sub(value.CreatedAt)) > value.Claim.WallTimeNanoseconds {
		return newError(Denied, "budget_reservation_record_invalid", false, nil)
	}
	request := ReservationRequest{RunID: ledger.RunID, TaskID: value.TaskID, ParentTaskID: value.ParentTaskID,
		Case: ledger.Case, Activity: value.Activity, PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute,
		Deadline: value.Deadline, TaskLimits: value.TaskLimits, Claim: value.Claim}
	claim, err := claimDigest(request, ledger.PlanDigest)
	if err != nil || claim != value.ClaimDigest ||
		budgetDigest("COH-RUN-BUDGET-RESERVATION-V1\x00", []byte(ledger.PlanDigest+"\x00"+claim+"\x00"+value.IdempotencyDigest)) != value.ReservationDigest {
		return newError(Denied, "budget_reservation_binding_invalid", false, nil)
	}
	if value.Status == ReservationActive {
		if value.SettlementDigest != "" || value.SettlementIdempotencyDigest != "" || value.Outcome != "" ||
			value.Actual != (Vector{}) || !value.SettledAt.IsZero() {
			return newError(Denied, "budget_active_record_invalid", false, nil)
		}
		return nil
	}
	if value.Status != ReservationSettled || !digestPattern.MatchString(value.SettlementDigest) ||
		!digestPattern.MatchString(value.SettlementIdempotencyDigest) ||
		!validOutcome(value.Outcome) || !validActualVector(value.Actual) || !vectorWithin(value.Actual, value.Claim) ||
		!validTime(value.SettledAt) || value.SettledAt.Before(value.CreatedAt) {
		return newError(Denied, "budget_settled_record_invalid", false, nil)
	}
	settlement, err := settlementDigest(value.ReservationDigest, value.SettlementIdempotencyDigest,
		value.Actual, value.Outcome)
	if err != nil || settlement != value.SettlementDigest {
		return newError(Denied, "budget_settlement_binding_invalid", false, nil)
	}
	return nil
}

func validLimitVector(value Vector) bool {
	return value.Tokens > 0 && value.Tokens <= maximumUintBudget && value.CostMicros > 0 && value.CostMicros <= maximumUintBudget &&
		value.WallTimeNanoseconds > 0 && value.WallTimeNanoseconds <= maximumUintBudget &&
		value.ToolCalls > 0 && value.ToolCalls <= maximumUintBudget && value.QueryRows > 0 && value.QueryRows <= maximumUintBudget &&
		value.EvidenceBytes > 0 && value.EvidenceBytes <= maximumUintBudget && value.DelegationDepth > 0 &&
		value.Fanout > 0 && value.Concurrency > 0
}

func validClaimVector(value Vector) bool {
	return value.Tokens <= maximumUintBudget && value.CostMicros <= maximumUintBudget &&
		value.WallTimeNanoseconds > 0 && value.WallTimeNanoseconds <= maximumUintBudget &&
		value.ToolCalls <= maximumUintBudget && value.QueryRows <= maximumUintBudget &&
		value.EvidenceBytes <= maximumUintBudget && value.Concurrency > 0
}

func validActualVector(value Vector) bool {
	return value.Tokens <= maximumUintBudget && value.CostMicros <= maximumUintBudget &&
		value.WallTimeNanoseconds <= maximumUintBudget && value.ToolCalls <= maximumUintBudget &&
		value.QueryRows <= maximumUintBudget && value.EvidenceBytes <= maximumUintBudget
}

func validChargedVector(value Vector) bool {
	return value.Tokens <= maximumUintBudget && value.CostMicros <= maximumUintBudget && value.ToolCalls <= maximumUintBudget &&
		value.QueryRows <= maximumUintBudget && value.EvidenceBytes <= maximumUintBudget && value.WallTimeNanoseconds == 0 &&
		value.DelegationDepth == 0 && value.Fanout == 0 && value.Concurrency == 0
}

func vectorWithin(value, limit Vector) bool {
	return value.Tokens <= limit.Tokens && value.CostMicros <= limit.CostMicros &&
		value.WallTimeNanoseconds <= limit.WallTimeNanoseconds && value.ToolCalls <= limit.ToolCalls &&
		value.QueryRows <= limit.QueryRows && value.EvidenceBytes <= limit.EvidenceBytes &&
		value.DelegationDepth <= limit.DelegationDepth && value.Fanout <= limit.Fanout &&
		value.Concurrency <= limit.Concurrency
}

func addCharged(left, right Vector) (Vector, bool) {
	values := [5][2]uint64{{left.Tokens, right.Tokens}, {left.CostMicros, right.CostMicros},
		{left.ToolCalls, right.ToolCalls}, {left.QueryRows, right.QueryRows}, {left.EvidenceBytes, right.EvidenceBytes}}
	result := left
	outputs := []*uint64{&result.Tokens, &result.CostMicros, &result.ToolCalls, &result.QueryRows, &result.EvidenceBytes}
	for index, pair := range values {
		if pair[0] > maximumUintBudget-pair[1] {
			return Vector{}, false
		}
		*outputs[index] = pair[0] + pair[1]
	}
	result.WallTimeNanoseconds, result.DelegationDepth, result.Fanout, result.Concurrency = 0, 0, 0, 0
	return result, true
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validOpaque(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
}
func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func validOutcome(value string) bool {
	return value == "succeeded" || value == "denied" || value == "canceled" || value == "timeout" ||
		value == "failed" || value == "uncertain"
}

func mapContext(err error) error {
	if err == context.Canceled {
		return newError(Canceled, "budget_canceled", false, context.Canceled)
	}
	if err == context.DeadlineExceeded {
		return newError(Timeout, "budget_timeout", false, context.DeadlineExceeded)
	}
	return newError(Unavailable, "budget_dependency_unavailable", true, nil)
}
