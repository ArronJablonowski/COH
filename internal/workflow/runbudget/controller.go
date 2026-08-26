package runbudget

import (
	"context"
	"slices"
	"time"
)

type Controller struct {
	store Store
	clock Clock
}

func New(store Store, clock Clock) (*Controller, error) {
	if store == nil || clock == nil {
		return nil, newError(InvalidInput, "budget_dependencies", false, nil)
	}
	return &Controller{store: store, clock: clock}, nil
}

func (controller *Controller) Reserve(ctx context.Context, request ReservationRequest) (Reservation, error) {
	if controller == nil || controller.store == nil || controller.clock == nil {
		return Reservation{}, newError(Unavailable, "budget_unavailable", true, nil)
	}
	if err := validateContext(ctx); err != nil {
		return Reservation{}, err
	}
	now := controller.clock.Now().UTC()
	if !validTime(now) {
		return Reservation{}, newError(Internal, "budget_clock_unavailable", false, nil)
	}
	if err := validateReservationRequest(request, now); err != nil {
		return Reservation{}, err
	}
	current, found, err := controller.store.Load(ctx, request.Case, request.RunID)
	if err != nil {
		return Reservation{}, mapStoreError(ctx, "budget_store_load", err)
	}
	if !found {
		if request.Plan == nil {
			return Reservation{}, newError(Denied, "budget_plan_required", false, nil)
		}
		candidate, reservation, buildErr := newLedgerWithReservation(request, now)
		if buildErr != nil {
			return Reservation{}, buildErr
		}
		stored, replayed, beginErr := controller.store.Begin(ctx, request.IdempotencyKey+":budget", candidate)
		if beginErr != nil {
			return Reservation{}, mapStoreError(ctx, "budget_store_begin", beginErr)
		}
		if !replayed {
			if err := validateLedger(stored); err != nil || stored.ProvenanceDigest != candidate.ProvenanceDigest {
				return Reservation{}, newError(Denied, "budget_store_result_invalid", false, nil)
			}
			reservation.LedgerDigest = stored.ProvenanceDigest
			return reservation, nil
		}
		current, found = stored, true
	}
	if !found {
		return Reservation{}, newError(Unavailable, "budget_store_missing", true, nil)
	}
	return controller.reserveExisting(ctx, request, current, now)
}

func (controller *Controller) reserveExisting(ctx context.Context, request ReservationRequest, current Ledger,
	now time.Time) (Reservation, error) {
	if err := validateLedger(current); err != nil {
		return Reservation{}, err
	}
	if current.RunID != request.RunID || current.Case != request.Case || current.PolicyDigest != request.PolicyDigest ||
		current.ProviderRoute != request.ProviderRoute {
		return Reservation{}, newError(Denied, "budget_scope_binding", false, nil)
	}
	if request.Plan != nil {
		digest, err := planDigest(*request.Plan)
		if err != nil || digest != current.PlanDigest {
			return Reservation{}, newError(Denied, "budget_plan_replay_binding", false, nil)
		}
	}
	claim, idempotency, reservation, err := reservationDigests(request, current.PlanDigest)
	if err != nil {
		return Reservation{}, err
	}
	for _, record := range current.Reservations {
		if record.TaskID != request.TaskID {
			continue
		}
		if record.ClaimDigest != claim || record.IdempotencyDigest != idempotency ||
			record.ReservationDigest != reservation {
			return Reservation{}, newError(Denied, "budget_task_replay_binding", false, nil)
		}
		return Reservation{ReservationDigest: reservation, PlanDigest: current.PlanDigest,
			ClaimDigest: claim, LedgerDigest: current.ProvenanceDigest, Replayed: true}, nil
	}
	if !now.Before(current.ExpiresAt) || request.Deadline.After(current.ExpiresAt) {
		return Reservation{}, newError(Denied, "budget_elapsed_exhausted", false, nil)
	}
	if !vectorWithin(request.TaskLimits, current.Limits) {
		return Reservation{}, newError(Denied, "budget_task_limit_exceeds_run", false, nil)
	}
	if err := validateReservationHierarchy(current, request); err != nil {
		return Reservation{}, err
	}
	charged, ok := addCharged(current.Charged, request.Claim)
	if !ok || !vectorWithin(charged, current.Limits) {
		return Reservation{}, newError(Denied, exhaustedReason(current.Charged, request.Claim, current.Limits), false, nil)
	}
	active := uint64(current.ActiveConcurrency) + uint64(request.Claim.Concurrency)
	if active > uint64(current.Limits.Concurrency) {
		return Reservation{}, newError(Denied, "budget_concurrency_exhausted", false, nil)
	}
	next := cloneLedger(current)
	next.Charged = charged
	next.ActiveConcurrency = uint32(active)
	next.Reservations = append(next.Reservations, newReservationRecord(request, claim, idempotency, reservation, now))
	slices.SortFunc(next.Reservations, func(left, right ReservationRecord) int {
		if left.TaskID < right.TaskID {
			return -1
		}
		if left.TaskID > right.TaskID {
			return 1
		}
		return 0
	})
	if err := controller.stamp(&next, current, "reservation_charged", now); err != nil {
		return Reservation{}, err
	}
	if err := validateLedger(next); err != nil {
		return Reservation{}, err
	}
	stored, err := controller.store.Save(ctx, request.IdempotencyKey+":budget", current, next)
	if err != nil {
		return Reservation{}, mapStoreError(ctx, "budget_store_save", err)
	}
	if err := validateLedger(stored); err != nil || stored.ProvenanceDigest != next.ProvenanceDigest {
		return Reservation{}, newError(Denied, "budget_store_result_invalid", false, nil)
	}
	return Reservation{ReservationDigest: reservation, PlanDigest: current.PlanDigest,
		ClaimDigest: claim, LedgerDigest: stored.ProvenanceDigest}, nil
}

func (controller *Controller) Settle(ctx context.Context, request SettlementRequest) (Settlement, error) {
	if controller == nil || controller.store == nil || controller.clock == nil {
		return Settlement{}, newError(Unavailable, "budget_unavailable", true, nil)
	}
	if err := validateContext(ctx); err != nil {
		return Settlement{}, err
	}
	if err := validateSettlementRequest(request); err != nil {
		return Settlement{}, err
	}
	current, found, err := controller.store.Load(ctx, request.Case, request.RunID)
	if err != nil {
		return Settlement{}, mapStoreError(ctx, "budget_store_load", err)
	}
	if !found {
		return Settlement{}, newError(Denied, "budget_ledger_missing", false, nil)
	}
	if err := validateLedger(current); err != nil {
		return Settlement{}, err
	}
	index := slices.IndexFunc(current.Reservations, func(value ReservationRecord) bool { return value.TaskID == request.TaskID })
	if index < 0 || current.Reservations[index].ReservationDigest != request.ReservationDigest {
		return Settlement{}, newError(Denied, "budget_settlement_binding", false, nil)
	}
	record := current.Reservations[index]
	actual := record.Claim
	if request.Actual != nil {
		actual = *request.Actual
	}
	if !validActualVector(actual) || !vectorWithin(actual, record.Claim) {
		return Settlement{}, newError(Denied, "budget_actual_exceeds_reservation", false, nil)
	}
	settlementIdempotency := budgetDigest("COH-RUN-BUDGET-SETTLEMENT-IDEMPOTENCY-V1\x00", []byte(request.IdempotencyKey))
	settlement, err := settlementDigest(record.ReservationDigest, settlementIdempotency, actual, request.Outcome)
	if err != nil {
		return Settlement{}, err
	}
	if record.Status == ReservationSettled {
		if record.SettlementDigest != settlement || record.SettlementIdempotencyDigest != settlementIdempotency {
			return Settlement{}, newError(Denied, "budget_settlement_replay_binding", false, nil)
		}
		return Settlement{ReservationDigest: record.ReservationDigest, SettlementDigest: settlement,
			LedgerDigest: current.ProvenanceDigest, Replayed: true}, nil
	}
	now := controller.clock.Now().UTC()
	if !validTime(now) {
		return Settlement{}, newError(Internal, "budget_clock_unavailable", false, nil)
	}
	next := cloneLedger(current)
	next.Reservations[index].Actual = actual
	next.Reservations[index].Outcome = request.Outcome
	next.Reservations[index].Status = ReservationSettled
	next.Reservations[index].SettlementDigest = settlement
	next.Reservations[index].SettlementIdempotencyDigest = settlementIdempotency
	next.Reservations[index].SettledAt = now
	if next.ActiveConcurrency < record.Claim.Concurrency {
		return Settlement{}, newError(Denied, "budget_concurrency_state_invalid", false, nil)
	}
	next.ActiveConcurrency -= record.Claim.Concurrency
	if err := controller.stamp(&next, current, "reservation_settled", now); err != nil {
		return Settlement{}, err
	}
	if err := validateLedger(next); err != nil {
		return Settlement{}, err
	}
	stored, err := controller.store.Save(ctx, request.IdempotencyKey+":budget", current, next)
	if err != nil {
		return Settlement{}, mapStoreError(ctx, "budget_store_save", err)
	}
	if err := validateLedger(stored); err != nil || stored.ProvenanceDigest != next.ProvenanceDigest {
		return Settlement{}, newError(Denied, "budget_store_result_invalid", false, nil)
	}
	return Settlement{ReservationDigest: record.ReservationDigest, SettlementDigest: settlement,
		LedgerDigest: stored.ProvenanceDigest}, nil
}

func newLedgerWithReservation(request ReservationRequest, now time.Time) (Ledger, Reservation, error) {
	plan, err := planDigest(*request.Plan)
	if err != nil {
		return Ledger{}, Reservation{}, err
	}
	if request.ParentTaskID != "" || request.Claim.DelegationDepth != 0 {
		return Ledger{}, Reservation{}, newError(Denied, "budget_root_hierarchy_invalid", false, nil)
	}
	claim, idempotency, reservation, err := reservationDigests(request, plan)
	if err != nil {
		return Ledger{}, Reservation{}, err
	}
	charged, ok := addCharged(Vector{}, request.Claim)
	if !ok || !vectorWithin(charged, request.Plan.Limits) || request.Claim.Concurrency > request.Plan.Limits.Concurrency {
		return Ledger{}, Reservation{}, newError(Denied, exhaustedReason(Vector{}, request.Claim, request.Plan.Limits), false, nil)
	}
	ledger := Ledger{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, RunID: request.RunID,
		Case: request.Case, PlanDigest: plan, PolicyDigest: request.PolicyDigest, ProviderRoute: request.ProviderRoute,
		Limits: request.Plan.Limits, Charged: charged, ActiveConcurrency: request.Claim.Concurrency,
		Reservations: []ReservationRecord{newReservationRecord(request, claim, idempotency, reservation, now)},
		ReasonCode:   "reservation_charged", CreatedAt: request.Plan.CreatedAt, ExpiresAt: request.Plan.ExpiresAt,
		UpdatedAt: now, Revision: 1}
	provenance, err := provenanceDigest("", ledger.ReasonCode, ledger)
	if err != nil {
		return Ledger{}, Reservation{}, err
	}
	ledger.ProvenanceDigest = provenance
	if err := validateLedger(ledger); err != nil {
		return Ledger{}, Reservation{}, err
	}
	return ledger, Reservation{ReservationDigest: reservation, PlanDigest: plan,
		ClaimDigest: claim, LedgerDigest: provenance}, nil
}

func validateReservationHierarchy(ledger Ledger, request ReservationRequest) error {
	if request.ParentTaskID == "" {
		if request.Claim.DelegationDepth != 0 {
			return newError(Denied, "budget_root_hierarchy_invalid", false, nil)
		}
		return nil
	}
	index := slices.IndexFunc(ledger.Reservations,
		func(value ReservationRecord) bool { return value.TaskID == request.ParentTaskID })
	if index < 0 {
		return newError(Denied, "budget_delegation_parent_missing", false, nil)
	}
	parent := ledger.Reservations[index]
	if parent.Claim.DelegationDepth == ^uint32(0) || request.Claim.DelegationDepth != parent.Claim.DelegationDepth+1 {
		return newError(Denied, "budget_delegation_depth_invalid", false, nil)
	}
	children := uint32(0)
	for _, record := range ledger.Reservations {
		if record.ParentTaskID == parent.TaskID {
			children++
		}
	}
	if children >= parent.Claim.Fanout {
		return newError(Denied, "budget_fanout_exhausted", false, nil)
	}
	return nil
}

func newReservationRecord(request ReservationRequest, claim, idempotency, reservation string,
	now time.Time) ReservationRecord {
	return ReservationRecord{ReservationDigest: reservation, ClaimDigest: claim, IdempotencyDigest: idempotency,
		TaskID: request.TaskID, ParentTaskID: request.ParentTaskID, Activity: request.Activity,
		PolicyDigest: request.PolicyDigest, ProviderRoute: request.ProviderRoute, Deadline: request.Deadline,
		TaskLimits: request.TaskLimits, Claim: request.Claim, Status: ReservationActive, CreatedAt: now}
}

func reservationDigests(request ReservationRequest, plan string) (string, string, string, error) {
	claim, err := claimDigest(request, plan)
	if err != nil {
		return "", "", "", err
	}
	idempotency := budgetDigest("COH-RUN-BUDGET-IDEMPOTENCY-V1\x00", []byte(request.IdempotencyKey))
	reservation := budgetDigest("COH-RUN-BUDGET-RESERVATION-V1\x00", []byte(plan+"\x00"+claim+"\x00"+idempotency))
	return claim, idempotency, reservation, nil
}

func (controller *Controller) stamp(next *Ledger, prior Ledger, operation string, now time.Time) error {
	if prior.Revision >= maximumUintBudget {
		return newError(Denied, "budget_revision_exhausted", false, nil)
	}
	next.PreviousProvenanceDigest = prior.ProvenanceDigest
	next.ReasonCode = operation
	next.UpdatedAt = now
	next.Revision = prior.Revision + 1
	provenance, err := provenanceDigest(prior.ProvenanceDigest, operation, *next)
	if err != nil {
		return err
	}
	next.ProvenanceDigest = provenance
	return nil
}

func exhaustedReason(charged, claim, limit Vector) string {
	checks := []struct {
		name           string
		used, add, max uint64
	}{
		{"budget_tokens_exhausted", charged.Tokens, claim.Tokens, limit.Tokens},
		{"budget_cost_exhausted", charged.CostMicros, claim.CostMicros, limit.CostMicros},
		{"budget_tool_calls_exhausted", charged.ToolCalls, claim.ToolCalls, limit.ToolCalls},
		{"budget_query_rows_exhausted", charged.QueryRows, claim.QueryRows, limit.QueryRows},
		{"budget_evidence_bytes_exhausted", charged.EvidenceBytes, claim.EvidenceBytes, limit.EvidenceBytes},
	}
	for _, check := range checks {
		if check.used > check.max || check.add > check.max-check.used {
			return check.name
		}
	}
	return "budget_limit_exhausted"
}

func mapStoreError(ctx context.Context, reason string, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return mapContext(ctx.Err())
	}
	if ErrorCode(err) != Unavailable {
		return err
	}
	return newError(Unavailable, reason, true, nil)
}

var _ Authority = (*Controller)(nil)
