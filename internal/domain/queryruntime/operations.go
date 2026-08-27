package queryruntime

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (controller *Controller) Poll(ctx context.Context, reference SessionRef) (Result, error) {
	return controller.run(ctx, reference, "poll", func(callContext context.Context,
		managed *managedSession) (queryconnector.ValidatedPoll, queryconnector.ValidatedPage, bool, error) {
		value, err := controller.adapter.Poll(callContext, queryconnector.PollRequest{QueryID: managed.value.QueryID,
			AttemptID: managed.value.AttemptID, Handle: managed.jobHandle, Authority: managed.authority})
		return value, queryconnector.ValidatedPage{}, false, adapterError(err)
	})
}

func (controller *Controller) NextPage(ctx context.Context, reference SessionRef) (Result, error) {
	return controller.run(ctx, reference, "next_page", func(callContext context.Context,
		managed *managedSession) (queryconnector.ValidatedPoll, queryconnector.ValidatedPage, bool, error) {
		value, err := controller.adapter.NextPage(callContext, queryconnector.PageRequest{QueryID: managed.value.QueryID,
			AttemptID: managed.value.AttemptID, Handle: *managed.pageHandle, Authority: managed.authority,
			Limits: managed.value.EffectiveLimits})
		return queryconnector.ValidatedPoll{}, value, true, adapterError(err)
	})
}

type adapterCall func(context.Context, *managedSession) (queryconnector.ValidatedPoll, queryconnector.ValidatedPage, bool, error)

func (controller *Controller) run(ctx context.Context, reference SessionRef, operation string, call adapterCall) (Result, error) {
	if controller == nil {
		return Result{}, newError(InvalidInput, "controller_required", nil)
	}
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	managed, err := controller.lookup(reference.SessionID)
	if err != nil {
		return Result{}, err
	}
	managed.mu.Lock()
	defer managed.mu.Unlock()
	if reference.SessionDigest != managed.value.SessionDigest {
		if managed.lastOperation == operation && managed.lastInputDigest == reference.SessionDigest {
			return managed.lastResult, managed.lastErr
		}
		return Result{}, newError(Conflict, "session_revision_mismatch", nil)
	}
	if err := VerifySession(managed.value); err != nil {
		return Result{}, err
	}
	if !active(managed.value.Status) || operation == "next_page" && managed.value.Status != "running" {
		return Result{}, newError(Denied, "session_terminal", nil)
	}
	now := controller.clock.Now().UTC()
	deadline, _ := time.Parse(timestampLayout, managed.value.Deadline)
	if !now.Before(deadline) {
		return controller.truncate(ctx, managed, reference.SessionDigest, operation, "query_deadline_elapsed", now, nil)
	}
	if controller.elapsedExceeded(managed.value, now) {
		return controller.truncate(ctx, managed, reference.SessionDigest, operation, "duration_limit_reached", now, nil)
	}
	if operation == "poll" && !handleCurrent(managed.jobHandle, now) {
		return controller.markUncertain(ctx, managed, reference.SessionDigest, operation, "job_handle_expired", now)
	}
	if operation == "next_page" && (managed.pageHandle == nil || !handleCurrent(*managed.pageHandle, now)) {
		return controller.markUncertain(ctx, managed, reference.SessionDigest, operation, "page_handle_expired", now)
	}
	reservation, err := controller.reserveRate(ctx, managed, operation, now)
	if err != nil {
		return Result{}, err
	}
	poll, page, directPage, err := call(ctx, managed)
	if err != nil {
		return Result{}, err
	}
	if directPage {
		return controller.acceptPage(ctx, managed, reference.SessionDigest, operation, page,
			reservation.ReservationDigest, now)
	}
	return controller.acceptPoll(ctx, managed, reference.SessionDigest, operation, poll,
		reservation.ReservationDigest, now)
}

func (controller *Controller) acceptPoll(ctx context.Context, managed *managedSession, inputDigest, operation string,
	poll queryconnector.ValidatedPoll, rateDigest string, now time.Time) (Result, error) {
	if poll.Digest() == "" {
		return Result{}, newError(InvalidInput, "poll_record_required", nil)
	}
	value := poll.Value()
	if value.QueryID != managed.value.QueryID || value.AttemptID != managed.value.AttemptID {
		return Result{}, newError(Conflict, "poll_mismatch", nil)
	}
	usage := usageFrom(value.Statistics)
	if !monotonic(managed.value.Usage, usage) {
		return Result{}, newError(Conflict, "statistics_regressed", nil)
	}
	if reason := budgetReason(usage, managed.value.EffectiveLimits); reason != "" {
		return controller.truncate(ctx, managed, inputDigest, operation, reason, now, &rateDigest)
	}
	if value.Page != nil {
		if !reflect.DeepEqual(value.Page.Statistics, value.Statistics) {
			return Result{}, newError(Conflict, "poll_page_statistics_mismatch", nil)
		}
		encoded, _ := json.Marshal(value.Page)
		page, err := queryconnector.DecodePage(ctx, encoded)
		if err != nil {
			return Result{}, adapterError(err)
		}
		return controller.acceptPageWithUsage(ctx, managed, inputDigest, operation, page, usage,
			rateDigest, now)
	}
	status, reason := pollOutcome(value, managed.partial)
	input := transitionInput{usage: usage, status: status, reason: reason, rateDigest: rateDigest,
		provenance: value.ProvenanceDigest, nextPageNumber: managed.value.NextPageNumber}
	session, err := controller.commit(ctx, managed, input, now)
	if err != nil {
		return Result{}, err
	}
	result := Result{Session: session}
	managed.cacheOperation(operation, inputDigest, result, nil)
	return result, nil
}

func (controller *Controller) acceptPage(ctx context.Context, managed *managedSession, inputDigest, operation string,
	page queryconnector.ValidatedPage, rateDigest string, now time.Time) (Result, error) {
	if page.Digest() == "" {
		return Result{}, newError(InvalidInput, "page_record_required", nil)
	}
	return controller.acceptPageWithUsage(ctx, managed, inputDigest, operation, page,
		usageFrom(page.Value().Statistics), rateDigest, now)
}

func (controller *Controller) acceptPageWithUsage(ctx context.Context, managed *managedSession, inputDigest,
	operation string, page queryconnector.ValidatedPage, usage Usage, rateDigest string, now time.Time) (Result, error) {
	value := page.Value()
	if value.QueryID != managed.value.QueryID || value.AttemptID != managed.value.AttemptID ||
		value.PageNumber != managed.value.NextPageNumber {
		return Result{}, newError(Conflict, "page_sequence_mismatch", nil)
	}
	if !monotonic(managed.value.Usage, usage) {
		return Result{}, newError(Conflict, "statistics_regressed", nil)
	}
	if reason := budgetReason(usage, managed.value.EffectiveLimits); reason != "" {
		return controller.truncate(ctx, managed, inputDigest, operation, reason, now, &rateDigest)
	}
	status, reason, release := pageOutcome(value.Completeness, value.NextPage != nil, managed.partial)
	if value.Completeness.Partial {
		managed.partial = true
	}
	if value.NextPage != nil && budgetExhausted(usage, managed.value.EffectiveLimits) {
		status, reason = "truncated", "budget_exhausted"
	}
	input := transitionInput{usage: usage, status: status, reason: reason, pageHandle: value.NextPage,
		pageDigest: page.Digest(), rateDigest: rateDigest, provenance: value.ProvenanceDigest,
		nextPageNumber: value.PageNumber + 1}
	if status == "truncated" {
		controller.protectiveCancel(ctx, managed, now, &input)
		input.pageHandle = nil
	}
	session, err := controller.commit(ctx, managed, input, now)
	if err != nil {
		return Result{}, err
	}
	result := Result{Session: session, Page: page, HasPage: release}
	managed.cacheOperation(operation, inputDigest, result, nil)
	return result, nil
}

func pollOutcome(value queryconnector.PollResult, partial bool) (string, string) {
	if value.Completeness.Status == "unknown" {
		return "uncertain", firstReason(value.Completeness.ReasonCodes, "vendor_unconfirmed")
	}
	if value.Completeness.Truncated {
		return "truncated", firstReason(value.Completeness.ReasonCodes, "vendor_truncated")
	}
	if value.Completeness.Partial || value.Outcome == "partial" || partial {
		return "partial", firstReason(value.Completeness.ReasonCodes, "vendor_partial")
	}
	switch value.Outcome {
	case "running":
		return "running", "vendor_running"
	case "completed":
		return "complete", "vendor_complete"
	case "canceled":
		return "canceled", "vendor_canceled"
	default:
		return "failed", "vendor_failed"
	}
}

func pageOutcome(value queryconnector.Completeness, hasNext, partial bool) (string, string, bool) {
	if value.Status == "unknown" {
		return "uncertain", firstReason(value.ReasonCodes, "vendor_unconfirmed"), false
	}
	if value.Truncated {
		return "truncated", firstReason(value.ReasonCodes, "vendor_truncated"), true
	}
	if value.Partial {
		if hasNext {
			return "running", firstReason(value.ReasonCodes, "vendor_partial"), true
		}
		return "partial", firstReason(value.ReasonCodes, "vendor_partial"), true
	}
	if hasNext {
		return "running", "page_available", true
	}
	if partial {
		return "partial", "vendor_partial", true
	}
	return "complete", "vendor_complete", true
}

func (managed *managedSession) cacheOperation(operation, inputDigest string, result Result, err error) {
	managed.lastOperation, managed.lastInputDigest = operation, inputDigest
	managed.lastResult, managed.lastErr = result, err
}
