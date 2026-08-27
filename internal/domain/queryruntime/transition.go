package queryruntime

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type transitionInput struct {
	usage          Usage
	status         string
	reason         string
	pageHandle     *queryconnector.HandleRef
	pageDigest     string
	rateDigest     string
	cancelDigest   string
	provenance     string
	nextPageNumber uint32
}

func (controller *Controller) commit(ctx context.Context, managed *managedSession, input transitionInput,
	now time.Time) (Session, error) {
	current := managed.value
	candidate := current
	candidate.SessionDigest = ""
	candidate.PreviousSessionDigest = current.SessionDigest
	candidate.Revision++
	candidate.Usage = input.usage
	candidate.Status = input.status
	candidate.ReasonCode = input.reason
	candidate.LastRateReservationDigest = input.rateDigest
	candidate.CancellationIntentDigest = input.cancelDigest
	candidate.VendorProvenanceDigest = input.provenance
	candidate.UpdatedAt = now.Format(timestampLayout)
	if input.nextPageNumber != 0 {
		candidate.NextPageNumber = input.nextPageNumber
	}
	candidate.LastPageDigest = input.pageDigest
	candidate.PageHandleDigest = ""
	if input.pageHandle != nil {
		handleDigest, err := canonicalDigest(handleDigestDomain, *input.pageHandle)
		if err != nil {
			return Session{}, err
		}
		candidate.PageHandleDigest = handleDigest
	}
	finalized, err := finalizeSession(candidate)
	if err != nil {
		return Session{}, err
	}
	if err := controller.record(ctx, finalized); err != nil {
		return Session{}, err
	}
	managed.value = finalized
	managed.pageHandle = cloneHandle(input.pageHandle)
	return finalized, nil
}

func usageFrom(value queryconnector.Statistics) Usage {
	return Usage{RowsScanned: value.RowsScanned, RowsReturned: value.RowsReturned,
		BytesReturned: value.BytesReturned, DurationMillis: value.DurationMillis,
		PagesReturned: value.PagesReturned, SlicesCompleted: value.SlicesCompleted,
		CostMillionths: value.CostMillionths}
}

func monotonic(previous, next Usage) bool {
	return next.RowsScanned >= previous.RowsScanned && next.RowsReturned >= previous.RowsReturned &&
		next.BytesReturned >= previous.BytesReturned && next.DurationMillis >= previous.DurationMillis &&
		next.PagesReturned >= previous.PagesReturned && next.SlicesCompleted >= previous.SlicesCompleted &&
		next.CostMillionths >= previous.CostMillionths
}

func budgetReason(usage Usage, limits queryconnector.Limits) string {
	switch {
	case usage.RowsReturned > limits.MaximumRows:
		return "row_limit_exceeded"
	case usage.BytesReturned > limits.MaximumBytes:
		return "byte_limit_exceeded"
	case usage.DurationMillis > limits.MaximumDurationMillis:
		return "duration_limit_exceeded"
	case usage.PagesReturned > limits.MaximumPages:
		return "page_limit_exceeded"
	case usage.SlicesCompleted > limits.MaximumSlices:
		return "slice_limit_exceeded"
	case usage.CostMillionths > limits.MaximumCostMillionths:
		return "cost_limit_exceeded"
	default:
		return ""
	}
}

func budgetExhausted(usage Usage, limits queryconnector.Limits) bool {
	return usage.RowsReturned == limits.MaximumRows || usage.BytesReturned == limits.MaximumBytes ||
		usage.DurationMillis == limits.MaximumDurationMillis || usage.PagesReturned == limits.MaximumPages ||
		usage.SlicesCompleted == limits.MaximumSlices || usage.CostMillionths == limits.MaximumCostMillionths
}

func (controller *Controller) elapsedExceeded(session Session, now time.Time) bool {
	started, err := time.Parse(timestampLayout, session.StartedAt)
	if err != nil || now.Before(started) {
		return true
	}
	return now.Sub(started) >= time.Duration(session.EffectiveLimits.MaximumDurationMillis)*time.Millisecond
}

func active(status string) bool { return status == "running" || status == "uncertain" }

func cloneHandle(value *queryconnector.HandleRef) *queryconnector.HandleRef {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func firstReason(reasons []string, fallback string) string {
	if len(reasons) > 0 {
		return reasons[0]
	}
	return fallback
}
