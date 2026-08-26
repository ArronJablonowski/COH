package agentloop

import (
	"context"
	"errors"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/toolroute"
)

func planningFailure(ctx context.Context, err error) (StepStatus, RunStatus, error) {
	if ctx.Err() == context.Canceled {
		return StepCanceled, RunCanceled, contextError("activity", context.Canceled)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return StepTimeout, RunTimeout, contextError("activity", context.DeadlineExceeded)
	}
	var classified interface{ ActivityOutcome() string }
	if Code(err) == Denied || errors.As(err, &classified) &&
		(classified.ActivityOutcome() == "denied" || classified.ActivityOutcome() == "invalid_input") {
		return StepDenied, RunDenied, newError(Denied, "activity", "activity_output_denied", false, nil)
	}
	return StepFailed, RunFailed, newError(Unavailable, "activity", "planning_unavailable", true, nil)
}

func actionFailure(err error) (StepStatus, RunStatus, error, bool) {
	var classified interface {
		ActivityOutcome() string
		DispatchIndeterminate() bool
	}
	if !errors.As(err, &classified) || classified.DispatchIndeterminate() {
		return "", "", nil, false
	}
	switch classified.ActivityOutcome() {
	case "denied", "invalid_input":
		mapped := newError(Denied, "authorized_action", "broker_denied", false, nil)
		return StepDenied, RunDenied, mapped, true
	case "canceled":
		mapped := newError(Canceled, "authorized_action", "broker_canceled", false, err)
		return StepCanceled, RunCanceled, mapped, true
	case "timeout":
		mapped := newError(Timeout, "authorized_action", "broker_timeout", false, err)
		return StepTimeout, RunTimeout, mapped, true
	case "failed", "unavailable":
		mapped := newError(Unavailable, "authorized_action", "broker_unavailable", true, nil)
		return StepFailed, RunFailed, mapped, true
	default:
		return "", "", nil, false
	}
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && validateOpaque(value.MediaType, 256) &&
		tokenPattern.MatchString(value.Classification) && value.Length >= 0
}

func validReceipt(value domain.ActionReceipt, intentDigest string) bool {
	return toolroute.ValidateReceipt(value, intentDigest) == nil
}

func receiptStatuses(outcome string) (StepStatus, RunStatus) {
	switch outcome {
	case "succeeded":
		return StepSucceeded, RunWaiting
	case "denied":
		return StepDenied, RunDenied
	case "canceled":
		return StepCanceled, RunCanceled
	case "timeout":
		return StepTimeout, RunTimeout
	case "failed":
		return StepFailed, RunFailed
	default:
		return StepUncertain, RunUncertain
	}
}

func terminalStatuses(outcome TerminalOutcome) (StepStatus, RunStatus) {
	switch outcome {
	case TerminalFailed:
		return StepFailed, RunFailed
	case TerminalDenied:
		return StepDenied, RunDenied
	case TerminalCanceled:
		return StepCanceled, RunCanceled
	case TerminalTimeout:
		return StepTimeout, RunTimeout
	default:
		return StepUncertain, RunUncertain
	}
}

func sortedReferences(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

func mergeReferences(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range append(append([]string(nil), left...), right...) {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
