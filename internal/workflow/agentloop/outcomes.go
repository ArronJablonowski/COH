package agentloop

import (
	"context"
	"errors"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
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

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && validateOpaque(value.MediaType, 256) &&
		tokenPattern.MatchString(value.Classification) && value.Length >= 0
}

func validReceipt(value domain.ActionReceipt, intentDigest string) bool {
	if value.IntentDigest != intentDigest || !validArtifact(value.Evidence) {
		return false
	}
	switch value.Outcome {
	case "succeeded", "denied", "canceled", "timeout", "failed", "uncertain":
		return true
	default:
		return false
	}
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
