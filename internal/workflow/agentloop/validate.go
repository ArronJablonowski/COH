package agentloop

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const maximumReferences = 128

var (
	uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

func validateContext(ctx context.Context, operation string) error {
	if ctx == nil {
		return newError(InvalidInput, operation, "context_required", false, nil)
	}
	if err := ctx.Err(); err != nil {
		return contextError(operation, err)
	}
	return nil
}

func contextError(operation string, err error) error {
	if err == context.DeadlineExceeded {
		return newError(Timeout, operation, "context_deadline", false, err)
	}
	return newError(Canceled, operation, "context_canceled", false, err)
}

func validateCase(value domain.CaseRef) bool {
	return uuidV7Pattern.MatchString(value.OrganizationID) && uuidV7Pattern.MatchString(value.TenantID) && uuidV7Pattern.MatchString(value.CaseID)
}

func validateOpaque(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func validateReferences(values []string) bool {
	if len(values) > maximumReferences || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validateActivity(kind ActivityKind, intentDigest string) bool {
	switch kind {
	case PlanningActivity:
		return intentDigest == ""
	case AuthorizedActionActivity:
		return digestPattern.MatchString(intentDigest)
	default:
		return false
	}
}

func validateStart(request StartRequest, now time.Time) error {
	if request.IdempotencyKey == "" || !validateOpaque(request.IdempotencyKey, 256) || !uuidV7Pattern.MatchString(request.RunID) || !uuidV7Pattern.MatchString(request.StepID) || !validateCase(request.Case) || !uuidV7Pattern.MatchString(request.ActorID) || !digestPattern.MatchString(request.PolicyDigest) || !tokenPattern.MatchString(request.ProviderRoute) || !validateActivity(request.Activity, request.IntentDigest) || !validateReferences(request.InputRefs) || request.Deadline.Location() != time.UTC || !now.Before(request.Deadline) {
		return newError(InvalidInput, "start", "start_request_invalid", false, nil)
	}
	return nil
}

func validateExecute(request ExecuteRequest) error {
	if !validateOpaque(request.IdempotencyKey, 256) || !validateCase(request.Case) || !uuidV7Pattern.MatchString(request.RunID) || !uuidV7Pattern.MatchString(request.StepID) {
		return newError(InvalidInput, "execute", "execute_request_invalid", false, nil)
	}
	return nil
}

func validateSchedule(request ScheduleRequest, now time.Time) error {
	if !validateOpaque(request.IdempotencyKey, 256) || !validateCase(request.Case) || !uuidV7Pattern.MatchString(request.RunID) || !uuidV7Pattern.MatchString(request.StepID) || !validateActivity(request.Activity, request.IntentDigest) || !validateReferences(request.InputRefs) || request.Deadline.Location() != time.UTC || !now.Before(request.Deadline) {
		return newError(InvalidInput, "schedule", "schedule_request_invalid", false, nil)
	}
	return nil
}

func validateTerminate(request TerminateRequest) error {
	if !validateOpaque(request.IdempotencyKey, 256) || !validateCase(request.Case) ||
		!uuidV7Pattern.MatchString(request.RunID) || !uuidV7Pattern.MatchString(request.StepID) ||
		!digestPattern.MatchString(request.ReasonDigest) {
		return newError(InvalidInput, "terminate", "terminate_request_invalid", false, nil)
	}
	switch request.Outcome {
	case TerminalFailed, TerminalDenied, TerminalCanceled, TerminalTimeout, TerminalUncertain:
		return nil
	default:
		return newError(InvalidInput, "terminate", "terminate_outcome_invalid", false, nil)
	}
}

func validateRun(value Run) error {
	if value.ContractVersion != ContractVersion || !uuidV7Pattern.MatchString(value.RunID) || !validateCase(value.Case) || !uuidV7Pattern.MatchString(value.ActorID) || value.WorkflowVersion != WorkflowVersion || !digestPattern.MatchString(value.PolicyDigest) || !tokenPattern.MatchString(value.ProviderRoute) || !uuidV7Pattern.MatchString(value.CurrentStepID) || value.Sequence == 0 || !validateReferences(value.InputRefs) || !validateReferences(value.OutputRefs) || !digestPattern.MatchString(value.ProvenanceDigest) || !validTimes(value.CreatedAt, value.UpdatedAt) || value.Revision == 0 {
		return newError(Denied, "state", "run_record_invalid", false, nil)
	}
	switch value.Status {
	case RunRunning, RunWaiting, RunSucceeded, RunFailed, RunDenied, RunCanceled, RunTimeout, RunUncertain:
		return nil
	default:
		return newError(Denied, "state", "run_status_invalid", false, nil)
	}
}

func validateStep(value Step) error {
	if value.ContractVersion != ContractVersion || !uuidV7Pattern.MatchString(value.StepID) || !uuidV7Pattern.MatchString(value.RunID) || !validateCase(value.Case) || !validateActivity(value.Kind, value.IntentDigest) || value.Attempt == 0 || value.Attempt > 1000 || value.Deadline.Location() != time.UTC || !validateReferences(value.InputRefs) || !validateReferences(value.OutputRefs) || !digestPattern.MatchString(value.ProvenanceDigest) || !validTimes(value.CreatedAt, value.UpdatedAt) || value.Revision == 0 {
		return newError(Denied, "state", "step_record_invalid", false, nil)
	}
	if value.ReceiptDigest != "" && !digestPattern.MatchString(value.ReceiptDigest) {
		return newError(Denied, "state", "step_receipt_invalid", false, nil)
	}
	switch value.Status {
	case StepPending, StepRunning, StepDispatching, StepSucceeded, StepFailed, StepDenied, StepCanceled, StepTimeout, StepUncertain:
		return nil
	default:
		return newError(Denied, "state", "step_status_invalid", false, nil)
	}
}

func validTimes(created, updated time.Time) bool {
	return !created.IsZero() && !updated.IsZero() && created.Location() == time.UTC && updated.Location() == time.UTC && !updated.Before(created)
}

func validateSnapshot(value Snapshot) error {
	if err := validateRun(value.Run); err != nil {
		return err
	}
	if err := validateStep(value.Step); err != nil {
		return err
	}
	if value.Run.Case != value.Step.Case || value.Run.RunID != value.Step.RunID || value.Run.CurrentStepID != value.Step.StepID || value.Run.UpdatedAt != value.Step.UpdatedAt || value.Run.ProvenanceDigest != value.Step.ProvenanceDigest || !validStatusBinding(value.Run.Status, value.Step.Status) {
		return newError(Denied, "state", "snapshot_binding_invalid", false, nil)
	}
	return nil
}

func validInitialSnapshot(value Snapshot) bool {
	return value.Run.Revision == 1 && value.Step.Revision == 1 && value.Run.Sequence == 1 &&
		value.Run.Status == RunRunning && value.Step.Status == StepPending && value.Step.Attempt == 1 &&
		value.Run.CreatedAt == value.Run.UpdatedAt && value.Step.CreatedAt == value.Step.UpdatedAt &&
		value.Run.CreatedAt == value.Step.CreatedAt && len(value.Run.OutputRefs) == 0 &&
		len(value.Step.OutputRefs) == 0 && value.Step.ReceiptDigest == ""
}

func validStatusBinding(run RunStatus, step StepStatus) bool {
	switch step {
	case StepPending, StepRunning, StepDispatching:
		return run == RunRunning
	case StepSucceeded:
		return run == RunWaiting || run == RunSucceeded
	case StepFailed:
		return run == RunFailed
	case StepDenied:
		return run == RunDenied
	case StepCanceled:
		return run == RunCanceled
	case StepTimeout:
		return run == RunTimeout
	case StepUncertain:
		return run == RunUncertain
	default:
		return false
	}
}

func validateTransition(prior, next Snapshot) error {
	if prior.Run.ContractVersion != next.Run.ContractVersion || prior.Run.Case != next.Run.Case ||
		prior.Run.RunID != next.Run.RunID || prior.Run.ActorID != next.Run.ActorID ||
		prior.Run.WorkflowVersion != next.Run.WorkflowVersion || prior.Run.PolicyDigest != next.Run.PolicyDigest ||
		prior.Run.ProviderRoute != next.Run.ProviderRoute || prior.Run.CreatedAt != next.Run.CreatedAt ||
		!slices.Equal(prior.Run.InputRefs, next.Run.InputRefs) || next.Run.UpdatedAt.Before(prior.Run.UpdatedAt) ||
		prior.Run.ProvenanceDigest == next.Run.ProvenanceDigest || !referenceSubset(prior.Run.OutputRefs, next.Run.OutputRefs) {
		return newError(Denied, "save", "run_transition_invalid", false, nil)
	}
	if prior.Step.StepID != next.Step.StepID {
		if prior.Run.Status != RunWaiting || prior.Step.Status != StepSucceeded || next.Run.Status != RunRunning ||
			next.Step.Status != StepPending || next.Step.Attempt != 1 || next.Step.ReceiptDigest != "" || len(next.Step.OutputRefs) != 0 ||
			next.Step.RunID != prior.Run.RunID || next.Step.Case != prior.Run.Case || next.Step.CreatedAt.Before(prior.Step.UpdatedAt) ||
			!slices.Equal(prior.Run.OutputRefs, next.Run.OutputRefs) {
			return newError(Denied, "save", "step_schedule_transition_invalid", false, nil)
		}
		return nil
	}
	if prior.Step.ContractVersion != next.Step.ContractVersion || prior.Step.RunID != next.Step.RunID ||
		prior.Step.Case != next.Step.Case || prior.Step.Kind != next.Step.Kind || prior.Step.Deadline != next.Step.Deadline ||
		prior.Step.IntentDigest != next.Step.IntentDigest || prior.Step.CreatedAt != next.Step.CreatedAt ||
		!slices.Equal(prior.Step.InputRefs, next.Step.InputRefs) || next.Step.UpdatedAt.Before(prior.Step.UpdatedAt) ||
		!referenceSubset(prior.Step.OutputRefs, next.Step.OutputRefs) || !legalStepTransition(prior.Step, next.Step) {
		return newError(Denied, "save", "step_transition_invalid", false, nil)
	}
	return nil
}

func legalStepTransition(prior, next Step) bool {
	if next.Attempt < prior.Attempt || next.Attempt > prior.Attempt+1 {
		return false
	}
	switch prior.Status {
	case StepPending:
		return next.Attempt == prior.Attempt && oneOfStep(next.Status, StepRunning, StepDispatching, StepFailed, StepDenied, StepCanceled, StepTimeout)
	case StepRunning:
		if next.Status == StepRunning {
			return next.Attempt == prior.Attempt+1
		}
		return next.Attempt == prior.Attempt && oneOfStep(next.Status, StepSucceeded, StepFailed, StepDenied, StepCanceled, StepTimeout)
	case StepDispatching:
		return next.Attempt == prior.Attempt && oneOfStep(next.Status, StepSucceeded, StepFailed, StepDenied, StepCanceled, StepTimeout, StepUncertain)
	case StepSucceeded:
		return next.Attempt == prior.Attempt && oneOfStep(next.Status, StepSucceeded, StepFailed, StepDenied, StepCanceled, StepTimeout)
	default:
		return false
	}
}

func oneOfStep(value StepStatus, choices ...StepStatus) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func referenceSubset(prior, next []string) bool {
	for _, value := range prior {
		index, found := slices.BinarySearch(next, value)
		if !found || index < 0 {
			return false
		}
	}
	return true
}

func terminalRun(status RunStatus) bool {
	return status == RunSucceeded || status == RunFailed || status == RunDenied || status == RunCanceled || status == RunTimeout || status == RunUncertain
}

func terminalStep(status StepStatus) bool {
	return status == StepSucceeded || status == StepFailed || status == StepDenied || status == StepCanceled || status == StepTimeout || status == StepUncertain
}
