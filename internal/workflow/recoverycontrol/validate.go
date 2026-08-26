package recoverycontrol

import (
	"context"
	"math"
	"reflect"
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

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", false, false, nil)
	}
	if err := ctx.Err(); err != nil {
		return mapContext(err)
	}
	return nil
}

func validateRecoverRequest(value RecoverRequest, now time.Time) error {
	if !validOpaque(value.IdempotencyKey, 256) || !validCommon(value.ControlID, value.Case, value.RunID,
		value.TaskID, value.PolicyDigest, value.CreatedAt, value.Deadline, now) ||
		!digestPattern.MatchString(value.ExpectedProvenanceDigest) ||
		value.IntentDigest != "" && !digestPattern.MatchString(value.IntentDigest) {
		return newError(InvalidInput, "recovery_request_invalid", false, false, nil)
	}
	return nil
}

func validateCancelRequest(value CancelRequest, now time.Time) error {
	if !validOpaque(value.IdempotencyKey, 256) || !validCommon(value.ControlID, value.Case, value.RunID,
		value.TaskID, value.PolicyDigest, value.CreatedAt, value.Deadline, now) ||
		!digestPattern.MatchString(value.ExpectedProvenanceDigest) || !digestPattern.MatchString(value.ReasonDigest) ||
		!validTargets(value.Targets) {
		return newError(InvalidInput, "cancellation_request_invalid", false, false, nil)
	}
	return nil
}

func validateInvokeRequest(value InvokeRequest, now time.Time) error {
	if !validOpaque(value.IdempotencyKey, 256) || !validCommon(value.ControlID, value.Case, value.RunID,
		value.TaskID, value.PolicyDigest, value.CreatedAt, value.Deadline, now) ||
		!tokenPattern.MatchString(value.RequestedRoute) || !validOperation(value.Operation, value.Case, value.TaskID) ||
		!validReferences(value.InputRefs, MaximumInputs) || !digestPattern.MatchString(value.BudgetReservationDigest) {
		return newError(InvalidInput, "fallback_request_invalid", false, false, nil)
	}
	return nil
}

func validCommon(controlID string, scope domain.CaseRef, runID, taskID, policy string,
	created, deadline, now time.Time) bool {
	return uuidPattern.MatchString(controlID) && validCase(scope) && uuidPattern.MatchString(runID) &&
		uuidPattern.MatchString(taskID) && digestPattern.MatchString(policy) && validTime(created) &&
		validTime(deadline) && deadline.After(created) && !created.After(now)
}

func validOperation(value domain.Operation, scope domain.CaseRef, taskID string) bool {
	return value.ID == taskID && value.Case == scope && tokenPattern.MatchString(value.Kind) &&
		validOpaque(value.Version, 128)
}

func validTargets(values []CancelTarget) bool {
	if len(values) == 0 || len(values) > MaximumTargets {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if value.Sequence != uint32(index+1) || value.Kind != ChildTask && value.Kind != ToolJob ||
			!uuidPattern.MatchString(value.TargetID) || !digestPattern.MatchString(value.ExpectedProvenanceDigest) {
			return false
		}
		key := string(value.Kind) + ":" + value.TargetID
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func validAcknowledgments(values []CancellationAck, targets []CancelTarget) bool {
	if len(values) > len(targets) {
		return false
	}
	for index, value := range values {
		target := targets[index]
		if value.Sequence != target.Sequence || value.Kind != target.Kind || value.TargetID != target.TargetID ||
			value.Outcome != AckCanceled && value.Outcome != AckAlreadyTerminal && value.Outcome != AckUncertain ||
			!digestPattern.MatchString(value.EvidenceDigest) || !digestPattern.MatchString(value.ProvenanceDigest) {
			return false
		}
	}
	return true
}

func validateRecord(value Record) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion ||
		!validCommon(value.ControlID, value.Case, value.RunID, value.TaskID, value.PolicyDigest,
			value.CreatedAt, value.Deadline, value.CreatedAt) ||
		!digestPattern.MatchString(value.IntentDigest) || !digestPattern.MatchString(value.IdempotencyDigest) ||
		!digestPattern.MatchString(value.ProvenanceDigest) ||
		value.PreviousProvenanceDigest != "" && !digestPattern.MatchString(value.PreviousProvenanceDigest) ||
		!validTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) || value.Revision == 0 ||
		value.Revision > math.MaxInt64 || !tokenPattern.MatchString(value.ReasonCode) {
		return newError(DeniedCode, "control_record_invalid", false, false, nil)
	}
	if value.Revision == 1 && value.PreviousProvenanceDigest != "" ||
		value.Revision > 1 && !digestPattern.MatchString(value.PreviousProvenanceDigest) {
		return newError(DeniedCode, "control_revision_invalid", false, false, nil)
	}
	intent, err := recordIntentDigest(value)
	if err != nil || intent != value.IntentDigest || !validVariant(value) {
		return newError(DeniedCode, "control_record_invalid", false, false, nil)
	}
	expected, err := provenanceDigest(value.PreviousProvenanceDigest, value.ReasonCode, value)
	if err != nil || expected != value.ProvenanceDigest {
		return newError(DeniedCode, "control_provenance_invalid", false, false, nil)
	}
	return nil
}

func validVariant(value Record) bool {
	switch value.Kind {
	case RecoveryKind:
		return validRecoveryRecord(value)
	case CancellationKind:
		return validCancellationRecord(value)
	case FallbackKind:
		return validFallbackRecord(value)
	default:
		return false
	}
}

func validRecoveryRecord(value Record) bool {
	if !digestPattern.MatchString(value.ExpectedProvenanceDigest) || value.ReasonDigest != "" ||
		!emptyOperation(value.Operation) || len(value.InputRefs) != 0 || value.BudgetReservationDigest != "" ||
		len(value.Targets) != 0 || len(value.Acknowledgments) != 0 || !emptyRoute(value.Route) ||
		len(value.Attempts) != 0 || !emptyArtifact(value.ResultArtifact) || !validWork(value.ObservedWork) {
		return false
	}
	if value.Status == RecoveryPrepared {
		return value.Revision == 1 && value.ReasonCode == "safe_resume_prepared" &&
			value.PreviousProvenanceDigest == "" && emptyWork(value.ResultWork)
	}
	if terminalControl(value.Status) {
		return value.Revision == 1 && value.ReasonCode == "terminal_preserved" &&
			value.PreviousProvenanceDigest == "" && value.ResultWork == value.ObservedWork ||
			value.Revision == 2 && digestPattern.MatchString(value.PreviousProvenanceDigest) &&
				validWork(value.ResultWork) && validRecoveryOutcome(value.ObservedWork, value.ResultWork, value.Status) &&
				value.ReasonCode == recoveryReason(value.Status)
	}
	return false
}

func validCancellationRecord(value Record) bool {
	if !digestPattern.MatchString(value.ExpectedProvenanceDigest) || !digestPattern.MatchString(value.ReasonDigest) ||
		!emptyOperation(value.Operation) || len(value.InputRefs) != 0 || value.BudgetReservationDigest != "" ||
		!emptyWork(value.ObservedWork) || !emptyWork(value.ResultWork) || !validTargets(value.Targets) ||
		!validAcknowledgments(value.Acknowledgments, value.Targets) || !emptyRoute(value.Route) ||
		len(value.Attempts) != 0 || !emptyArtifact(value.ResultArtifact) {
		return false
	}
	if value.Status == CancellationActive {
		return value.ReasonCode == "cancellation_propagating" && len(value.Acknowledgments) < len(value.Targets)
	}
	if value.Status != Completed && value.Status != Uncertain || len(value.Acknowledgments) != len(value.Targets) {
		return false
	}
	uncertain := slices.ContainsFunc(value.Acknowledgments, func(ack CancellationAck) bool {
		return ack.Outcome == AckUncertain
	})
	return value.Status == Uncertain && uncertain && value.ReasonCode == "cancellation_ack_uncertain" ||
		value.Status == Completed && !uncertain && value.ReasonCode == "cancellation_completed"
}

func validFallbackRecord(value Record) bool {
	if value.ExpectedProvenanceDigest != "" || value.ReasonDigest != "" ||
		!validOperation(value.Operation, value.Case, value.TaskID) ||
		!validReferences(value.InputRefs, MaximumInputs) || !digestPattern.MatchString(value.BudgetReservationDigest) ||
		!emptyWork(value.ObservedWork) || !emptyWork(value.ResultWork) || len(value.Targets) != 0 ||
		len(value.Acknowledgments) != 0 || !validRouteBinding(value.Route, value.PolicyDigest, value.CreatedAt) ||
		!validAttempts(value.Attempts, value.Route, value.ControlID) {
		return false
	}
	switch value.Status {
	case PrimaryAttempting:
		return value.Revision == 1 && len(value.Attempts) == 1 && value.Attempts[0].Status == PrimaryAttempting &&
			value.ReasonCode == "primary_attempting" && value.PreviousProvenanceDigest == "" &&
			emptyArtifact(value.ResultArtifact)
	case PrimaryUnavailable:
		return value.Revision == 2 && len(value.Attempts) == 1 && value.Attempts[0].Status == PrimaryUnavailable &&
			value.ReasonCode == "primary_unavailable" && emptyArtifact(value.ResultArtifact)
	case FallbackAttempting:
		return value.Revision == 3 && len(value.Attempts) == 2 &&
			value.Attempts[1].Status == FallbackAttempting && value.ReasonCode == "fallback_attempting" &&
			emptyArtifact(value.ResultArtifact)
	case Completed:
		return (value.Revision == 2 && len(value.Attempts) == 1 || value.Revision == 4 && len(value.Attempts) == 2) &&
			value.Attempts[len(value.Attempts)-1].Status == Completed && value.ReasonCode == "provider_succeeded" &&
			validArtifact(value.ResultArtifact) && value.Attempts[len(value.Attempts)-1].Artifact == value.ResultArtifact
	case Denied, Failed, Canceled, TimedOut, Uncertain:
		return value.Revision >= 2 && value.Revision <= 4 && value.ReasonCode == fallbackTerminalReason(value.Status) &&
			emptyArtifact(value.ResultArtifact)
	default:
		return false
	}
}

func validRecoveryOutcome(observed, result WorkSnapshot, status Status) bool {
	if observed.Case != result.Case || observed.RunID != result.RunID || observed.TaskID != result.TaskID ||
		observed.IntentDigest != result.IntentDigest {
		return false
	}
	if terminalWork(observed.Status) && result.Status != observed.Status {
		return false
	}
	if observed.SideEffect == ConfirmedSideEffect &&
		(result.SideEffect != ConfirmedSideEffect || result.ReceiptDigest != observed.ReceiptDigest) {
		return false
	}
	want := controlStatus(result.Status)
	return want == status
}

func validWork(value WorkSnapshot) bool {
	if !validCase(value.Case) || !uuidPattern.MatchString(value.RunID) || !uuidPattern.MatchString(value.TaskID) ||
		!validWorkStatus(value.Status) || !validSideEffect(value.SideEffect) ||
		value.IntentDigest != "" && !digestPattern.MatchString(value.IntentDigest) ||
		value.ReceiptDigest != "" && !digestPattern.MatchString(value.ReceiptDigest) ||
		!digestPattern.MatchString(value.ProvenanceDigest) ||
		value.TerminalEvidence != "" && !digestPattern.MatchString(value.TerminalEvidence) {
		return false
	}
	return value.SideEffect != ConfirmedSideEffect || digestPattern.MatchString(value.ReceiptDigest)
}

func validRouteBinding(value RouteBinding, policy string, now time.Time) bool {
	return uuidPattern.MatchString(value.DecisionID) && value.PolicyDigest == policy &&
		tokenPattern.MatchString(value.RequestedRoute) && tokenPattern.MatchString(value.PrimaryRoute) &&
		tokenPattern.MatchString(value.FallbackRoute) && value.PrimaryRoute != value.FallbackRoute &&
		digestPattern.MatchString(value.ApprovalDigest) && validCapability(value.Primary) &&
		validCapability(value.Fallback) && equivalentCapabilities(value.Primary, value.Fallback) == nil &&
		validTime(value.IssuedAt) && validTime(value.ExpiresAt) && value.ExpiresAt.After(value.IssuedAt) &&
		value.ExpiresAt.Sub(value.IssuedAt) <= 24*time.Hour && !now.Before(value.IssuedAt) && now.Before(value.ExpiresAt)
}

func validCapability(value CapabilityProfile) bool {
	return digestPattern.MatchString(value.CapabilityDigest) && digestPattern.MatchString(value.QualificationDigest) &&
		oneOf(value.DataRoute, "air_gapped", "local", "approved_external") &&
		oneOf(value.StateMode, "stateless", "client_managed", "provider_managed") &&
		validAllowedSet(value.MessageRoles, []string{"assistant", "developer", "system", "tool", "user"}) &&
		validAllowedSet(value.ContentKinds, []string{"input_json", "output_json", "reasoning_ref", "text", "tool_call", "tool_result"}) &&
		validAllowedSet(value.StateModes, []string{"client_managed", "provider_managed", "stateless"}) &&
		slices.Contains(value.StateModes, value.StateMode) && value.MaximumInputTokens > 0 &&
		value.MaximumInputTokens <= 16777216 && value.MaximumOutputTokens > 0 &&
		value.MaximumOutputTokens <= 1048576 && value.MaximumMessages > 0 && value.MaximumMessages <= 16384 &&
		value.MaximumTools <= 1024 && value.MaximumParallelToolCalls <= 256 &&
		value.MaximumStreamSeconds > 0 && value.MaximumStreamSeconds <= 86400 &&
		value.ContextLimit >= value.MaximumInputTokens+value.MaximumOutputTokens && value.ContextLimit <= 16777216 &&
		value.ToolCalls == (value.MaximumTools > 0 && value.MaximumParallelToolCalls > 0)
}

func validAttempts(values []ProviderAttempt, route RouteBinding, controlID string) bool {
	if len(values) == 0 || len(values) > 2 {
		return false
	}
	for index, value := range values {
		wantRoute, wantCapability := route.PrimaryRoute, route.Primary.CapabilityDigest
		if index == 1 {
			wantRoute, wantCapability = route.FallbackRoute, route.Fallback.CapabilityDigest
		}
		if value.Sequence != uint32(index+1) || value.AttemptID != attemptID(controlID, value.Sequence, wantRoute, wantCapability) ||
			value.Route != wantRoute || value.CapabilityDigest != wantCapability || !validAttemptOutcome(value) {
			return false
		}
	}
	return true
}

func validAttemptOutcome(value ProviderAttempt) bool {
	switch value.Status {
	case PrimaryAttempting, FallbackAttempting:
		return value.Outcome == "pending" && emptyArtifact(value.Artifact) && value.EvidenceDigest == ""
	case PrimaryUnavailable:
		return value.Outcome == "unavailable" && emptyArtifact(value.Artifact) &&
			digestPattern.MatchString(value.EvidenceDigest)
	case Completed:
		return value.Outcome == "succeeded" && validArtifact(value.Artifact) &&
			digestPattern.MatchString(value.EvidenceDigest)
	case Denied, Failed, Canceled, TimedOut, Uncertain:
		return value.Outcome == string(value.Status) && emptyArtifact(value.Artifact) &&
			digestPattern.MatchString(value.EvidenceDigest)
	default:
		return false
	}
}

func fallbackTerminalReason(status Status) string {
	switch status {
	case Denied:
		return "provider_denied"
	case Failed:
		return "provider_failed"
	case Canceled:
		return "provider_canceled"
	case TimedOut:
		return "provider_timeout"
	default:
		return "provider_outcome_uncertain"
	}
}

func terminalControl(value Status) bool {
	return value == Completed || value == Failed || value == Denied || value == Canceled ||
		value == TimedOut || value == Uncertain
}

func terminalWork(value WorkStatus) bool {
	return value == WorkSucceeded || value == WorkFailed || value == WorkDenied || value == WorkCanceled ||
		value == WorkTimeout || value == WorkUncertain
}

func controlStatus(value WorkStatus) Status {
	switch value {
	case WorkSucceeded, WorkWaiting:
		return Completed
	case WorkFailed:
		return Failed
	case WorkDenied:
		return Denied
	case WorkCanceled:
		return Canceled
	case WorkTimeout:
		return TimedOut
	default:
		return Uncertain
	}
}

func validWorkStatus(value WorkStatus) bool {
	return value == WorkPending || value == WorkRunning || value == WorkWaiting || terminalWork(value)
}

func validSideEffect(value SideEffectState) bool {
	return value == NoSideEffect || value == ConfirmedSideEffect || value == IndeterminateSideEffect
}

func validReferences(values []string, maximum int) bool {
	if len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validSortedTokens(values []string) bool {
	if len(values) == 0 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validAllowedSet(values, allowed []string) bool {
	if !validSortedTokens(values) {
		return false
	}
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && value.MediaType == "application/json" &&
		tokenPattern.MatchString(value.Classification) && value.Length > 0 && value.Length <= 1<<30
}

func emptyArtifact(value domain.ArtifactRef) bool { return value == (domain.ArtifactRef{}) }
func emptyWork(value WorkSnapshot) bool           { return value == (WorkSnapshot{}) }
func emptyOperation(value domain.Operation) bool  { return value == (domain.Operation{}) }

func emptyRoute(value RouteBinding) bool {
	value.Primary.MessageRoles, value.Primary.ContentKinds, value.Primary.StateModes = nil, nil, nil
	value.Fallback.MessageRoles, value.Fallback.ContentKinds, value.Fallback.StateModes = nil, nil, nil
	return reflect.DeepEqual(value, RouteBinding{})
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validOpaque(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
}

func validTime(value time.Time) bool             { return !value.IsZero() && value.Location() == time.UTC }
func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }
