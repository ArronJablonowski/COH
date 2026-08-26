package agentphase

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
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
		if err == context.DeadlineExceeded {
			return newError(Timeout, operation, "context_deadline", false, err)
		}
		return newError(Canceled, operation, "context_canceled", false, err)
	}
	return nil
}

func validateCase(value domain.CaseRef) bool {
	return uuidV7Pattern.MatchString(value.OrganizationID) &&
		uuidV7Pattern.MatchString(value.TenantID) && uuidV7Pattern.MatchString(value.CaseID)
}

func validateOpaque(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func validateRetryPolicy(value RetryPolicy) bool {
	return value.MaximumPhaseAttempts >= 1 && value.MaximumPhaseAttempts <= 8 &&
		value.MaximumReviewCycles >= 1 && value.MaximumReviewCycles <= 8
}

func validateStart(request StartRequest) error {
	if !validateOpaque(request.IdempotencyKey, 256) || !uuidV7Pattern.MatchString(request.RunID) ||
		!uuidV7Pattern.MatchString(request.TraceID) || !validateCase(request.Case) ||
		!uuidV7Pattern.MatchString(request.ActorID) || !digestPattern.MatchString(request.PolicyDigest) ||
		!tokenPattern.MatchString(request.ProviderRoute) || !validateDigestSet(request.InputRefs, maximumReferences, false) ||
		!validateRetryPolicy(request.RetryPolicy) || request.Deadline.IsZero() || request.Deadline.Location() != time.UTC {
		return newError(InvalidInput, "start", "start_request_invalid", false, nil)
	}
	return nil
}

func validateSession(value Session) error {
	if !uuidV7Pattern.MatchString(value.TraceID) || !validPhase(value.Phase) || !validateRetryPolicy(value.RetryPolicy) ||
		value.Cycle == 0 || value.Cycle > value.RetryPolicy.MaximumReviewCycles ||
		!digestPattern.MatchString(value.ControlDigest) || value.Snapshot.Run.ContractVersion != agentloop.ContractVersion ||
		value.Snapshot.Run.Case != value.Snapshot.Step.Case || value.Snapshot.Run.RunID != value.Snapshot.Step.RunID {
		return newError(Denied, "session", "session_invalid", false, nil)
	}
	control, err := controlDigest(value.Snapshot.Run.RunID, value.TraceID, value.RetryPolicy)
	if err != nil || control != value.ControlDigest {
		return newError(Denied, "session", "control_binding_invalid", false, nil)
	}
	if _, found := slices.BinarySearch(value.Snapshot.Run.InputRefs, control); !found {
		return newError(Denied, "session", "control_reference_missing", false, nil)
	}
	expected, err := phaseStepID(value.Snapshot.Run.RunID, value.TraceID, value.Cycle, value.Phase)
	if err != nil || expected != value.Snapshot.Step.StepID || expected != value.Snapshot.Run.CurrentStepID {
		return newError(Denied, "session", "phase_identity_invalid", false, nil)
	}
	expectedKind := agentloop.PlanningActivity
	if value.Phase == ActPhase {
		expectedKind = agentloop.AuthorizedActionActivity
	}
	if value.Snapshot.Step.Kind != expectedKind {
		return newError(Denied, "session", "activity_kind_invalid", false, nil)
	}
	return nil
}

func validatePhaseOutput(value PhaseOutput) error {
	if value.ContractVersion != ContractVersion || !validPhase(value.Phase) ||
		!uuidV7Pattern.MatchString(value.TraceID) || value.Cycle == 0 || value.Cycle > 8 ||
		!digestPattern.MatchString(value.InputSetDigest) || !digestPattern.MatchString(value.ArtifactDigest) ||
		!validateDigestSet(value.EvidenceRefs, maximumReferences, false) || value.Claims == nil || value.Findings == nil ||
		len(value.Claims) > 64 || len(value.Findings) > 64 {
		return newError(Denied, "output", "phase_output_invalid", false, nil)
	}
	for index, claim := range value.Claims {
		if !validateClaim(claim) || index > 0 && value.Claims[index-1].ClaimID >= claim.ClaimID {
			return newError(Denied, "output", "claim_invalid", false, nil)
		}
	}
	for index, finding := range value.Findings {
		if !validateFinding(finding) || index > 0 && value.Findings[index-1].FindingID >= finding.FindingID {
			return newError(Denied, "output", "finding_invalid", false, nil)
		}
	}
	switch value.Phase {
	case PlanPhase:
		if !digestPattern.MatchString(value.IntentDigest) || value.ReceiptDigest != "" ||
			len(value.EvidenceRefs) != 0 || value.Completeness != "" || value.NegativeResult ||
			len(value.Claims) != 0 || len(value.Findings) != 0 || value.ReviewDisposition != "" {
			return newError(Denied, "output", "plan_output_invalid", false, nil)
		}
	case ActPhase:
		if !digestPattern.MatchString(value.IntentDigest) || !digestPattern.MatchString(value.ReceiptDigest) ||
			len(value.EvidenceRefs) == 0 || value.Completeness != Complete || value.NegativeResult ||
			len(value.Claims) != 0 || len(value.Findings) != 0 || value.ReviewDisposition != "" {
			return newError(Denied, "output", "act_output_invalid", false, nil)
		}
	case ObservePhase:
		if value.IntentDigest != "" || value.ReceiptDigest != "" || len(value.EvidenceRefs) == 0 ||
			!validCompleteness(value.Completeness) || len(value.Claims) != 0 || len(value.Findings) != 0 ||
			value.ReviewDisposition != "" {
			return newError(Denied, "output", "observe_output_invalid", false, nil)
		}
	case ReviewPhase:
		if value.IntentDigest != "" || value.ReceiptDigest != "" || len(value.EvidenceRefs) == 0 ||
			!validCompleteness(value.Completeness) || len(value.Findings) == 0 ||
			value.ReviewDisposition != ReviewAccepted && value.ReviewDisposition != ReviewRevise {
			return newError(Denied, "output", "review_output_invalid", false, nil)
		}
	}
	return nil
}

func validatePhaseInput(value PhaseInput) error {
	if value.ContractVersion != ContractVersion || !validPhase(value.Phase) ||
		!uuidV7Pattern.MatchString(value.TraceID) || value.Cycle == 0 || value.Cycle > 8 ||
		!validateDigestSet(value.InputRefs, maximumReferences, false) ||
		!digestPattern.MatchString(value.InputSetDigest) || !validateRetryPolicy(value.RetryPolicy) ||
		value.Cycle > value.RetryPolicy.MaximumReviewCycles {
		return newError(Denied, "input", "phase_input_invalid", false, nil)
	}
	digest, err := inputSetDigest(value.InputRefs)
	if err != nil || digest != value.InputSetDigest {
		return newError(Denied, "input", "input_digest_invalid", false, nil)
	}
	if value.Phase == PlanPhase && value.Cycle == 1 {
		if value.PriorOutputDigest != "" {
			return newError(Denied, "input", "prior_output_invalid", false, nil)
		}
	} else if !digestPattern.MatchString(value.PriorOutputDigest) {
		return newError(Denied, "input", "prior_output_invalid", false, nil)
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value.Deadline)
	if err != nil || parsed.Format("2006-01-02T15:04:05.000000000Z") != value.Deadline {
		return newError(Denied, "input", "deadline_invalid", false, nil)
	}
	return nil
}

func validateClaim(value Claim) bool {
	return uuidV7Pattern.MatchString(value.ClaimID) && digestPattern.MatchString(value.StatementDigest) &&
		validateDigestSet(value.EvidenceRefs, maximumReferences, true) &&
		validateDigestSet(value.CounterevidenceRefs, maximumReferences, false) &&
		value.ConfidenceBasisPoints <= 10000 && validateDigestSet(value.UnknownDigests, maximumReferences, false) &&
		validateDigestSet(value.RecommendedNextStepDigests, maximumReferences, true)
}

func validateFinding(value Finding) bool {
	return uuidV7Pattern.MatchString(value.FindingID) && digestPattern.MatchString(value.SummaryDigest) &&
		oneOf(value.Status, "observed", "suspected", "confirmed", "rejected") &&
		oneOf(value.Severity, "informational", "low", "medium", "high", "critical") &&
		validateDigestSet(value.EvidenceRefs, maximumReferences, true) &&
		validateDigestSet(value.CounterevidenceRefs, maximumReferences, false) &&
		value.ConfidenceBasisPoints <= 10000 && validateDigestSet(value.UnknownDigests, maximumReferences, false) &&
		validateDigestSet(value.RecommendedNextStepDigests, maximumReferences, true)
}

func validateDigestSet(values []string, maximum int, required bool) bool {
	if values == nil || required && len(values) == 0 || len(values) > maximum || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}

func validPhase(value Phase) bool {
	return value == PlanPhase || value == ActPhase || value == ObservePhase || value == ReviewPhase
}

func validCompleteness(value Completeness) bool {
	return value == Complete || value == Partial || value == Empty || value == Uncertain
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
