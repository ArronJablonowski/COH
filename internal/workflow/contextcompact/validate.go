package contextcompact

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	timezonePattern = regexp.MustCompile(`^[A-Za-z0-9_+:/.-]{1,64}$`)
)

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", false, nil)
	}
	if err := ctx.Err(); err != nil {
		return mapContext(err)
	}
	return nil
}

func validateRequest(value Request, now time.Time) error {
	if !validOpaque(value.IdempotencyKey, 256) {
		return newError(InvalidInput, "compaction_idempotency_invalid", false, nil)
	}
	if err := validateIntent(value.Intent); err != nil {
		return err
	}
	if value.Intent.CreatedAt.After(now) {
		return newError(InvalidInput, "compaction_time_binding_invalid", false, nil)
	}
	return nil
}

func validateIntent(value Intent) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.CompactionID) || !uuidPattern.MatchString(value.RunID) ||
		!uuidPattern.MatchString(value.TaskID) || !validCase(value.Case) ||
		!digestPattern.MatchString(value.PolicyDigest) || !tokenPattern.MatchString(value.ProviderRoute) ||
		len(value.Sources) == 0 || len(value.Sources) > MaximumSources || !validTime(value.CreatedAt) ||
		!validTime(value.Deadline) || !value.Deadline.After(value.CreatedAt) {
		return newError(InvalidInput, "compaction_intent_invalid", false, nil)
	}
	seen := make(map[string]struct{}, len(value.Sources))
	for index, source := range value.Sources {
		if source.Sequence != uint32(index+1) || !validSource(source) {
			return newError(InvalidInput, "compaction_source_invalid", false, nil)
		}
		if _, exists := seen[source.EvidenceID]; exists {
			return newError(InvalidInput, "compaction_evidence_duplicate", false, nil)
		}
		seen[source.EvidenceID] = struct{}{}
	}
	return nil
}

func validSource(value Source) bool {
	if !uuidPattern.MatchString(value.EvidenceID) || !digestPattern.MatchString(value.EvidenceDigest) ||
		value.Trust != UntrustedEvidence || !validSourceTime(value.SourceTime) ||
		!validCanonicalTimestamp(value.NormalizedTime) || !timezonePattern.MatchString(value.OriginalTimezone) ||
		value.ClockUncertaintyNanoseconds > math.MaxInt64 || !validPrecision(value.Precision) ||
		!validOrder(value.Order) || !validResult(value.Result) || !validCompleteness(value.Completeness) ||
		!validUncertainty(value.Uncertainty) {
		return false
	}
	return true
}

func validateState(value State) error {
	intent := Intent{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		CompactionID: value.CompactionID, RunID: value.RunID, TaskID: value.TaskID, Case: value.Case,
		PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute, Sources: value.Sources,
		CreatedAt: value.CreatedAt, Deadline: value.Deadline}
	bound, err := intentDigest(intent)
	manifest, manifestErr := sourceManifestDigest(value.Sources)
	if err != nil || manifestErr != nil || bound != value.IntentDigest || manifest != value.SourceManifestDigest ||
		!digestPattern.MatchString(value.IdempotencyDigest) ||
		value.SummaryTrust != UntrustedEvidence ||
		!validStateTransition(value) || value.PreviousProvenanceDigest != "" &&
		!digestPattern.MatchString(value.PreviousProvenanceDigest) || !digestPattern.MatchString(value.ProvenanceDigest) ||
		!validTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) || value.Revision == 0 ||
		value.Revision > math.MaxInt64 {
		return newError(Denied, "compaction_state_invalid", false, nil)
	}
	switch value.Status {
	case StatusWriting, StatusUncertain:
		if value.Summary != (domain.ArtifactRef{}) {
			return newError(Denied, "compaction_summary_state_invalid", false, nil)
		}
	case StatusCompleted:
		if !validArtifact(value.Summary) {
			return newError(Denied, "compaction_summary_invalid", false, nil)
		}
	default:
		return newError(Denied, "compaction_status_invalid", false, nil)
	}
	expected, digestErr := provenanceDigest(value.PreviousProvenanceDigest, value.ReasonCode, value)
	if digestErr != nil || expected != value.ProvenanceDigest {
		return newError(Denied, "compaction_provenance_invalid", false, nil)
	}
	return nil
}

func validStateTransition(value State) bool {
	switch value.Status {
	case StatusWriting:
		return value.Revision == 1 && value.ReasonCode == "summary_writing" &&
			value.PreviousProvenanceDigest == ""
	case StatusCompleted:
		return value.Revision == 2 && value.ReasonCode == "summary_completed" &&
			digestPattern.MatchString(value.PreviousProvenanceDigest)
	case StatusUncertain:
		validReason := value.ReasonCode == "summary_outcome_uncertain" ||
			value.ReasonCode == "summary_reference_invalid" || value.ReasonCode == "summary_canceled" ||
			value.ReasonCode == "summary_timeout" || value.ReasonCode == "summary_dependency_unavailable"
		return value.Revision == 2 && validReason && digestPattern.MatchString(value.PreviousProvenanceDigest)
	default:
		return false
	}
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && value.MediaType == "application/json" &&
		tokenPattern.MatchString(value.Classification) && value.Length > 0 && value.Length <= 1<<30
}

func validSourceTime(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && (strings.HasSuffix(value, "Z") || strings.ContainsAny(value[len(value)-6:], "+-"))
}

func validCanonicalTimestamp(value string) bool {
	parsed, err := time.Parse(timestampLayout, value)
	return err == nil && formatTime(parsed) == value
}

func validPrecision(value TimePrecision) bool {
	switch value {
	case PrecisionNanosecond, PrecisionMicrosecond, PrecisionMillisecond, PrecisionSecond,
		PrecisionMinute, PrecisionHour, PrecisionDay, PrecisionUnknown:
		return true
	default:
		return false
	}
}

func validOrder(value OrderConfidence) bool {
	return value == OrderStrict || value == OrderOverlap || value == OrderUnknown
}

func validResult(value ResultState) bool {
	return value == ResultObserved || value == ResultNegative || value == ResultGap ||
		value == ResultConflicting || value == ResultError
}

func validCompleteness(value Completeness) bool {
	return value == Complete || value == Partial || value == Truncated || value == SourceUnavailable || value == Unknown
}

func validUncertainty(value Uncertainty) bool {
	return value == UncertaintyNone || value == UncertaintyBounded || value == UncertaintyClock ||
		value == UncertaintyConflicting || value == UncertaintyUnknown
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

func mapContext(err error) error {
	if err == context.Canceled {
		return newError(Canceled, "compaction_canceled", false, context.Canceled)
	}
	if err == context.DeadlineExceeded {
		return newError(Timeout, "compaction_timeout", false, context.DeadlineExceeded)
	}
	return newError(Unavailable, "compaction_dependency_unavailable", true, nil)
}
