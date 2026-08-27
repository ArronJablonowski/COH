package temporaltime

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	selectorPattern = regexp.MustCompile(`^(original|ocsf|ecs)(\.[A-Za-z0-9_-]+)+$`)
	timezonePattern = regexp.MustCompile(`^[A-Za-z0-9_+.-]{1,64}(/[A-Za-z0-9_+.-]{1,64}){1,3}$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func validateCommand(ctx context.Context, value Command) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.OperationID) || !digestPattern.MatchString(value.IdempotencyKey) ||
		!validCase(value.Case) || !validSourceBinding(value.SourceBinding) || !validOriginal(value.OriginalTime) ||
		!validParser(value.Parser) || !validTimezone(value.Timezone) || !validCalibration(value.Calibration) ||
		!validEvidenceState(value.EvidenceState) || !validCompleteness(value.Completeness) ||
		!validTimestamp(value.RequestedAt) || !validTimestamp(value.Deadline) || value.Deadline <= value.RequestedAt {
		return newError(InvalidInput, InvalidSourceText, nil)
	}
	return nil
}

func validateRecord(ctx context.Context, value Record) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RecordID) || !uuidPattern.MatchString(value.OperationID) ||
		!digestPattern.MatchString(value.CommandDigest) || !validCase(value.Case) ||
		!validSourceBinding(value.SourceBinding) || !validOriginal(value.OriginalTime) || !validParser(value.Parser) ||
		!validTimezoneResult(value.TimezoneResult) || !validCalibration(value.Calibration) ||
		!validEvidenceState(value.EvidenceState) || !validCompleteness(value.Completeness) || !validTimestamp(value.CreatedAt) ||
		!validOutcomeReason(value.Outcome, value.ReasonCode) || !validCandidateTimes(value.CandidateUTC) {
		return newError(InvalidInput, IntervalInvalid, nil)
	}
	if value.Outcome == Normalized {
		if value.NormalizedUTC == nil || !validTimestamp(*value.NormalizedUTC) || value.Interval.Kind != Bounded ||
			!validBoundedInterval(value.Interval) || len(value.CandidateUTC) == 0 {
			return newError(InvalidInput, IntervalInvalid, nil)
		}
	} else if value.NormalizedUTC != nil || value.Outcome != Unresolved && !validUnboundedInterval(value.Interval) ||
		value.Outcome == Unresolved && !validBoundedInterval(value.Interval) && !validUnboundedInterval(value.Interval) {
		return newError(InvalidInput, IntervalInvalid, nil)
	}
	return nil
}

func validateComparison(ctx context.Context, value Comparison) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != ComparisonSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.ComparisonID) || !validCase(value.Case) || !validRecordRef(value.Left) ||
		!validRecordRef(value.Right) || !validComparisonOutcome(value.Outcome) || !validConfidence(value.Confidence) ||
		!validRationale(value.Rationale) || !validTimestamp(value.CreatedAt) {
		return newError(InvalidInput, IntervalInvalid, nil)
	}
	strict := value.Outcome == Before || value.Outcome == After
	if strict != (value.GapNanoseconds != nil) || strict && *value.GapNanoseconds < 0 || strict && value.Rationale != DisjointIntervals {
		return newError(InvalidInput, IntervalInvalid, nil)
	}
	return nil
}

func validateReceipt(ctx context.Context, value Receipt) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.OperationID) || !digestPattern.MatchString(value.IdempotencyKey) ||
		!digestPattern.MatchString(value.CommandDigest) || value.Record != nil && !validRecordRef(*value.Record) ||
		!validOutcomeReason(value.Outcome, value.ReasonCode) || !digestPattern.MatchString(value.AuditDigest) ||
		value.PreviousProvenanceDigest != nil && !digestPattern.MatchString(*value.PreviousProvenanceDigest) ||
		!digestPattern.MatchString(value.ProvenanceDigest) || !validTimestamp(value.CreatedAt) ||
		!validTimestamp(value.UpdatedAt) || value.UpdatedAt < value.CreatedAt {
		return newError(InvalidInput, IntervalInvalid, nil)
	}
	return nil
}

func validCase(value Case) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}

func validSourceBinding(value SourceBinding) bool {
	return uuidPattern.MatchString(value.EnvelopeID) && digestPattern.MatchString(value.EnvelopeDigest) &&
		digestPattern.MatchString(value.ArtifactDigest) && digestPattern.MatchString(value.ManifestDigest) &&
		digestPattern.MatchString(value.IngestReceiptDigest) && digestPattern.MatchString(value.SourceProvenanceDigest) &&
		digestPattern.MatchString(value.SourceIdentityDigest) && validSelector(value.FieldSelector) && digestPattern.MatchString(value.DeduplicationDigest)
}

func validSelector(value string) bool {
	if len(value) > 1024 || !selectorPattern.MatchString(value) {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 17 {
		return false
	}
	for _, part := range parts[1:] {
		if len(part) == 0 || len(part) > 128 {
			return false
		}
	}
	return true
}

func validOriginal(value OriginalTime) bool {
	return len(value.Text) > 0 && len(value.Text) <= 4096 && utf8.ValidString(value.Text) && tokenPattern.MatchString(value.Format) && validPrecision(value.Precision)
}

func validParser(value ParserIdentity) bool {
	return tokenPattern.MatchString(value.Name) && len(value.Version) > 0 && len(value.Version) <= 256 && utf8.ValidString(value.Version) && digestPattern.MatchString(value.Digest)
}

func validTimezone(value TimezoneAssertion) bool {
	switch value.Kind {
	case ExplicitOffset:
		return value.Name == "" && validOffset(value.OffsetMinutes) && value.TZDataVersion == "" && value.TZDataDigest == ""
	case IANA:
		return timezonePattern.MatchString(value.Name) && len(value.Name) <= 256 && (value.OffsetMinutes == nil || validOffset(value.OffsetMinutes)) &&
			len(value.TZDataVersion) > 0 && len(value.TZDataVersion) <= 256 && digestPattern.MatchString(value.TZDataDigest)
	case MissingTimezone:
		return value.Name == "" && value.OffsetMinutes == nil && value.TZDataVersion == "" && value.TZDataDigest == ""
	default:
		return false
	}
}

func validOffset(value *int16) bool { return value != nil && *value >= -840 && *value <= 840 }

func validCalibration(value Calibration) bool {
	if value.State == UnknownCalibration {
		return value.ClockKind == UnknownClock && value.Identity == "" && value.IdentityDigest == "" && value.EstimateNanoseconds == nil && value.RadiusNanoseconds == nil
	}
	return value.State == KnownCalibration && slices.Contains([]ClockKind{SourceClock, CollectorClock, ServerClock, DeviceClock}, value.ClockKind) &&
		len(value.Identity) > 0 && len(value.Identity) <= 256 && utf8.ValidString(value.Identity) && digestPattern.MatchString(value.IdentityDigest) &&
		value.EstimateNanoseconds != nil && value.RadiusNanoseconds != nil && *value.RadiusNanoseconds >= 0
}

func validTimezoneResult(value TimezoneResult) bool {
	if !validTimezone(value.Assertion) || !slices.Contains([]DSTState{DSTExact, DSTFold, DSTGapState, DSTNotApplicable, DSTUnresolved}, value.DSTState) || len(value.ResolvedOffsetsMinutes) > 2 {
		return false
	}
	for index, offset := range value.ResolvedOffsetsMinutes {
		if offset < -840 || offset > 840 || index > 0 && value.ResolvedOffsetsMinutes[index-1] >= offset {
			return false
		}
	}
	return true
}

func validCandidateTimes(values []string) bool {
	if len(values) > 2 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validTimestamp(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validBoundedInterval(value Interval) bool {
	return value.Kind == Bounded && value.EarliestUTC != nil && value.LatestUTC != nil &&
		validTimestamp(*value.EarliestUTC) && validTimestamp(*value.LatestUTC) && *value.EarliestUTC <= *value.LatestUTC
}

func validUnboundedInterval(value Interval) bool {
	return value.Kind == Unbounded && value.EarliestUTC == nil && value.LatestUTC == nil
}

func validRecordRef(value RecordRef) bool {
	return uuidPattern.MatchString(value.RecordID) && digestPattern.MatchString(value.RecordDigest) && digestPattern.MatchString(value.DeduplicationDigest)
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(timestampLayout, value)
	return err == nil && parsed.Format(timestampLayout) == value
}

func validPrecision(value Precision) bool {
	return slices.Contains([]Precision{Nanosecond, Microsecond, Millisecond, Second, Minute, Hour, Day, UnknownPrecision}, value)
}

func validEvidenceState(value EvidenceState) bool {
	return slices.Contains([]EvidenceState{Observed, Negative, Gap, Partial, Conflicting}, value)
}

func validCompleteness(value Completeness) bool {
	return slices.Contains([]Completeness{Complete, PartialCompleteness, Truncated, UnavailableCompleteness, UnknownCompleteness}, value)
}

func validOutcomeReason(outcome Outcome, reason Reason) bool {
	switch outcome {
	case Normalized:
		return reason == ReasonNormalized
	case Unresolved:
		return slices.Contains([]Reason{TimezoneUnresolved, TimezoneMismatch, DSTGap, PrecisionUnknown, CalibrationUnresolved}, reason)
	case Denied:
		return slices.Contains([]Reason{InvalidSourceText, ParserNotRegistered, FormatNotSupported, EvidenceBindingMismatch, EvidenceStateInvalid, ArithmeticOverflow, IntervalInvalid, IdempotencyConflict}, reason)
	case CanceledOutcome:
		return reason == ContextCanceled
	case TimeoutOutcome:
		return reason == ContextDeadline
	case DependencyUnavailable:
		return reason == DependencyUnavailableReason
	default:
		return false
	}
}

func validComparisonOutcome(value ComparisonOutcome) bool {
	return slices.Contains([]ComparisonOutcome{Before, After, Equal, Overlap, Duplicate, Conflict, UnknownComparison}, value)
}

func validConfidence(value Confidence) bool {
	return slices.Contains([]Confidence{Exact, BoundedConfidence, Ambiguous, UnknownConfidence}, value)
}

func validRationale(value Rationale) bool {
	return slices.Contains([]Rationale{DisjointIntervals, EqualSingleton, IntersectingIntervals, SameBindingSameRecord, SameBindingIncompatibleFacts, UnboundedInterval, UnresolvedInput}, value)
}

func hasForbiddenName(name string) bool {
	lower := strings.ToLower(name)
	for _, forbidden := range []string{"path", "url", "sql", "http", "client", "connector", "executor", "credential", "secret", "callback", "shell"} {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	return false
}
