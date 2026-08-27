package temporaltime

import (
	"context"
	"math"
	"slices"
	"time"
)

// BuildRecord applies a verified parser, timezone, and calibration result. The
// function is pure apart from context checks; callers persist its canonical
// output through the idempotent store boundary.
func BuildRecord(ctx context.Context, command Command, civil CivilTime, resolution TimezoneResolution, calibration Calibration, createdAt time.Time) (Record, error) {
	_, commandDigest, err := CanonicalCommand(ctx, command)
	if err != nil {
		return Record{}, err
	}
	if !validCivil(civil) || civil.Precision != command.OriginalTime.Precision || !validTimestamp(formatTime(createdAt)) {
		return Record{}, newError(InvalidInput, InvalidSourceText, nil)
	}
	record := baseRecord(command, commandDigest, calibration, createdAt)
	if command.Timezone.Kind == MissingTimezone {
		if resolution.DSTState != DSTUnresolved || len(resolution.Intervals) != 0 {
			return Record{}, newError(ConflictError, TimezoneMismatch, nil)
		}
		return unresolvedRecord(record, TimezoneUnresolved, DSTUnresolved), nil
	}
	if civil.Precision == UnknownPrecision {
		return unresolvedRecord(record, PrecisionUnknown, resolution.DSTState), nil
	}
	if calibration.State == UnknownCalibration {
		return unresolvedRecord(record, CalibrationUnresolved, resolution.DSTState), nil
	}
	if !validCalibration(calibration) || !sameCalibration(calibration, command.Calibration) {
		return Record{}, newError(ConflictError, CalibrationUnresolved, nil)
	}
	if err := validateResolution(command.Timezone, resolution); err != nil {
		return Record{}, err
	}
	record.TimezoneResult = timezoneResult(command.Timezone, resolution)
	if resolution.DSTState == DSTGapState {
		return unresolvedRecord(record, DSTGap, DSTGapState), nil
	}
	corrected, candidates, nominal, err := correctedIntervals(resolution.Intervals, calibration)
	if err != nil {
		return Record{}, err
	}
	record.CandidateUTC = candidates
	record.Interval = aggregateInterval(corrected)
	if resolution.DSTState == DSTFold {
		record.Outcome = Unresolved
		record.ReasonCode = TimezoneUnresolved
		return record, nil
	}
	record.NormalizedUTC = &nominal
	record.Outcome = Normalized
	record.ReasonCode = ReasonNormalized
	return record, nil
}

func baseRecord(command Command, commandDigest string, calibration Calibration, createdAt time.Time) Record {
	return Record{
		SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		RecordID: command.OperationID, OperationID: command.OperationID, CommandDigest: commandDigest,
		Case: command.Case, SourceBinding: command.SourceBinding, OriginalTime: command.OriginalTime,
		Parser: command.Parser, TimezoneResult: TimezoneResult{Assertion: command.Timezone, DSTState: DSTUnresolved, ResolvedOffsetsMinutes: []int16{}},
		Calibration: calibration, CandidateUTC: []string{}, Interval: Interval{Kind: Unbounded},
		EvidenceState: command.EvidenceState, Completeness: command.Completeness, CreatedAt: formatTime(createdAt),
	}
}

func unresolvedRecord(record Record, reason Reason, state DSTState) Record {
	record.TimezoneResult.DSTState = state
	record.Outcome = Unresolved
	record.ReasonCode = reason
	record.CandidateUTC = []string{}
	record.NormalizedUTC = nil
	record.Interval = Interval{Kind: Unbounded}
	return record
}

func validateResolution(assertion TimezoneAssertion, value TimezoneResolution) error {
	wanted := 0
	switch value.DSTState {
	case DSTExact, DSTNotApplicable:
		wanted = 1
	case DSTFold:
		wanted = 2
	case DSTGapState:
		wanted = 0
	default:
		return newError(ConflictError, TimezoneMismatch, nil)
	}
	if len(value.Intervals) != wanted || assertion.Kind == ExplicitOffset && value.DSTState != DSTNotApplicable || assertion.Kind == IANA && value.DSTState == DSTNotApplicable {
		return newError(ConflictError, TimezoneMismatch, nil)
	}
	for index, interval := range value.Intervals {
		if !validResolvedInterval(interval) || assertion.OffsetMinutes != nil && interval.OffsetMinutes != *assertion.OffsetMinutes ||
			index > 0 && !value.Intervals[index-1].EarliestUTC.Before(interval.EarliestUTC) {
			return newError(ConflictError, TimezoneMismatch, nil)
		}
	}
	return nil
}

func validResolvedInterval(value ResolvedInterval) bool {
	return !value.EarliestUTC.IsZero() && !value.LatestUTC.IsZero() && !value.LatestUTC.Before(value.EarliestUTC) &&
		value.OffsetMinutes >= -840 && value.OffsetMinutes <= 840 && validTimestamp(formatTime(value.EarliestUTC)) && validTimestamp(formatTime(value.LatestUTC))
}

func correctedIntervals(values []ResolvedInterval, calibration Calibration) ([]ResolvedInterval, []string, string, error) {
	estimate := *calibration.EstimateNanoseconds
	radius := *calibration.RadiusNanoseconds
	maximumSkew, ok := add64(estimate, radius)
	if !ok {
		return nil, nil, "", newError(DeniedError, ArithmeticOverflow, nil)
	}
	minimumSkew, ok := sub64(estimate, radius)
	if !ok {
		return nil, nil, "", newError(DeniedError, ArithmeticOverflow, nil)
	}
	lowerShift, lowerOK := negate64(maximumSkew)
	upperShift, upperOK := negate64(minimumSkew)
	nominalShift, nominalOK := negate64(estimate)
	if !lowerOK || !upperOK || !nominalOK {
		return nil, nil, "", newError(DeniedError, ArithmeticOverflow, nil)
	}
	result := make([]ResolvedInterval, 0, len(values))
	candidates := make([]string, 0, len(values))
	for _, value := range values {
		earliest, earliestOK := addTime(value.EarliestUTC, lowerShift)
		latest, latestOK := addTime(value.LatestUTC, upperShift)
		nominal, candidateOK := addTime(value.EarliestUTC, nominalShift)
		if !earliestOK || !latestOK || !candidateOK || latest.Before(earliest) {
			return nil, nil, "", newError(DeniedError, ArithmeticOverflow, nil)
		}
		result = append(result, ResolvedInterval{EarliestUTC: earliest, LatestUTC: latest, OffsetMinutes: value.OffsetMinutes})
		candidates = append(candidates, formatTime(nominal))
	}
	slices.Sort(candidates)
	return result, candidates, candidates[0], nil
}

func aggregateInterval(values []ResolvedInterval) Interval {
	earliest, latest := values[0].EarliestUTC, values[0].LatestUTC
	for _, value := range values[1:] {
		if value.EarliestUTC.Before(earliest) {
			earliest = value.EarliestUTC
		}
		if value.LatestUTC.After(latest) {
			latest = value.LatestUTC
		}
	}
	lower, upper := formatTime(earliest), formatTime(latest)
	return Interval{Kind: Bounded, EarliestUTC: &lower, LatestUTC: &upper}
}

func validCivil(value CivilTime) bool {
	if !validPrecision(value.Precision) || value.Year < 0 || value.Year > 9999 || value.Month < time.January || value.Month > time.December ||
		value.Day < 1 || value.Day > 31 || value.Hour < 0 || value.Hour > 23 || value.Minute < 0 || value.Minute > 59 || value.Second < 0 || value.Second > 59 ||
		value.Nanosecond < 0 || value.Nanosecond >= int(time.Second) {
		return false
	}
	probe := time.Date(value.Year, value.Month, value.Day, value.Hour, value.Minute, value.Second, value.Nanosecond, time.UTC)
	return probe.Year() == value.Year && probe.Month() == value.Month && probe.Day() == value.Day
}

func sameCalibration(left, right Calibration) bool {
	if left.State != right.State || left.ClockKind != right.ClockKind || left.Identity != right.Identity || left.IdentityDigest != right.IdentityDigest {
		return false
	}
	return sameInt64(left.EstimateNanoseconds, right.EstimateNanoseconds) && sameInt64(left.RadiusNanoseconds, right.RadiusNanoseconds)
}

func sameInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func timezoneResult(assertion TimezoneAssertion, value TimezoneResolution) TimezoneResult {
	offsets := make([]int16, 0, len(value.Intervals))
	for _, interval := range value.Intervals {
		if !slices.Contains(offsets, interval.OffsetMinutes) {
			offsets = append(offsets, interval.OffsetMinutes)
		}
	}
	slices.Sort(offsets)
	return TimezoneResult{Assertion: assertion, DSTState: value.DSTState, ResolvedOffsetsMinutes: offsets}
}

func add64(left, right int64) (int64, bool) {
	if right > 0 && left > math.MaxInt64-right || right < 0 && left < math.MinInt64-right {
		return 0, false
	}
	return left + right, true
}

func sub64(left, right int64) (int64, bool) {
	if right == math.MinInt64 {
		return 0, false
	}
	return add64(left, -right)
}

func negate64(value int64) (int64, bool) {
	if value == math.MinInt64 {
		return 0, false
	}
	return -value, true
}

func addTime(value time.Time, nanoseconds int64) (result time.Time, ok bool) {
	result = value.Add(time.Duration(nanoseconds))
	return result, result.Year() >= 0 && result.Year() <= 9999 && validTimestamp(formatTime(result))
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }
