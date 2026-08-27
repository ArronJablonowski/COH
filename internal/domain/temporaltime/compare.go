package temporaltime

import (
	"context"
	"math"
	"math/big"
	"time"
)

// CompareRecords returns a conservative relation. It never imposes strict
// ordering on intersecting or unresolved intervals.
func CompareRecords(ctx context.Context, comparisonID string, left, right Record, createdAt time.Time) (Comparison, error) {
	_, leftDigest, err := CanonicalRecord(ctx, left)
	if err != nil {
		return Comparison{}, err
	}
	_, rightDigest, err := CanonicalRecord(ctx, right)
	if err != nil {
		return Comparison{}, err
	}
	if !uuidPattern.MatchString(comparisonID) || left.Case != right.Case || !validTimestamp(formatTime(createdAt)) {
		return Comparison{}, newError(InvalidInput, IntervalInvalid, nil)
	}
	comparison := Comparison{
		SchemaVersion: ComparisonSchemaVersion, ContractVersion: ContractVersion, ComparisonID: comparisonID,
		Case:      left.Case,
		Left:      RecordRef{RecordID: left.RecordID, RecordDigest: leftDigest, DeduplicationDigest: left.SourceBinding.DeduplicationDigest},
		Right:     RecordRef{RecordID: right.RecordID, RecordDigest: rightDigest, DeduplicationDigest: right.SourceBinding.DeduplicationDigest},
		CreatedAt: formatTime(createdAt),
	}
	if comparison.Left.DeduplicationDigest == comparison.Right.DeduplicationDigest {
		if leftDigest == rightDigest {
			comparison.Outcome, comparison.Confidence, comparison.Rationale = Duplicate, confidenceFor(left, right), SameBindingSameRecord
		} else {
			comparison.Outcome, comparison.Confidence, comparison.Rationale = Conflict, Ambiguous, SameBindingIncompatibleFacts
		}
		return comparison, nil
	}
	if left.Outcome != Normalized || right.Outcome != Normalized || !validBoundedInterval(left.Interval) || !validBoundedInterval(right.Interval) {
		comparison.Outcome, comparison.Confidence, comparison.Rationale = UnknownComparison, UnknownConfidence, UnresolvedInput
		if left.Interval.Kind == Unbounded || right.Interval.Kind == Unbounded {
			comparison.Rationale = UnboundedInterval
		}
		return comparison, nil
	}
	leftFirst, leftLast := parseInterval(left.Interval)
	rightFirst, rightLast := parseInterval(right.Interval)
	switch {
	case leftLast.Before(rightFirst):
		gap, ok := uncoveredNanoseconds(leftLast, rightFirst)
		if !ok {
			return Comparison{}, newError(DeniedError, ArithmeticOverflow, nil)
		}
		comparison.Outcome, comparison.Confidence, comparison.Rationale, comparison.GapNanoseconds = Before, confidenceFor(left, right), DisjointIntervals, &gap
	case rightLast.Before(leftFirst):
		gap, ok := uncoveredNanoseconds(rightLast, leftFirst)
		if !ok {
			return Comparison{}, newError(DeniedError, ArithmeticOverflow, nil)
		}
		comparison.Outcome, comparison.Confidence, comparison.Rationale, comparison.GapNanoseconds = After, confidenceFor(left, right), DisjointIntervals, &gap
	case leftFirst.Equal(leftLast) && rightFirst.Equal(rightLast) && leftFirst.Equal(rightFirst):
		comparison.Outcome, comparison.Confidence, comparison.Rationale = Equal, confidenceFor(left, right), EqualSingleton
	default:
		comparison.Outcome, comparison.Confidence, comparison.Rationale = Overlap, confidenceFor(left, right), IntersectingIntervals
	}
	return comparison, nil
}

func confidenceFor(left, right Record) Confidence {
	if left.TimezoneResult.DSTState == DSTFold || right.TimezoneResult.DSTState == DSTFold || left.EvidenceState == Conflicting || right.EvidenceState == Conflicting {
		return Ambiguous
	}
	if exactRecord(left) && exactRecord(right) {
		return Exact
	}
	return BoundedConfidence
}

func exactRecord(value Record) bool {
	if value.Interval.Kind != Bounded || value.Interval.EarliestUTC == nil || value.Interval.LatestUTC == nil || *value.Interval.EarliestUTC != *value.Interval.LatestUTC ||
		value.Calibration.State != KnownCalibration || value.Calibration.RadiusNanoseconds == nil || *value.Calibration.RadiusNanoseconds != 0 {
		return false
	}
	return value.TimezoneResult.DSTState == DSTExact || value.TimezoneResult.DSTState == DSTNotApplicable
}

func parseInterval(value Interval) (time.Time, time.Time) {
	first, _ := time.Parse(timestampLayout, *value.EarliestUTC)
	last, _ := time.Parse(timestampLayout, *value.LatestUTC)
	return first, last
}

func uncoveredNanoseconds(first, second time.Time) (int64, bool) {
	firstNanos := absoluteNanoseconds(first)
	secondNanos := absoluteNanoseconds(second)
	delta := new(big.Int).Sub(secondNanos, firstNanos)
	delta.Sub(delta, big.NewInt(1))
	if delta.Sign() < 0 || !delta.IsInt64() || delta.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return 0, false
	}
	return delta.Int64(), true
}

func absoluteNanoseconds(value time.Time) *big.Int {
	seconds := big.NewInt(value.Unix())
	seconds.Mul(seconds, big.NewInt(int64(time.Second)))
	return seconds.Add(seconds, big.NewInt(int64(value.Nanosecond())))
}
