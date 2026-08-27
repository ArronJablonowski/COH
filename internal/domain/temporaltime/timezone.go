package temporaltime

import (
	"context"
	"slices"
	"time"
)

type pinnedZone struct {
	location *time.Location
}

// PinnedTimezoneResolver resolves only an exact immutable tzdata identity. The
// caller constructs locations from its verified bundled tzdata; this type has
// no filesystem or network loading surface.
type PinnedTimezoneResolver struct {
	version string
	digest  string
	zones   map[string]pinnedZone
}

func NewPinnedTimezoneResolver(version, digest string, zones map[string]*time.Location) (*PinnedTimezoneResolver, error) {
	if len(version) == 0 || len(version) > 256 || !digestPattern.MatchString(digest) || len(zones) == 0 || len(zones) > 1024 {
		return nil, newError(InvalidInput, TimezoneUnresolved, nil)
	}
	copyZones := make(map[string]pinnedZone, len(zones))
	for name, location := range zones {
		if !timezonePattern.MatchString(name) || location == nil {
			return nil, newError(InvalidInput, TimezoneUnresolved, nil)
		}
		copyZones[name] = pinnedZone{location: location}
	}
	return &PinnedTimezoneResolver{version: version, digest: digest, zones: copyZones}, nil
}

func (resolver *PinnedTimezoneResolver) ResolveCivil(ctx context.Context, civil CivilTime, assertion TimezoneAssertion) (TimezoneResolution, error) {
	if err := checkContext(ctx); err != nil {
		return TimezoneResolution{}, err
	}
	if resolver == nil || !validCivil(civil) || !civilAligned(civil) || !validTimezone(assertion) {
		return TimezoneResolution{}, newError(InvalidInput, TimezoneUnresolved, nil)
	}
	switch assertion.Kind {
	case MissingTimezone:
		return TimezoneResolution{DSTState: DSTUnresolved, Intervals: []ResolvedInterval{}}, nil
	case ExplicitOffset:
		location := time.FixedZone("source-offset", int(*assertion.OffsetMinutes)*60)
		intervals, err := resolveIntervals(civil, location, assertion.OffsetMinutes)
		if err != nil || len(intervals) != 1 {
			return TimezoneResolution{}, newError(DeniedError, TimezoneMismatch, err)
		}
		return TimezoneResolution{DSTState: DSTNotApplicable, Intervals: intervals}, nil
	case IANA:
		if assertion.TZDataVersion != resolver.version || assertion.TZDataDigest != resolver.digest {
			return TimezoneResolution{}, newError(DeniedError, TimezoneMismatch, nil)
		}
		zone, exists := resolver.zones[assertion.Name]
		if !exists {
			return TimezoneResolution{}, newError(DeniedError, TimezoneUnresolved, nil)
		}
		all, err := resolveIntervals(civil, zone.location, nil)
		if err != nil {
			return TimezoneResolution{}, err
		}
		state := DSTExact
		if len(all) == 0 {
			state = DSTGapState
		} else if len(all) == 2 {
			state = DSTFold
		}
		selected := all
		if assertion.OffsetMinutes != nil {
			selected = selected[:0]
			for _, interval := range all {
				if interval.OffsetMinutes == *assertion.OffsetMinutes {
					selected = append(selected, interval)
				}
			}
			if len(selected) == 0 && state != DSTGapState {
				return TimezoneResolution{}, newError(DeniedError, TimezoneMismatch, nil)
			}
		}
		return TimezoneResolution{DSTState: state, Intervals: selected}, nil
	default:
		return TimezoneResolution{}, newError(DeniedError, TimezoneUnresolved, nil)
	}
}

type utcCandidate struct {
	instant time.Time
	offset  int16
}

func resolveIntervals(civil CivilTime, location *time.Location, offsetFilter *int16) ([]ResolvedInterval, error) {
	startCivil, endCivil, err := civilBounds(civil)
	if err != nil {
		return nil, err
	}
	starts := resolveCandidates(startCivil, location, offsetFilter)
	ends := resolveCandidates(endCivil, location, nil)
	result := make([]ResolvedInterval, 0, len(starts))
	for _, start := range starts {
		end, exists := matchingEnd(start, ends)
		if !exists || end.instant.Before(start.instant) {
			return nil, newError(DeniedError, IntervalInvalid, nil)
		}
		result = append(result, ResolvedInterval{EarliestUTC: start.instant, LatestUTC: end.instant, OffsetMinutes: start.offset})
	}
	slices.SortFunc(result, func(left, right ResolvedInterval) int { return left.EarliestUTC.Compare(right.EarliestUTC) })
	return result, nil
}

func civilBounds(value CivilTime) (CivilTime, CivilTime, error) {
	start := time.Date(value.Year, value.Month, value.Day, value.Hour, value.Minute, value.Second, value.Nanosecond, time.UTC)
	var next time.Time
	switch value.Precision {
	case Nanosecond:
		next = start.Add(time.Nanosecond)
	case Microsecond:
		next = start.Add(time.Microsecond)
	case Millisecond:
		next = start.Add(time.Millisecond)
	case Second:
		next = start.Add(time.Second)
	case Minute:
		next = start.Add(time.Minute)
	case Hour:
		next = start.Add(time.Hour)
	case Day:
		next = start.AddDate(0, 0, 1)
	default:
		return CivilTime{}, CivilTime{}, newError(DeniedError, PrecisionUnknown, nil)
	}
	if next.Year() < 0 || next.Year() > 9999 {
		return CivilTime{}, CivilTime{}, newError(DeniedError, ArithmeticOverflow, nil)
	}
	end := next.Add(-time.Nanosecond)
	return civilFromUTC(start, value.Precision), civilFromUTC(end, value.Precision), nil
}

func civilFromUTC(value time.Time, precision Precision) CivilTime {
	return CivilTime{Year: value.Year(), Month: value.Month(), Day: value.Day(), Hour: value.Hour(), Minute: value.Minute(), Second: value.Second(), Nanosecond: value.Nanosecond(), Precision: precision}
}

func resolveCandidates(civil CivilTime, location *time.Location, offsetFilter *int16) []utcCandidate {
	probe := time.Date(civil.Year, civil.Month, civil.Day, civil.Hour, civil.Minute, civil.Second, civil.Nanosecond, location)
	offsets := make(map[int]struct{}, 4)
	for _, delta := range []time.Duration{-36 * time.Hour, -6 * time.Hour, 0, 6 * time.Hour, 36 * time.Hour} {
		_, offset := probe.Add(delta).Zone()
		offsets[offset] = struct{}{}
	}
	wallUTC := time.Date(civil.Year, civil.Month, civil.Day, civil.Hour, civil.Minute, civil.Second, civil.Nanosecond, time.UTC)
	result := make([]utcCandidate, 0, 2)
	for offset := range offsets {
		if offset%60 != 0 || offset/60 < -840 || offset/60 > 840 || offsetFilter != nil && int16(offset/60) != *offsetFilter {
			continue
		}
		candidate := wallUTC.Add(-time.Duration(offset) * time.Second)
		local := candidate.In(location)
		if sameCivil(local, civil) {
			result = append(result, utcCandidate{instant: candidate.UTC(), offset: int16(offset / 60)})
		}
	}
	slices.SortFunc(result, func(left, right utcCandidate) int { return left.instant.Compare(right.instant) })
	return result
}

func matchingEnd(start utcCandidate, ends []utcCandidate) (utcCandidate, bool) {
	for _, end := range ends {
		if end.offset == start.offset && !end.instant.Before(start.instant) {
			return end, true
		}
	}
	for _, end := range ends {
		if !end.instant.Before(start.instant) {
			return end, true
		}
	}
	return utcCandidate{}, false
}

func sameCivil(value time.Time, civil CivilTime) bool {
	return value.Year() == civil.Year && value.Month() == civil.Month && value.Day() == civil.Day && value.Hour() == civil.Hour &&
		value.Minute() == civil.Minute && value.Second() == civil.Second && value.Nanosecond() == civil.Nanosecond
}
