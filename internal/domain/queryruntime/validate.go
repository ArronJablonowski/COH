package queryruntime

import (
	"crypto/subtle"
	"regexp"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

func validateConfig(config Config) error {
	if config.Interactive.Mode != "interactive" || config.Export.Mode != "export" ||
		!validLimits(config.Interactive.Limits) || !validLimits(config.Export.Limits) ||
		!validPollProfile(config.Interactive) || !validPollProfile(config.Export) ||
		config.MaximumSessions <= 0 || config.MaximumSessions > MaximumSessionCapacity ||
		config.CancellationWait <= 0 || config.CancellationWait > MaximumCancellationWait ||
		config.RecordWait <= 0 || config.RecordWait > MaximumRecordWait {
		return newError(InvalidInput, "configuration_invalid", nil)
	}
	return nil
}

func validateSession(value Session, digestEmpty bool) error {
	if value.SchemaVersion != SessionSchemaVersion || value.ContractVersion != ContractVersion ||
		(digestEmpty && value.SessionDigest != "") || (!digestEmpty && !digestPattern.MatchString(value.SessionDigest)) ||
		!uuidPattern.MatchString(value.SessionID) || value.Revision == 0 || !uuidPattern.MatchString(value.QueryID) ||
		!digestPattern.MatchString(value.QueryDigest) || !digestPattern.MatchString(value.BoundsDecisionDigest) ||
		!digestPattern.MatchString(value.ExecutionDigest) || !uuidPattern.MatchString(value.AttemptID) ||
		!uuidPattern.MatchString(value.OrganizationID) || !uuidPattern.MatchString(value.TenantID) ||
		!uuidPattern.MatchString(value.ActorID) || !tokenPattern.MatchString(value.SourceID) ||
		!oneOf(value.Mode, "interactive", "export") || !validLimits(value.EffectiveLimits) ||
		!oneOf(value.Status, "running", "complete", "partial", "truncated", "canceled", "uncertain", "failed") ||
		!tokenPattern.MatchString(value.ReasonCode) || value.NextPageNumber == 0 || value.PollDelayMillis == 0 ||
		!validTimestamp(value.NextPollAt) ||
		!digestPattern.MatchString(value.JobHandleDigest) || !digestPattern.MatchString(value.VendorProvenanceDigest) ||
		!validOptionalDigest(value.PreviousSessionDigest) || !validOptionalDigest(value.PageHandleDigest) ||
		!validOptionalDigest(value.LastPageDigest) || !validOptionalDigest(value.LastRateReservationDigest) ||
		!validOptionalDigest(value.CancellationIntentDigest) || !validTimes(value.StartedAt, value.Deadline) ||
		!validTimestamp(value.UpdatedAt) || !withinLimits(value.Usage, value.EffectiveLimits) {
		return newError(InvalidInput, "session_invalid", nil)
	}
	started, _ := time.Parse(timestampLayout, value.StartedAt)
	updated, _ := time.Parse(timestampLayout, value.UpdatedAt)
	if updated.Before(started) || (value.Revision == 1) != (value.PreviousSessionDigest == "") ||
		(value.Revision > 1 && !digestPattern.MatchString(value.PreviousSessionDigest)) {
		return newError(InvalidInput, "session_invalid", nil)
	}
	return nil
}

func validPollProfile(value Profile) bool {
	return value.MinimumPollInterval > 0 && value.MinimumPollInterval <= value.MaximumPollInterval &&
		value.MaximumPollInterval <= MaximumPollInterval && value.MinimumPollInterval%time.Millisecond == 0 &&
		value.MaximumPollInterval%time.Millisecond == 0
}

func validateRateReservation(value RateReservation, digestEmpty bool) error {
	if value.SchemaVersion != RateSchemaVersion || value.ContractVersion != ContractVersion ||
		(digestEmpty && value.ReservationDigest != "") || (!digestEmpty && !digestPattern.MatchString(value.ReservationDigest)) ||
		!digestPattern.MatchString(value.KeyDigest) || !uuidPattern.MatchString(value.SessionID) ||
		!oneOf(value.Operation, "poll", "next_page", "cancel", "protective_cancel") || value.Sequence == 0 ||
		!validTimes(value.ReservedAt, value.ValidUntil) {
		return newError(InvalidInput, "rate_reservation_invalid", nil)
	}
	return nil
}

func validateSlicePlan(value SlicePlan, digestEmpty bool) error {
	if value.SchemaVersion != SlicePlanSchemaVersion || value.ContractVersion != ContractVersion ||
		(digestEmpty && value.PlanDigest != "") || (!digestEmpty && !digestPattern.MatchString(value.PlanDigest)) ||
		!uuidPattern.MatchString(value.ParentQueryID) || !digestPattern.MatchString(value.ParentQueryDigest) ||
		!digestPattern.MatchString(value.BoundsDecisionDigest) || len(value.Slices) == 0 || len(value.Slices) > MaximumSliceDescriptors {
		return newError(InvalidInput, "slice_plan_invalid", nil)
	}
	count := uint32(len(value.Slices))
	for index, descriptor := range value.Slices {
		if descriptor.Index != uint32(index+1) || descriptor.Count != count ||
			!digestPattern.MatchString(descriptor.SliceDigest) || !validTimes(descriptor.Start, descriptor.End) ||
			(index > 0 && value.Slices[index-1].End != descriptor.Start) {
			return newError(InvalidInput, "slice_plan_invalid", nil)
		}
		digestInput := struct {
			ParentQueryDigest    string `json:"parent_query_digest"`
			BoundsDecisionDigest string `json:"bounds_decision_digest"`
			Index                uint32 `json:"index"`
			Count                uint32 `json:"count"`
			Start                string `json:"start"`
			End                  string `json:"end"`
		}{value.ParentQueryDigest, value.BoundsDecisionDigest, descriptor.Index, descriptor.Count,
			descriptor.Start, descriptor.End}
		expected, err := canonicalDigest(sliceDigestDomain, digestInput)
		if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(descriptor.SliceDigest)) != 1 {
			return newError(Conflict, "slice_integrity", err)
		}
	}
	return nil
}

func validLimits(value queryconnector.Limits) bool {
	return value.MaximumRows > 0 && value.MaximumBytes > 0 && value.MaximumDurationMillis > 0 &&
		value.MaximumPages > 0 && value.MaximumSlices > 0 && value.MaximumCostMillionths > 0 && value.RequestsPerMinute > 0
}

func withinLimits(usage Usage, limits queryconnector.Limits) bool {
	return usage.RowsReturned <= usage.RowsScanned && usage.RowsReturned <= limits.MaximumRows &&
		usage.BytesReturned <= limits.MaximumBytes && usage.DurationMillis <= limits.MaximumDurationMillis &&
		usage.PagesReturned <= limits.MaximumPages && usage.SlicesCompleted <= limits.MaximumSlices &&
		usage.CostMillionths <= limits.MaximumCostMillionths
}

func validOptionalDigest(value string) bool { return value == "" || digestPattern.MatchString(value) }

func validTimestamp(value string) bool {
	parsed, err := time.Parse(timestampLayout, value)
	return err == nil && parsed.Format(timestampLayout) == value
}

func validTimes(start, end string) bool {
	if !validTimestamp(start) || !validTimestamp(end) {
		return false
	}
	first, _ := time.Parse(timestampLayout, start)
	last, _ := time.Parse(timestampLayout, end)
	return first.Before(last)
}

func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }
