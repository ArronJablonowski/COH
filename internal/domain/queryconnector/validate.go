package queryconnector

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func validateCapability(value CapabilitySnapshot) error {
	if value.SchemaVersion != CapabilitySchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.SnapshotID) || !tokenPattern.MatchString(value.SourceID) ||
		!tokenPattern.MatchString(value.AdapterVersion) || !digestPattern.MatchString(value.SourceIdentityDigest) ||
		!validTimes(value.ObservedAt, value.ValidUntil) || !validTokens(value.QueryLanguages, 32) ||
		!validLimits(value.HardLimits) || !value.Features.ReadOnly || !value.Features.Validation {
		return NewError(InvalidInput, "capability_invalid", nil)
	}
	return nil
}

func validateQuery(value Query) error {
	if value.SchemaVersion != QuerySchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.QueryID) || !validScope(value.Scope) || !validAuthority(value.Authority) ||
		!digestPattern.MatchString(value.CapabilityDigest) || !digestPattern.MatchString(value.SchemaDigest) ||
		!tokenPattern.MatchString(value.Language) || strings.TrimSpace(value.NativeText) == "" || len(value.NativeText) > 262144 ||
		!validTimes(value.TimeRange.Start, value.TimeRange.End) || !validLimits(value.Limits) ||
		!validTimes(value.RequestedAt, value.Deadline) {
		return NewError(InvalidInput, "query_invalid", nil)
	}
	return nil
}

func validateValidation(value ValidationResult) error {
	if value.SchemaVersion != ValidationSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.QueryID) || !oneOf(value.Outcome, "accepted", "denied") ||
		!tokenPattern.MatchString(value.ValidatorVersion) || !digestPattern.MatchString(value.CanonicalQueryDigest) ||
		!digestPattern.MatchString(value.ProvenanceDigest) || !validReasons(value.ReasonCodes) ||
		(value.Outcome == "accepted" && len(value.ReasonCodes) != 0) || (value.Outcome == "denied" && len(value.ReasonCodes) == 0) {
		return NewError(InvalidInput, "validation_invalid", nil)
	}
	return nil
}

func validateExecution(value Execution) error {
	if value.SchemaVersion != ExecutionSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.QueryID) || !uuidPattern.MatchString(value.AttemptID) ||
		!validHandle(value.Handle) || !oneOf(value.Outcome, "queued", "running") || !validTimestamp(value.StartedAt) ||
		!digestPattern.MatchString(value.ProvenanceDigest) {
		return NewError(InvalidInput, "execution_invalid", nil)
	}
	return nil
}

func validateSchemaPage(value SchemaPage) error {
	if value.SchemaVersion != SchemaSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !digestPattern.MatchString(value.SchemaDigest) ||
		!digestPattern.MatchString(value.ProvenanceDigest) || len(value.Entries) == 0 || len(value.Entries) > 4096 ||
		(value.Complete && value.NextCursor != nil) || (!value.Complete && value.NextCursor == nil) {
		return NewError(InvalidInput, "schema_page_invalid", nil)
	}
	for _, entry := range value.Entries {
		if !tokenPattern.MatchString(entry.ResourceID) || !tokenPattern.MatchString(entry.Name) ||
			!oneOf(entry.Type, "string", "integer", "boolean", "timestamp", "ip", "bytes", "object") {
			return NewError(InvalidInput, "schema_entry_invalid", nil)
		}
	}
	if value.NextCursor != nil && !validHandle(*value.NextCursor) {
		return NewError(InvalidInput, "schema_cursor_invalid", nil)
	}
	return nil
}

func validatePoll(value PollResult) error {
	if value.SchemaVersion != PollSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.QueryID) || !uuidPattern.MatchString(value.AttemptID) ||
		!oneOf(value.Outcome, "running", "completed", "partial", "canceled", "failed") ||
		!validCompleteness(value.Completeness) || !validStatistics(value.Statistics) || !digestPattern.MatchString(value.ProvenanceDigest) ||
		(value.Page != nil && validatePage(*value.Page) != nil) || (value.Outcome == "running" && value.Page != nil) {
		return NewError(InvalidInput, "poll_invalid", nil)
	}
	return nil
}

func validatePage(value ResultPage) error {
	if value.SchemaVersion != PageSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.QueryID) || !uuidPattern.MatchString(value.AttemptID) || value.PageNumber == 0 ||
		len(value.Rows) > 100000 || !digestPattern.MatchString(value.ResultDigest) ||
		!validCompleteness(value.Completeness) || !validStatistics(value.Statistics) || !digestPattern.MatchString(value.ProvenanceDigest) {
		return NewError(InvalidInput, "page_invalid", nil)
	}
	if value.NextPage != nil && !validHandle(*value.NextPage) {
		return NewError(InvalidInput, "page_handle_invalid", nil)
	}
	return nil
}

func validateCancellation(value Cancellation) error {
	if value.SchemaVersion != CancellationVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.QueryID) || !uuidPattern.MatchString(value.AttemptID) ||
		!oneOf(value.Outcome, "requested", "confirmed", "uncertain") || !validTimestamp(value.RequestedAt) ||
		!digestPattern.MatchString(value.ProvenanceDigest) || (value.Outcome == "confirmed") != (value.ConfirmedAt != nil) ||
		(value.ConfirmedAt != nil && !validTimestamp(*value.ConfirmedAt)) {
		return NewError(InvalidInput, "cancellation_invalid", nil)
	}
	return nil
}

func validScope(value Scope) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID) && tokenPattern.MatchString(value.SourceID) && validTokens(value.ResourceIDs, 4096)
}

func validAuthority(value AuthorityBinding) bool {
	return uuidPattern.MatchString(value.ActorID) && digestPattern.MatchString(value.AuthorizationDigest) &&
		digestPattern.MatchString(value.PolicyDecisionDigest) && digestPattern.MatchString(value.AuditReservationDigest)
}

func validLimits(value Limits) bool {
	return value.MaximumRows > 0 && value.MaximumBytes > 0 && value.MaximumDurationMillis > 0 &&
		value.MaximumPages > 0 && value.MaximumSlices > 0 && value.MaximumCostMillionths > 0 && value.RequestsPerMinute > 0
}

func validHandle(value HandleRef) bool {
	return uuidPattern.MatchString(value.HandleID) && oneOf(value.Kind, "schema_cursor", "query_job", "result_page") &&
		tokenPattern.MatchString(value.SourceID) && digestPattern.MatchString(value.OpaqueDigest) && validTimes(value.IssuedAt, value.ExpiresAt)
}

func validCompleteness(value Completeness) bool {
	if !oneOf(value.Status, "complete", "partial", "unknown") || !validReasons(value.ReasonCodes) {
		return false
	}
	return (value.Status == "complete" && !value.Partial && !value.Truncated && len(value.ReasonCodes) == 0) ||
		(value.Status == "partial" && value.Partial && len(value.ReasonCodes) > 0) ||
		(value.Status == "unknown" && !value.VendorConfirmed && len(value.ReasonCodes) > 0)
}

func validStatistics(value Statistics) bool {
	return value.RowsReturned <= value.RowsScanned && value.PagesReturned > 0 && value.SlicesCompleted > 0
}

func validReasons(values []string) bool {
	if len(values) > 64 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !reasonPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validTokens(values []string, maximum int) bool {
	if len(values) == 0 || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	return err == nil && parsed.Format("2006-01-02T15:04:05.000000000Z") == value
}

func validTimes(start, end string) bool {
	if !validTimestamp(start) || !validTimestamp(end) {
		return false
	}
	first, _ := time.Parse("2006-01-02T15:04:05.000000000Z", start)
	last, _ := time.Parse("2006-01-02T15:04:05.000000000Z", end)
	return first.Before(last)
}

func oneOf(value string, values ...string) bool { return slices.Contains(values, value) }
