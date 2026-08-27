package querybounds

import (
	"regexp"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func validateAuthority(authority AuthoritySnapshot, now time.Time) error {
	if !uuidPattern.MatchString(authority.OrganizationID) || !uuidPattern.MatchString(authority.TenantID) ||
		!uuidPattern.MatchString(authority.CaseID) || !uuidPattern.MatchString(authority.ActorID) ||
		!tokenPattern.MatchString(authority.SourceID) || authority.ActorRevision == 0 || authority.SourceRevision == 0 ||
		authority.AllowlistRevision == 0 || authority.CapabilityRevision == 0 || authority.PolicyRevision == 0 ||
		authority.RevocationRevision == 0 || !validResources(authority.ResourceIDs) ||
		!digestPattern.MatchString(authority.CapabilityDigest) ||
		!digestPattern.MatchString(authority.AuthorizationDecisionDigest) ||
		!digestPattern.MatchString(authority.PolicyDecisionDigest) ||
		!digestPattern.MatchString(authority.AuditReservationDigest) || authority.ObservedAt.IsZero() || now.IsZero() ||
		authority.MaximumInterval <= 0 || authority.MaximumFutureSkew < 0 ||
		authority.MaximumFutureSkew > MaximumFutureSkewLimit || !validLimits(authority.MaximumLimits) {
		return newError(InvalidInput, "authority_invalid", nil)
	}
	if authority.ApprovalRequired {
		if !digestPattern.MatchString(authority.ApprovalDecisionDigest) ||
			!digestPattern.MatchString(authority.ApprovalQueryDigest) ||
			!digestPattern.MatchString(authority.ApprovalPolicyDecisionDigest) || authority.ApprovalExpiresAt.IsZero() {
			return newError(InvalidInput, "approval_authority_invalid", nil)
		}
	} else if authority.ApprovalAllowed || authority.ApprovalDecisionDigest != "" || authority.ApprovalQueryDigest != "" ||
		authority.ApprovalPolicyDecisionDigest != "" || !authority.ApprovalExpiresAt.IsZero() {
		return newError(InvalidInput, "approval_authority_invalid", nil)
	}
	observed := authority.ObservedAt.UTC()
	if observed.After(now.Add(5*time.Second)) || now.Sub(observed) > MaximumAuthorityAge {
		return newError(Denied, "authority_stale", nil)
	}
	return nil
}

func validateDecision(value Decision) error {
	start, startErr := time.Parse("2006-01-02T15:04:05.000000000Z", value.IntervalStart)
	end, endErr := time.Parse("2006-01-02T15:04:05.000000000Z", value.IntervalEnd)
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion || value.DecisionDigest != "" ||
		!uuidPattern.MatchString(value.QueryID) || !digestPattern.MatchString(value.QueryDigest) ||
		!oneOf(value.Outcome, "allowed", "denied", "invalid", "unavailable") || !reasonPattern.MatchString(value.ReasonCode) ||
		!uuidPattern.MatchString(value.OrganizationID) || !uuidPattern.MatchString(value.TenantID) ||
		!uuidPattern.MatchString(value.CaseID) || !uuidPattern.MatchString(value.ActorID) ||
		!tokenPattern.MatchString(value.SourceID) || !digestPattern.MatchString(value.CapabilityDigest) ||
		!digestPattern.MatchString(value.AuthorityDigest) || !digestPattern.MatchString(value.ResourceScopeDigest) ||
		!digestPattern.MatchString(value.AuthorizationDecisionDigest) || !digestPattern.MatchString(value.PolicyDecisionDigest) ||
		!digestPattern.MatchString(value.AuditReservationDigest) ||
		startErr != nil || endErr != nil || !start.Before(end) ||
		!digestPattern.MatchString(value.LimitsDigest) || !validTimestamp(value.EvaluatedAt) ||
		(value.ApprovalDecisionDigest != "" && !digestPattern.MatchString(value.ApprovalDecisionDigest)) ||
		(value.Replayed && value.Outcome != "allowed") {
		return newError(InvalidInput, "decision_invalid", nil)
	}
	if value.Outcome == "allowed" && (value.ActorRevision == 0 || value.SourceRevision == 0 || value.AllowlistRevision == 0 ||
		value.CapabilityRevision == 0 || value.PolicyRevision == 0 || value.RevocationRevision == 0 ||
		(value.ApprovalRequired && !digestPattern.MatchString(value.ApprovalDecisionDigest)) ||
		(!value.ApprovalRequired && value.ApprovalDecisionDigest != "")) {
		return newError(InvalidInput, "decision_invalid", nil)
	}
	return nil
}

func validResources(values []string) bool {
	if len(values) == 0 || len(values) > 4096 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}

func validLimits(value queryconnector.Limits) bool {
	return value.MaximumRows > 0 && value.MaximumBytes > 0 && value.MaximumDurationMillis > 0 &&
		value.MaximumPages > 0 && value.MaximumSlices > 0 && value.MaximumCostMillionths > 0 && value.RequestsPerMinute > 0
}

func withinLimits(request, maximum queryconnector.Limits) bool {
	return request.MaximumRows <= maximum.MaximumRows && request.MaximumBytes <= maximum.MaximumBytes &&
		request.MaximumDurationMillis <= maximum.MaximumDurationMillis && request.MaximumPages <= maximum.MaximumPages &&
		request.MaximumSlices <= maximum.MaximumSlices && request.MaximumCostMillionths <= maximum.MaximumCostMillionths &&
		request.RequestsPerMinute <= maximum.RequestsPerMinute
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	return err == nil && parsed.Format("2006-01-02T15:04:05.000000000Z") == value
}

func oneOf(value string, values ...string) bool { return slices.Contains(values, value) }

func sameStrings(left, right []string) bool { return slices.Equal(left, right) }

func nonSecretReason(err error) (ErrorCode, string) {
	if code, reason := Code(err), Reason(err); code != "" && reasonPattern.MatchString(reason) {
		return code, reason
	}
	return Unavailable, "dependency_unavailable"
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }
