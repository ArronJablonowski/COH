package approvallifecycle

import (
	"regexp"
	"time"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

func ValidateRecord(record Record) error {
	if record.SchemaVersion != SchemaVersion || record.ContractVersion != ContractVersion {
		return NewError(InvalidInput, "unsupported_contract")
	}
	for _, value := range []string{record.ApprovalID, record.OrganizationID, record.TenantID, record.CaseID, record.RequestorActorID, record.RequestorPrincipalID, record.ActionOwnerActorID, record.LastActorID, record.LastEventID} {
		if !uuidPattern.MatchString(value) {
			return NewError(InvalidInput, "invalid_identity")
		}
	}
	for _, value := range []string{record.FingerprintDigest, record.ManifestDigest, record.PolicyDecisionDigest, record.LastOperationDigest} {
		if !digestPattern.MatchString(value) {
			return NewError(InvalidInput, "invalid_digest")
		}
	}
	requestedAt, requestedErr := parseTimestamp(record.RequestedAt)
	validFrom, fromErr := parseTimestamp(record.ValidFrom)
	validUntil, untilErr := parseTimestamp(record.ValidUntil)
	updatedAt, updatedErr := parseTimestamp(record.UpdatedAt)
	if requestedErr != nil || fromErr != nil || untilErr != nil || updatedErr != nil ||
		validUntil.Before(validFrom) || validUntil.Equal(validFrom) || requestedAt.After(updatedAt) {
		return NewError(InvalidInput, "invalid_time_window")
	}
	if record.Revision == 0 || record.RequestorRevision == 0 || record.LastActorRevision == 0 || record.RequiredGrantCount == 0 || record.RequiredGrantCount > 16 ||
		record.MaximumUseCount == 0 || record.MaximumUseCount > 1000 || record.UseCount > record.MaximumUseCount {
		return NewError(InvalidInput, "invalid_counter")
	}
	if !validActionTier(record.ActionTier) || len(record.Grants) > int(record.RequiredGrantCount) || duplicateGrant(record.Grants) {
		return NewError(InvalidInput, "invalid_grants")
	}
	for _, grant := range record.Grants {
		grantedAt, err := parseTimestamp(grant.GrantedAt)
		if !uuidPattern.MatchString(grant.ActorID) || !uuidPattern.MatchString(grant.PrincipalID) || grant.ActorRevision == 0 ||
			grant.EnrollmentRevision == 0 || err != nil || grantedAt.Before(requestedAt) || grantedAt.After(updatedAt) {
			return NewError(InvalidInput, "invalid_grant")
		}
		if grant.ActorID == record.RequestorActorID || grant.PrincipalID == record.RequestorPrincipalID {
			return NewError(Denied, "self_approval")
		}
	}
	if !validState(record.State) || !validStateShape(record) {
		return NewError(InvalidInput, "invalid_state")
	}
	if !tokenPattern.MatchString(record.ReasonCode) {
		return NewError(InvalidInput, "invalid_reason_code")
	}
	return nil
}

func ValidateEvent(event Event) error {
	if event.SchemaVersion != SchemaVersion || event.ContractVersion != ContractVersion || !uuidPattern.MatchString(event.EventID) {
		return NewError(InvalidInput, "invalid_event")
	}
	switch event.Operation {
	case "request", "grant", "reject", "expire", "consume", "revoke":
	default:
		return NewError(InvalidInput, "invalid_event")
	}
	switch event.Outcome {
	case "allowed", "denied", "invalid", "canceled", "timeout", "unavailable":
	default:
		return NewError(InvalidInput, "invalid_event")
	}
	if !tokenPattern.MatchString(event.ReasonCode) {
		return NewError(InvalidInput, "invalid_event")
	}
	if _, err := parseTimestamp(event.OccurredAt); err != nil {
		return NewError(InvalidInput, "invalid_event")
	}
	for _, value := range []string{event.ApprovalID, event.OrganizationID, event.TenantID, event.CaseID, event.ActorID} {
		if value != "" && !uuidPattern.MatchString(value) {
			return NewError(InvalidInput, "invalid_event")
		}
	}
	if event.FingerprintDigest != "" && !digestPattern.MatchString(event.FingerprintDigest) || event.ActorID == "" && event.ActorRevision != 0 {
		return NewError(InvalidInput, "invalid_event")
	}
	return nil
}

func validState(state State) bool {
	switch state {
	case Requested, Granted, Rejected, Expired, Consumed, Revoked:
		return true
	default:
		return false
	}
}

func validStateShape(record Record) bool {
	grantCount := len(record.Grants)
	switch record.State {
	case Requested:
		return grantCount < int(record.RequiredGrantCount) && record.UseCount == 0
	case Granted:
		return grantCount == int(record.RequiredGrantCount) && record.UseCount < record.MaximumUseCount
	case Consumed:
		return grantCount == int(record.RequiredGrantCount) && record.UseCount == record.MaximumUseCount
	case Rejected, Expired:
		return record.UseCount == 0
	case Revoked:
		return record.UseCount < record.MaximumUseCount
	default:
		return false
	}
}

func duplicateGrant(grants []Grant) bool {
	actors := make(map[string]struct{}, len(grants))
	principals := make(map[string]struct{}, len(grants))
	for _, grant := range grants {
		if _, exists := actors[grant.ActorID]; exists {
			return true
		}
		if _, exists := principals[grant.PrincipalID]; exists {
			return true
		}
		actors[grant.ActorID] = struct{}{}
		principals[grant.PrincipalID] = struct{}{}
	}
	return false
}

func validActionTier(value string) bool {
	return value == "T0" || value == "T1" || value == "T2" || value == "T3" || value == "T4"
}

func parseTimestamp(value string) (time.Time, error) { return time.Parse(timestampLayout, value) }
