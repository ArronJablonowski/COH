package approvallifecycle

// ValidateTransition proves that next is one permitted optimistic revision of
// previous. Exact retries are handled by the persistence idempotency contract,
// so an equal revision is never a new transition.
func ValidateTransition(previous, next Record) error {
	if err := ValidateRecord(previous); err != nil {
		return err
	}
	if err := ValidateRecord(next); err != nil {
		return err
	}
	if next.Revision != previous.Revision+1 {
		return NewError(Conflict, "stale_revision")
	}
	if !sameBinding(previous, next) {
		return NewError(Denied, "approval_binding_changed")
	}
	previousUpdated, _ := parseTimestamp(previous.UpdatedAt)
	nextUpdated, _ := parseTimestamp(next.UpdatedAt)
	if nextUpdated.Before(previousUpdated) {
		return NewError(Denied, "time_regression")
	}
	if terminal(previous.State) {
		return NewError(Denied, "terminal_state")
	}
	if !sameGrantPrefix(previous.Grants, next.Grants) {
		return NewError(Denied, "grant_history_changed")
	}
	switch previous.State {
	case Requested:
		return validateRequestedTransition(previous, next)
	case Granted:
		return validateGrantedTransition(previous, next)
	default:
		return NewError(Denied, "transition_denied")
	}
}

func validateRequestedTransition(previous, next Record) error {
	switch next.State {
	case Requested, Granted:
		if len(next.Grants) != len(previous.Grants)+1 || next.UseCount != 0 {
			return NewError(Denied, "grant_transition_invalid")
		}
		thresholdReached := len(next.Grants) == int(next.RequiredGrantCount)
		if thresholdReached != (next.State == Granted) {
			return NewError(Denied, "grant_threshold_invalid")
		}
		return nil
	case Rejected, Expired, Revoked:
		if len(next.Grants) != len(previous.Grants) || next.UseCount != 0 {
			return NewError(Denied, "disposition_transition_invalid")
		}
		return nil
	default:
		return NewError(Denied, "transition_denied")
	}
}

func validateGrantedTransition(previous, next Record) error {
	switch next.State {
	case Granted, Consumed:
		if len(next.Grants) != len(previous.Grants) || next.UseCount != previous.UseCount+1 {
			return NewError(Denied, "consume_transition_invalid")
		}
		exhausted := next.UseCount == next.MaximumUseCount
		if exhausted != (next.State == Consumed) {
			return NewError(Denied, "consume_limit_invalid")
		}
		return nil
	case Expired, Revoked:
		if len(next.Grants) != len(previous.Grants) || next.UseCount != previous.UseCount {
			return NewError(Denied, "disposition_transition_invalid")
		}
		return nil
	default:
		return NewError(Denied, "transition_denied")
	}
}

func sameBinding(left, right Record) bool {
	return left.SchemaVersion == right.SchemaVersion && left.ContractVersion == right.ContractVersion &&
		left.ApprovalID == right.ApprovalID && left.OrganizationID == right.OrganizationID &&
		left.TenantID == right.TenantID && left.CaseID == right.CaseID &&
		left.FingerprintDigest == right.FingerprintDigest && left.ManifestDigest == right.ManifestDigest &&
		left.PolicyDecisionDigest == right.PolicyDecisionDigest && left.RequestorActorID == right.RequestorActorID &&
		left.RequestorRevision == right.RequestorRevision && left.ActionOwnerActorID == right.ActionOwnerActorID && left.RequestedAt == right.RequestedAt &&
		left.ValidFrom == right.ValidFrom && left.ValidUntil == right.ValidUntil &&
		left.RequiredGrantCount == right.RequiredGrantCount && left.MaximumUseCount == right.MaximumUseCount
}

func sameGrantPrefix(left, right []Grant) bool {
	if len(right) < len(left) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func terminal(state State) bool {
	return state == Rejected || state == Expired || state == Consumed || state == Revoked
}
