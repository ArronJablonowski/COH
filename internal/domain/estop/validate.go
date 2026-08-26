package estop

import (
	"strings"
	"time"
)

func ValidateScope(scope Scope) error {
	if !validUUID(scope.OrganizationID) || !validUUID(scope.TenantID) {
		return NewError(InvalidInput, "scope_invalid")
	}
	switch scope.Kind {
	case "global":
		if scope.CaseID != "" {
			return NewError(InvalidInput, "global_scope_invalid")
		}
	case "case":
		if !validUUID(scope.CaseID) {
			return NewError(InvalidInput, "case_scope_invalid")
		}
	default:
		return NewError(InvalidInput, "scope_kind_invalid")
	}
	return nil
}

func ValidateCommand(command Command) error {
	if command.SchemaVersion != CommandSchemaVersion || command.ContractVersion != ContractVersion {
		return NewError(Denied, "unsupported_command_contract")
	}
	if !validUUID(command.RequestID) || !validOpaque(command.IdempotencyKey, 1, 128) ||
		!validUUID(command.ActorID) || !validReason(command.ReasonCode) {
		return NewError(InvalidInput, "command_identity_invalid")
	}
	return ValidateScope(command.Scope)
}

func ValidateAuthority(authority Authority, now time.Time) error {
	if err := ValidateScope(authority.Scope); err != nil {
		return err
	}
	if !validUUID(authority.ActorID) || authority.ActorRevision == 0 ||
		!validDigest(authority.AuthorizationDecisionDigest) || !validDigest(authority.PolicyDecisionDigest) ||
		authority.ObservedAt.IsZero() || now.IsZero() {
		return NewError(InvalidInput, "authority_invalid")
	}
	if !authority.ActorActive {
		return NewError(Denied, "actor_revoked")
	}
	if !authority.AuthorizationAllowed {
		return NewError(Denied, "authorization_denied")
	}
	if !authority.PolicyAllowed {
		return NewError(Denied, "policy_denied")
	}
	observed := authority.ObservedAt.UTC()
	if observed.After(now.Add(5*time.Second)) || now.Sub(observed) > MaximumAuthorityAge {
		return NewError(Denied, "authority_stale")
	}
	return nil
}

func ValidateState(state State) error {
	if state.SchemaVersion != StateSchemaVersion || state.ContractVersion != ContractVersion ||
		ValidateScope(state.Scope) != nil || state.Epoch == 0 || !state.Active || !validUUID(state.RequestID) ||
		!validDigest(state.RequestDigest) || !validUUID(state.ActorID) || state.ActorRevision == 0 ||
		!validReason(state.ReasonCode) || !validDigest(state.AuthorizationDecisionDigest) ||
		!validDigest(state.PolicyDecisionDigest) || state.ActivatedAt.IsZero() {
		return NewError(InvalidInput, "state_invalid")
	}
	return nil
}

func ValidateAcknowledgement(ack Acknowledgement) error {
	if ack.SchemaVersion != AckSchemaVersion || ack.ContractVersion != ContractVersion ||
		ValidateScope(ack.Scope) != nil || ack.Epoch == 0 || !validToken(ack.ControlID) ||
		!validControlKind(ack.ControlKind) || !validControlOutcome(ack.Outcome) ||
		!validToken(ack.ReasonCode) || ack.StartedAt.IsZero() || ack.CompletedAt.IsZero() ||
		ack.CompletedAt.Before(ack.StartedAt) || ack.ElapsedNanos < 0 || ack.ObjectiveNanos <= 0 {
		return NewError(InvalidInput, "control_ack_invalid")
	}
	if ack.Outcome == "applied" && !validDigest(ack.EvidenceDigest) {
		return NewError(InvalidInput, "control_evidence_invalid")
	}
	if ack.Outcome != "applied" && ack.EvidenceDigest != "" {
		return NewError(InvalidInput, "control_evidence_invalid")
	}
	return nil
}

func ControlObjective(kind string) (time.Duration, bool) {
	switch kind {
	case "credential", "lease":
		return LeaseRejectObjective, true
	case "egress":
		return EgressCutObjective, true
	case "remote_job", "workflow":
		return WorkflowSignalObjective, true
	case "cooperative":
		return TerminationObjective, true
	default:
		return 0, false
	}
}

func validControlKind(value string) bool {
	_, ok := ControlObjective(value)
	return ok
}

func validControlOutcome(value string) bool {
	return value == "applied" || value == "failed" || value == "timeout"
}

func validReason(value string) bool {
	switch value {
	case "operator_emergency", "safety_watch_expired", "runner_heartbeat_lost", "policy_emergency", "incident_containment":
		return true
	default:
		return false
	}
}

func validUUID(value string) bool {
	if len(value) != 36 || value[14] != '7' || !strings.Contains("89ab", value[19:20]) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.ToValidUTF8(value, "") == value &&
		!strings.ContainsAny(value, "\r\n\t")
}
