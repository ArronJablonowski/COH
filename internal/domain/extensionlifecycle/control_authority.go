package extensionlifecycle

import (
	"context"
	"errors"
	"time"
)

const MaximumEStopObservationAge = 30 * time.Second

// ControlAuthority is fresh authenticated command-root input. Intent data
// cannot assert these facts, and this value is deliberately not serializable.
type ControlAuthority struct {
	ObservedAt                  time.Time
	ExpiresAt                   time.Time
	ActorID                     string
	ActorKind                   string
	OrganizationID              string
	TenantID                    string
	ActorRevision               uint64
	Authenticated               bool
	Active                      bool
	Administrator               bool
	LifecycleAllowed            bool
	ProductionAgent             bool
	AuthorizationDecisionDigest string
}

// EStopObservation is read through the broker control boundary immediately
// before lifecycle execution. It is never accepted from the command payload.
type EStopObservation struct {
	ObservedAt     time.Time
	OrganizationID string
	TenantID       string
	State          string
	Revision       uint64
}

func (ControlAuthority) MarshalJSON() ([]byte, error) {
	return nil, errors.New("extension control authority is not serializable")
}
func (*ControlAuthority) UnmarshalJSON([]byte) error {
	return errors.New("extension control authority is not accepted from JSON")
}
func (EStopObservation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("extension E-stop observation is not serializable")
}
func (*EStopObservation) UnmarshalJSON([]byte) error {
	return errors.New("extension E-stop observation is not accepted from JSON")
}

// VerifyControlAuthority binds the signed administrator intent and admission
// snapshot to the authenticated command-root caller and current broker E-stop.
func VerifyControlAuthority(ctx context.Context, intent ValidatedIntent, authority ControlAuthority,
	estop EStopObservation, admission AuthoritySnapshot, clock Clock,
) error {
	if clock == nil || intent.Digest() == "" {
		return newError(InvalidInput, "control_authority_input")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	now := clock.Now().UTC()
	command := intent.Value()
	if authority.ProductionAgent || authority.ActorKind == "model" || authority.ActorKind == "agent" {
		return newError(Denied, "production_agent_lifecycle_denied")
	}
	if authority.ObservedAt.Location() != time.UTC || authority.ExpiresAt.Location() != time.UTC ||
		authority.ObservedAt.After(now) || !now.Before(authority.ExpiresAt) ||
		authority.ExpiresAt.Sub(authority.ObservedAt) > MaximumAuthorityAge ||
		!validUUID7(authority.ActorID) || authority.ActorKind != "administrator" ||
		!validUUID7(authority.OrganizationID) || !validUUID7(authority.TenantID) ||
		authority.ActorRevision == 0 || authority.ActorRevision > MaximumRevision ||
		!authority.Authenticated || !authority.Active || !authority.Administrator || !authority.LifecycleAllowed ||
		!validDigest(authority.AuthorizationDecisionDigest) {
		return newError(Denied, "command_root_authority")
	}
	if command.ActorID != authority.ActorID || command.ActorKind != authority.ActorKind ||
		command.OrganizationID != authority.OrganizationID || command.TenantID != authority.TenantID ||
		admission.Scope.OrganizationID != authority.OrganizationID || admission.Scope.TenantID != authority.TenantID {
		return newError(Denied, "command_root_binding")
	}
	if estop.ObservedAt.Location() != time.UTC || estop.ObservedAt.After(now) ||
		now.Sub(estop.ObservedAt) > MaximumEStopObservationAge || estop.OrganizationID != authority.OrganizationID ||
		estop.TenantID != authority.TenantID || estop.State != "armed" || estop.Revision == 0 ||
		estop.Revision > MaximumRevision || estop.State != command.EStopState || estop.Revision != command.EStopRevision ||
		estop.State != admission.EStopState || estop.Revision != admission.EStopRevision {
		return newError(Denied, "broker_estop_boundary")
	}
	return contextError(ctx)
}
