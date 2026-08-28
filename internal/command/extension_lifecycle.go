package command

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/broker"
	"github.com/ArronJablonowski/COH/internal/domain/extensionlifecycle"
)

// ExtensionLifecycleRequest contains only strictly decoded immutable command
// data. The resolver must derive authority from authenticated control-plane
// state; it must not trust identity or authority claims in these documents.
type ExtensionLifecycleRequest struct {
	Envelope extensionlifecycle.ValidatedEnvelope
	Intent   extensionlifecycle.ValidatedIntent
}

type ExtensionLifecycleAuthorization struct {
	Control   extensionlifecycle.ControlAuthority
	Admission extensionlifecycle.AuthoritySnapshot
}

type ExtensionLifecycleAuthority interface {
	ResolveExtensionLifecycle(context.Context, ExtensionLifecycleRequest) (ExtensionLifecycleAuthorization, error)
}

type ExtensionLifecycleResult struct {
	Operation    string
	Activation   extensionlifecycle.ActivationResult
	Deactivation extensionlifecycle.DeactivationResult
}

// ExtensionLifecycle is the only production composition entry point. It
// constructs both controllers with the broker-owned effect port, resolves
// fresh administrator authority, and observes E-stop on every invocation and
// restart replay before any lifecycle effect can continue.
type ExtensionLifecycle struct {
	authority    ExtensionLifecycleAuthority
	control      broker.ExtensionLifecycleControl
	activation   *extensionlifecycle.ActivationController
	deactivation *extensionlifecycle.DeactivationController
	clock        extensionlifecycle.Clock
}

func NewExtensionLifecycle(authority ExtensionLifecycleAuthority, control broker.ExtensionLifecycleControl,
	store extensionlifecycle.ActivationStore, audit extensionlifecycle.ActivationAuditPort,
	gate extensionlifecycle.DeactivationGate, clock extensionlifecycle.Clock,
) (*ExtensionLifecycle, error) {
	if authority == nil || control == nil || store == nil || audit == nil || gate == nil || clock == nil {
		return nil, extensionlifecycle.NewInvalidInput("command_root_dependencies")
	}
	activation, err := extensionlifecycle.NewActivationController(store, control, audit, clock)
	if err != nil {
		return nil, err
	}
	deactivation, err := extensionlifecycle.NewDeactivationController(store, control, audit, gate, clock)
	if err != nil {
		return nil, err
	}
	return &ExtensionLifecycle{authority: authority, control: control, activation: activation,
		deactivation: deactivation, clock: clock}, nil
}

func (service *ExtensionLifecycle) Execute(ctx context.Context, envelopeInput, intentInput []byte) (ExtensionLifecycleResult, error) {
	if service == nil || service.authority == nil || service.control == nil || service.activation == nil ||
		service.deactivation == nil || service.clock == nil {
		return ExtensionLifecycleResult{}, extensionlifecycle.NewInvalidInput("command_root_unavailable")
	}
	envelope, err := extensionlifecycle.DecodeEnvelope(ctx, envelopeInput)
	if err != nil {
		return ExtensionLifecycleResult{}, err
	}
	intent, err := extensionlifecycle.DecodeIntent(ctx, intentInput)
	if err != nil {
		return ExtensionLifecycleResult{}, err
	}
	authorization, err := service.authority.ResolveExtensionLifecycle(ctx, ExtensionLifecycleRequest{Envelope: envelope, Intent: intent})
	if err != nil {
		return ExtensionLifecycleResult{}, extensionlifecycle.NewUnavailable("command_root_authority_unavailable")
	}
	command := intent.Value()
	estop, err := service.control.ObserveExtensionEStop(ctx, extensionlifecycle.ExactScope{
		OrganizationID: command.OrganizationID, TenantID: command.TenantID,
	})
	if err != nil {
		return ExtensionLifecycleResult{}, extensionlifecycle.NewUnavailable("broker_estop_unavailable")
	}
	if err := extensionlifecycle.VerifyControlAuthority(ctx, intent, authorization.Control, estop,
		authorization.Admission, service.clock); err != nil {
		return ExtensionLifecycleResult{}, err
	}
	admission, err := extensionlifecycle.VerifyAdmission(ctx, envelope.CanonicalBytes(), intent.CanonicalBytes(),
		authorization.Admission, service.clock)
	if err != nil {
		return ExtensionLifecycleResult{}, err
	}
	result := ExtensionLifecycleResult{Operation: command.Operation}
	switch command.Operation {
	case "activate":
		result.Activation, err = service.activation.Activate(ctx, admission)
	case "deactivate":
		result.Deactivation, err = service.deactivation.Deactivate(ctx, admission)
	default:
		err = extensionlifecycle.NewDenied("lifecycle_operation")
	}
	if err != nil {
		return ExtensionLifecycleResult{}, err
	}
	return result, nil
}
