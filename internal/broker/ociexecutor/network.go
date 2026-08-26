package ociexecutor

import (
	"context"
	"time"
)

// NoNetworkBroker is the production broker for signed network mode none. Any
// connected policy requires a separately configured enforcement broker.
type NoNetworkBroker struct{ clock Clock }

func NewNoNetworkBroker(clock Clock) (*NoNetworkBroker, error) {
	if clock == nil {
		return nil, NewError(InvalidInput, "network_broker_clock")
	}
	return &NoNetworkBroker{clock: clock}, nil
}

func (broker *NoNetworkBroker) Acquire(ctx context.Context, request NetworkRequest) (NetworkLease, error) {
	if broker == nil || broker.clock == nil {
		return NetworkLease{}, NewError(Unavailable, "network_broker_unavailable")
	}
	if err := contextError(ctx); err != nil {
		return NetworkLease{}, err
	}
	if request.Policy.Mode != "none" || !validNetworkPolicy(request.Policy) ||
		request.PolicyDigest != digestBytes(canonicalBytes(request.Policy)) {
		return NetworkLease{}, NewError(Denied, "network_policy_not_supported")
	}
	authorityUntil, err := time.Parse(time.RFC3339Nano, request.AuthorityUntil)
	if err != nil {
		return NetworkLease{}, NewError(Denied, "network_authority")
	}
	now := broker.clock.Now().UTC()
	if now.IsZero() || !now.Before(authorityUntil) {
		return NetworkLease{}, NewError(Denied, "network_authority")
	}
	return NetworkLease{LeaseID: request.AttemptID, Request: request, EngineNetwork: "none",
		EnforcementDigest: digestBytes(canonicalBytes(struct {
			Mode   string
			Policy string
		}{Mode: "none", Policy: request.PolicyDigest})),
		AuthorizedAt: formatTime(now), ValidUntil: request.AuthorityUntil, Cleanup: func() error { return nil }}, nil
}
