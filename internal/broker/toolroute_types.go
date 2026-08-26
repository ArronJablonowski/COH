package broker

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector"
	"github.com/ArronJablonowski/COH/internal/domain"
)

const toolRouteRecordVersion = "coh.tool-route-state/v1"

type toolRouteStatus string

const (
	routePending     toolRouteStatus = "pending"
	routeAuthorizing toolRouteStatus = "authorizing"
	routeDispatching toolRouteStatus = "dispatching"
	routeSucceeded   toolRouteStatus = "succeeded"
	routeDenied      toolRouteStatus = "denied"
	routeCanceled    toolRouteStatus = "canceled"
	routeTimeout     toolRouteStatus = "timeout"
	routeFailed      toolRouteStatus = "failed"
	routeUncertain   toolRouteStatus = "uncertain"
)

type toolRouteRecord struct {
	RecordVersion              string
	OperationID                string
	Case                       domain.CaseRef
	IntentDigest               string
	IdempotencyDigest          string
	ContextDigest              string
	ManifestDigest             string
	IntentPolicyDecisionDigest string
	PreDispatchDecisionDigest  string
	ApprovalID                 string
	ApprovalRevision           uint64
	ApprovalFingerprintDigest  string
	RequestorActorID           string
	RequestorActorRevision     uint64
	ActionOwnerActorID         string
	ActionOwnerActorRevision   uint64
	Status                     toolRouteStatus
	ReasonCode                 string
	DispatchAuditID            string
	CompletionAuditID          string
	Receipt                    domain.ActionReceipt
	ReceiptDigest              string
	PreviousProvenanceDigest   string
	ProvenanceDigest           string
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
	Revision                   uint64
}

type toolRouteIdentity struct {
	ActorID       string
	ActorRevision uint64
}

type toolRouteStore interface {
	lookup(context.Context, domain.CaseRef, string) (toolRouteRecord, bool, error)
	begin(context.Context, string, toolRouteRecord) (toolRouteRecord, bool, error)
	save(context.Context, string, toolRouteRecord, toolRouteRecord) (toolRouteRecord, error)
}

type toolRouteContextResolver interface {
	resolveToolRoute(context.Context, domain.ToolIntent, string) (preDispatchCommand, error)
}

type toolRouteStopGuard interface {
	Allow(context.Context, string, string, string) error
}

type toolRouteAuthority struct {
	store     toolRouteStore
	resolver  toolRouteContextResolver
	gate      *preDispatchGate
	stop      toolRouteStopGuard
	connector connector.Gateway
	audit     preDispatchAuditAppender
	clock     approvalClock
	identity  toolRouteIdentity
}

func newToolRouteAuthority(store toolRouteStore, resolver toolRouteContextResolver, gate *preDispatchGate,
	stop toolRouteStopGuard, gateway connector.Gateway, audit preDispatchAuditAppender, clock approvalClock,
	identity toolRouteIdentity) (*toolRouteAuthority, error) {
	if store == nil || resolver == nil || gate == nil || stop == nil || gateway == nil || audit == nil || clock == nil ||
		!uuidPattern.MatchString(identity.ActorID) || identity.ActorRevision == 0 {
		return nil, newRouteError(routeCodeInvalidInput, "route_dependencies", false, nil)
	}
	return &toolRouteAuthority{store: store, resolver: resolver, gate: gate, stop: stop,
		connector: gateway, audit: audit, clock: clock, identity: identity}, nil
}

var _ Authority = (*toolRouteAuthority)(nil)
