package broker

import (
	"context"
	"errors"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/toolroute"
)

type routeMemoryStore struct {
	key       string
	current   toolRouteRecord
	history   []toolRouteRecord
	saveCalls int
	failSave  int
}

func (store *routeMemoryStore) lookup(_ context.Context, scope domain.CaseRef,
	operationID string) (toolRouteRecord, bool, error) {
	if store.current.OperationID == "" {
		return toolRouteRecord{}, false, nil
	}
	if store.current.OperationID != operationID || store.current.Case != scope {
		return toolRouteRecord{}, false, nil
	}
	return store.current, true, nil
}

func (store *routeMemoryStore) begin(_ context.Context, key string,
	candidate toolRouteRecord) (toolRouteRecord, bool, error) {
	if store.current.OperationID != "" {
		return store.current, true, nil
	}
	if err := validateToolRouteRecord(candidate); err != nil {
		return toolRouteRecord{}, false, err
	}
	store.key, store.current = key, candidate
	store.history = append(store.history, candidate)
	return candidate, false, nil
}

func (store *routeMemoryStore) save(_ context.Context, _ string, prior,
	next toolRouteRecord) (toolRouteRecord, error) {
	store.saveCalls++
	if store.failSave == store.saveCalls {
		return toolRouteRecord{}, errors.New("injected route save failure")
	}
	if prior != store.current {
		return toolRouteRecord{}, errors.New("route revision conflict")
	}
	if err := validateToolRouteTransition(prior, next); err != nil {
		return toolRouteRecord{}, err
	}
	store.current = next
	store.history = append(store.history, next)
	return next, nil
}

type routeContextStub struct {
	command preDispatchCommand
	err     error
	calls   int
	cancel  context.CancelFunc
}

func (resolver *routeContextStub) resolveToolRoute(_ context.Context, _ domain.ToolIntent,
	_ string) (preDispatchCommand, error) {
	resolver.calls++
	if resolver.cancel != nil {
		resolver.cancel()
	}
	return resolver.command, resolver.err
}

type routeStopStub struct {
	err    error
	failAt int
	calls  int
}

func (guard *routeStopStub) Allow(context.Context, string, string, string) error {
	guard.calls++
	if guard.failAt != 0 && guard.calls != guard.failAt {
		return nil
	}
	return guard.err
}

type routeConnectorStub struct {
	receipt domain.ActionReceipt
	err     error
	calls   int
}

func (gateway *routeConnectorStub) Dispatch(_ context.Context, _ domain.ToolIntent) (domain.ActionReceipt, error) {
	gateway.calls++
	return gateway.receipt, gateway.err
}

type toolRouteFixture struct {
	authority   *toolRouteAuthority
	predispatch *preDispatchFixture
	store       *routeMemoryStore
	resolver    *routeContextStub
	stop        *routeStopStub
	connector   *routeConnectorStub
	intent      domain.ToolIntent
}

func newToolRouteFixture(t *testing.T) *toolRouteFixture {
	return newToolRouteFixtureTier(t, "T2")
}

func newToolRouteFixtureTier(t *testing.T, tier string) *toolRouteFixture {
	t.Helper()
	predispatch := newPreDispatchFixture(t, tier)
	intent := domain.ToolIntent{OperationID: workflowTaskID, Case: caseRef(), Tool: "gate.tool",
		Action: "execute", TargetDigest: gateDigest("1"), ArgumentDigest: gateDigest("2")}
	intentDigest, err := toolroute.Digest(intent)
	if err != nil {
		t.Fatal(err)
	}
	store := &routeMemoryStore{}
	resolver := &routeContextStub{command: predispatch.command}
	stop := &routeStopStub{}
	gateway := &routeConnectorStub{receipt: domain.ActionReceipt{IntentDigest: intentDigest, Outcome: "succeeded",
		Evidence: domain.ArtifactRef{Digest: gateDigest("b"), MediaType: "application/json",
			Classification: "restricted", Length: 42}}}
	authority, err := newToolRouteAuthority(store, resolver, predispatch.gate, stop, gateway,
		predispatch.audit, &fakeClock{now: testTime},
		toolRouteIdentity{ActorID: ownerID, ActorRevision: owner().Revision})
	if err != nil {
		t.Fatal(err)
	}
	return &toolRouteFixture{authority: authority, predispatch: predispatch, store: store,
		resolver: resolver, stop: stop, connector: gateway, intent: intent}
}
