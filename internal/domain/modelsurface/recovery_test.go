package modelsurface

import (
	"context"
	"errors"
	"testing"
)

type transitionStoreStub struct {
	latest   map[string][]byte
	byDigest map[string][]byte
	fail     bool
}

func (store *transitionStoreStub) CreateTransition(_ context.Context, key string, value ValidatedTransition) ([]byte, bool, error) {
	if store.fail {
		return nil, false, errors.New("unavailable")
	}
	if existing, found := store.latest[key]; found {
		return append([]byte(nil), existing...), false, nil
	}
	raw := value.CanonicalBytes()
	store.latest[key] = raw
	store.byDigest[value.Digest()] = raw
	return append([]byte(nil), raw...), true, nil
}
func (store *transitionStoreStub) CompareAndSwapTransition(_ context.Context, key, expected string, value ValidatedTransition) ([]byte, bool, error) {
	if store.fail {
		return nil, false, errors.New("unavailable")
	}
	current, found := store.latest[key]
	if !found {
		return nil, false, nil
	}
	decoded, err := DecodeTransition(context.Background(), current)
	if err != nil || decoded.Digest() != expected {
		return append([]byte(nil), current...), false, nil
	}
	raw := value.CanonicalBytes()
	store.latest[key] = raw
	store.byDigest[value.Digest()] = raw
	return append([]byte(nil), raw...), true, nil
}
func (store *transitionStoreStub) ReadLatestTransition(_ context.Context, key string) ([]byte, bool, error) {
	value, found := store.latest[key]
	return append([]byte(nil), value...), found, nil
}
func (store *transitionStoreStub) ReadTransition(_ context.Context, digest string) ([]byte, bool, error) {
	value, found := store.byDigest[digest]
	return append([]byte(nil), value...), found, nil
}

type recoveryReaderStub struct {
	projections map[string][]byte
	bindings    map[string][]byte
	streams     map[uint64][]byte
}

type projectionReplayerStub struct{ drift bool }

func (stub *projectionReplayerStub) Reproject(_ context.Context, projection Projection) (ProjectedSurface, error) {
	if stub.drift {
		projection.SurfaceDigest = digest('f')
	}
	return ProjectedSurface{projection: projection}, nil
}

func (reader *recoveryReaderStub) ReadProjection(_ context.Context, digest string) ([]byte, bool, error) {
	value, found := reader.projections[digest]
	return append([]byte(nil), value...), found, nil
}
func (reader *recoveryReaderStub) ReadBinding(_ context.Context, digest string) ([]byte, bool, error) {
	value, found := reader.bindings[digest]
	return append([]byte(nil), value...), found, nil
}
func (reader *recoveryReaderStub) ReadStreamEvent(_ context.Context, _, _ string, sequence uint64) ([]byte, bool, error) {
	value, found := reader.streams[sequence]
	return append([]byte(nil), value...), found, nil
}

func TestRecoveryControllerExactReplayAdvanceAndCrashDirectives(t *testing.T) {
	controller, store, records, prepared, binding := newRecoveryFixture(t)
	current, replayed, err := controller.Prepare(context.Background(), "run.recovery", prepared)
	if err != nil || replayed {
		t.Fatalf("prepare replayed=%v err=%v", replayed, err)
	}
	_, replayed, err = controller.Prepare(context.Background(), "run.recovery", prepared)
	if err != nil || !replayed {
		t.Fatalf("replay replayed=%v err=%v", replayed, err)
	}
	changed := prepared
	changed.AttemptID = uuid(60)
	if _, _, err = controller.Prepare(context.Background(), "run.recovery", changed); Reason(err) != "changed_replay" {
		t.Fatalf("changed replay err=%v", err)
	}
	current, err = controller.Advance(context.Background(), "run.recovery", current, AdvanceTransition{TransitionID: uuid(61), Phase: "verified", BindingDigest: binding.BindingDigest, UpdatedAt: timestamp(4)})
	if err != nil {
		t.Fatal(err)
	}
	current, err = controller.Advance(context.Background(), "run.recovery", current, AdvanceTransition{TransitionID: uuid(62), Phase: "dispatched", BindingDigest: binding.BindingDigest, UpdatedAt: timestamp(4)})
	if err != nil {
		t.Fatal(err)
	}
	state, err := controller.Recover(context.Background(), "run.recovery")
	if err != nil || state.Directive != "mark_uncertain" {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	stream := validStream()
	stream.Sequence, stream.ObservedAt = 1, timestamp(5)
	stream.BindingDigest, stream.ProjectionDigest, stream.InputSurfaceDigest = binding.BindingDigest, binding.ProjectionDigest, binding.SurfaceDigest
	raw, _, _ := CanonicalStreamEvent(context.Background(), stream)
	records.streams[1] = raw
	current, err = controller.Advance(context.Background(), "run.recovery", current, AdvanceTransition{TransitionID: uuid(63), Phase: "streaming", BindingDigest: binding.BindingDigest, StreamCursor: 1, UpdatedAt: timestamp(5)})
	if err != nil {
		t.Fatal(err)
	}
	state, err = controller.Recover(context.Background(), "run.recovery")
	if err != nil || state.Directive != "resume_stream" {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	if len(store.byDigest) != 4 {
		t.Fatalf("stored transitions=%d", len(store.byDigest))
	}
}

func TestRecoveryControllerDeniesInvalidAdvanceTamperAndCrossScope(t *testing.T) {
	controller, store, records, prepared, binding := newRecoveryFixture(t)
	current, _, _ := controller.Prepare(context.Background(), "run.recovery", prepared)
	if _, err := controller.Advance(context.Background(), "run.recovery", current, AdvanceTransition{TransitionID: uuid(61), Phase: "dispatched", BindingDigest: binding.BindingDigest, UpdatedAt: timestamp(4)}); Reason(err) != "transition_advance" {
		t.Fatalf("advance err=%v", err)
	}
	current, _ = controller.Advance(context.Background(), "run.recovery", current, AdvanceTransition{TransitionID: uuid(62), Phase: "verified", BindingDigest: binding.BindingDigest, UpdatedAt: timestamp(4)})
	latest := current.Value()
	latest.Scope.TenantID = uuid(90)
	latest.TransitionDigest = ""
	tampered, _ := validatedTransition(context.Background(), latest)
	store.latest["run.recovery"] = tampered.CanonicalBytes()
	if _, err := controller.Recover(context.Background(), "run.recovery"); Reason(err) != "transition_chain" {
		t.Fatalf("scope chain err=%v", err)
	}
	store.latest["run.recovery"] = current.CanonicalBytes()
	delete(records.bindings, binding.BindingDigest)
	if _, err := controller.Recover(context.Background(), "run.recovery"); Reason(err) != "binding_missing" {
		t.Fatalf("binding err=%v", err)
	}
}

func TestRecoveryControllerPersistsExplicitForkAndFallbackBranches(t *testing.T) {
	controller, store, _, _, binding := newRecoveryFixture(t)
	parent := validTransition()
	parent.Phase, parent.BindingDigest, parent.StreamCursor, parent.TerminalOutcome = "terminal", binding.BindingDigest, 1, "failed"
	parentDoc, err := validatedTransition(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	store.byDigest[parentDoc.Digest()] = parentDoc.CanonicalBytes()
	fork := validTransition()
	fork.TransitionID, fork.RequestID, fork.AttemptID = uuid(70), uuid(71), uuid(72)
	fork.Revision, fork.PreviousTransitionDigest = 2, parentDoc.Digest()
	forkDoc, replayed, err := controller.Fork(context.Background(), "fork.recovery", parentDoc, fork)
	if err != nil || replayed {
		t.Fatalf("fork replayed=%v err=%v", replayed, err)
	}
	state, err := controller.Recover(context.Background(), "fork.recovery")
	if err != nil || state.Directive != "verify" || state.Transition.Digest() != forkDoc.Digest() {
		t.Fatalf("fork state=%#v err=%v", state, err)
	}
	fallback := validTransition()
	fallback.TransitionID, fallback.AttemptID, fallback.ProviderRoute = uuid(73), uuid(74), "llama_cpp.local"
	fallback.Revision, fallback.ProviderAttempt, fallback.PreviousTransitionDigest = 2, 2, parentDoc.Digest()
	_, replayed, err = controller.BeginFallback(context.Background(), "fallback.recovery", parentDoc, fallback)
	if err != nil || replayed {
		t.Fatalf("fallback replayed=%v err=%v", replayed, err)
	}
	fallback.ProviderRoute = parent.ProviderRoute
	if _, _, err = controller.BeginFallback(context.Background(), "invalid.fallback", parentDoc, fallback); Reason(err) != "fallback_transition" {
		t.Fatalf("invalid fallback err=%v", err)
	}
}

func newRecoveryFixture(t *testing.T) (*RecoveryController, *transitionStoreStub, *recoveryReaderStub, Transition, InferenceBinding) {
	t.Helper()
	projectionRaw, projectionDigest, err := CanonicalProjection(context.Background(), validProjection())
	if err != nil {
		t.Fatal(err)
	}
	bindingRaw, bindingDigest, err := CanonicalBinding(context.Background(), validBinding())
	if err != nil {
		t.Fatal(err)
	}
	bindingDoc, _ := DecodeBinding(context.Background(), bindingRaw)
	binding := bindingDoc.Value()
	prepared := validTransition()
	prepared.ProjectionDigest = projectionDigest
	store := &transitionStoreStub{latest: map[string][]byte{}, byDigest: map[string][]byte{}}
	records := &recoveryReaderStub{projections: map[string][]byte{projectionDigest: projectionRaw}, bindings: map[string][]byte{bindingDigest: bindingRaw}, streams: map[uint64][]byte{}}
	controller, err := NewRecoveryController(store, records, &projectionReplayerStub{})
	if err != nil {
		t.Fatal(err)
	}
	return controller, store, records, prepared, binding
}
