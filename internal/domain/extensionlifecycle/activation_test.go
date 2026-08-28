package extensionlifecycle

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
)

type memoryActivationStore struct {
	mu          sync.Mutex
	transitions map[string]Transition
	receipts    map[string]RegistrationReceipt
	active      map[string]ActiveExtension
	manifests   map[string][]byte
}

func newMemoryActivationStore() *memoryActivationStore {
	return &memoryActivationStore{transitions: map[string]Transition{}, receipts: map[string]RegistrationReceipt{}, active: map[string]ActiveExtension{}, manifests: map[string][]byte{}}
}
func (store *memoryActivationStore) LoadManifest(_ context.Context, digest string) ([]byte, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.manifests[digest]
	return slices.Clone(value), ok, nil
}
func (store *memoryActivationStore) LoadInactivePredecessor(_ context.Context, extension, organization, tenant, manifest string, revision uint64) (Transition, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, value := range store.transitions {
		if value.ExtensionID == extension && value.OrganizationID == organization && value.TenantID == tenant &&
			value.ManifestDigest == manifest && value.ExpectedLifecycleRevision == revision &&
			value.Direction == DeactivateDirection && value.Phase == InactivePhase {
			return value, true, nil
		}
	}
	return Transition{}, false, nil
}
func (store *memoryActivationStore) PutManifest(_ context.Context, _ string, digest string, canonical []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.manifests[digest]; ok && !slices.Equal(existing, canonical) {
		return errors.New("manifest collision")
	}
	store.manifests[digest] = slices.Clone(canonical)
	return nil
}
func activeKey(extension, organization, tenant string) string {
	return extension + "\x00" + organization + "\x00" + tenant
}
func (store *memoryActivationStore) LoadActive(_ context.Context, extension, organization, tenant string) (ActiveExtension, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.active[activeKey(extension, organization, tenant)]
	return value, ok, nil
}
func (store *memoryActivationStore) LoadTransition(_ context.Context, id string) (Transition, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.transitions[id]
	return value, ok, nil
}
func (store *memoryActivationStore) LoadReceipt(_ context.Context, digest string) (RegistrationReceipt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.receipts[digest]
	return value, ok, nil
}
func (store *memoryActivationStore) CreateTransition(_ context.Context, value Transition) (Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.transitions[value.TransitionID]; ok {
		if existing.IntentDigest != value.IntentDigest {
			return Transition{}, errors.New("conflict")
		}
		return existing, nil
	}
	store.transitions[value.TransitionID] = value
	return value, nil
}
func (store *memoryActivationStore) AdvanceTransition(_ context.Context, current, next Transition) (Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.advance(current, next)
}
func (store *memoryActivationStore) advance(current, next Transition) (Transition, error) {
	actual, ok := store.transitions[current.TransitionID]
	if !ok || actual.Sequence != current.Sequence || actual.TransitionDigest != current.TransitionDigest || next.Sequence != current.Sequence+1 {
		return Transition{}, errors.New("cas")
	}
	store.transitions[next.TransitionID] = next
	return next, nil
}
func (store *memoryActivationStore) CommitReceipt(_ context.Context, current Transition, receipt RegistrationReceipt, next Transition) (Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.receipts[receipt.ReceiptDigest]; ok && existing.ReceiptID != receipt.ReceiptID {
		return Transition{}, errors.New("receipt collision")
	}
	result, err := store.advance(current, next)
	if err != nil {
		return Transition{}, err
	}
	store.receipts[receipt.ReceiptDigest] = receipt
	return result, nil
}
func (store *memoryActivationStore) CommitRevocation(_ context.Context, current Transition, registered, revoked RegistrationReceipt, next Transition) (Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	existing, ok := store.receipts[registered.ReceiptDigest]
	if !ok || existing.ReceiptID != registered.ReceiptID || revoked.State != "revoked" {
		return Transition{}, errors.New("receipt missing")
	}
	result, err := store.advance(current, next)
	if err != nil {
		return Transition{}, err
	}
	delete(store.receipts, registered.ReceiptDigest)
	store.receipts[revoked.ReceiptDigest] = revoked
	return result, nil
}
func (store *memoryActivationStore) PublishActive(_ context.Context, current Transition, active ActiveExtension, next Transition) (Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := activeKey(active.ExtensionID, active.OrganizationID, active.TenantID)
	if _, ok := store.active[key]; ok {
		return Transition{}, errors.New("already active")
	}
	result, err := store.advance(current, next)
	if err != nil {
		return Transition{}, err
	}
	store.active[key] = active
	return result, nil
}
func (store *memoryActivationStore) RemoveActive(_ context.Context, current Transition, active ActiveExtension, next Transition) (Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := activeKey(active.ExtensionID, active.OrganizationID, active.TenantID)
	existing, ok := store.active[key]
	if !ok || existing.ActiveDigest != active.ActiveDigest || next.TerminalAuditDigest == "" {
		return Transition{}, errors.New("active removal conflict")
	}
	result, err := store.advance(current, next)
	if err != nil {
		return Transition{}, err
	}
	delete(store.active, key)
	return result, nil
}

type stagedEffects struct {
	mu             sync.Mutex
	results        map[string]EffectResult
	stagedOrdinals []uint64
	revoked        []uint64
	failOrdinal    int
	lostOrdinal    int
	failRevoke     bool
}

func newStagedEffects() *stagedEffects {
	return &stagedEffects{results: map[string]EffectResult{}, failOrdinal: -1, lostOrdinal: -1}
}
func (effects *stagedEffects) Resolve(_ context.Context, request EffectRequest) (EffectResult, bool, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	value, ok := effects.results[request.EffectKey]
	return value, ok, nil
}
func (effects *stagedEffects) Stage(_ context.Context, request EffectRequest) (EffectResult, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	if result, ok := effects.results[request.EffectKey]; ok {
		return result, nil
	}
	if int(request.Ordinal) == effects.failOrdinal {
		return EffectResult{}, errors.New("stage failed")
	}
	result := EffectResult{ReceiptID: deterministicUUID7("receipt", request.Ordinal), HandleID: deterministicUUID7("handle", request.Ordinal), Generation: request.Ordinal + 1, RegistryRevision: request.RegistryRevision, EffectAuditDigest: testDigest(byte('a' + request.Ordinal)), RegisteredAt: "2026-08-28T08:00:00Z"}
	effects.results[request.EffectKey], effects.stagedOrdinals = result, append(effects.stagedOrdinals, request.Ordinal)
	if int(request.Ordinal) == effects.lostOrdinal {
		return EffectResult{}, errors.New("response lost")
	}
	return result, nil
}
func (effects *stagedEffects) Revoke(_ context.Context, request EffectRequest, handle RevocationHandle) (RevocationResult, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	if effects.failRevoke {
		effects.failRevoke = false
		return RevocationResult{}, errors.New("revoke failed")
	}
	if handle.RegistrationOrdinal != request.Ordinal || handle.ExtensionID != request.ExtensionID {
		return RevocationResult{}, errors.New("owner mismatch")
	}
	if !slices.Contains(effects.revoked, request.Ordinal) {
		effects.revoked = append(effects.revoked, request.Ordinal)
	}
	delete(effects.results, request.EffectKey)
	return RevocationResult{RevokedAt: "2026-08-28T08:00:01Z", EffectAuditDigest: testDigest('e')}, nil
}

type activationAuditStub struct {
	fail              bool
	calls             int
	deactivationCalls int
}

func (audit *activationAuditStub) CommitActivation(_ context.Context, _, _ string, receipts []string) (string, error) {
	audit.calls++
	if audit.fail {
		return "", errors.New("audit failed")
	}
	if len(receipts) == 0 {
		return "", errors.New("empty")
	}
	return testDigest('f'), nil
}
func (audit *activationAuditStub) CommitDeactivation(_ context.Context, _, _, terminal string, receipts []string) (string, error) {
	audit.deactivationCalls++
	if audit.fail {
		return "", errors.New("audit failed")
	}
	if !validDigest(terminal) || len(receipts) == 0 {
		return "", errors.New("incomplete")
	}
	return testDigest('d'), nil
}

func TestTransactionalActivationPublishesOnlyAfterEveryStagedEffect(t *testing.T) {
	fixture := multiRegistrationFixture(t, 3)
	store, effects, audit := newMemoryActivationStore(), newStagedEffects(), &activationAuditStub{}
	controller, err := NewActivationController(store, effects, audit, fixedClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Activate(context.Background(), admission)
	if err != nil || result.Transition.Phase != ActivePhase || len(result.Active.RegistrationReceiptDigests) != 3 || audit.calls != 1 || !slices.Equal(effects.stagedOrdinals, []uint64{0, 1, 2}) {
		t.Fatalf("result=%+v effects=%+v audit=%+v err=%v", result, effects, audit, err)
	}
	replay, err := controller.Activate(context.Background(), admission)
	if err != nil || !replay.Replayed || len(effects.stagedOrdinals) != 3 || audit.calls != 1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
}

func TestPartialFailureUnwindsInExactReverseOrderWithoutActivePointer(t *testing.T) {
	fixture := multiRegistrationFixture(t, 4)
	store, effects, audit := newMemoryActivationStore(), newStagedEffects(), &activationAuditStub{}
	effects.failOrdinal = 3
	controller, _ := NewActivationController(store, effects, audit, fixedClock{testNow})
	admission, _ := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
	_, err := controller.Activate(context.Background(), admission)
	if Reason(err) != "activation_unwound" || !slices.Equal(effects.revoked, []uint64{2, 1, 0}) {
		t.Fatalf("revoked=%v err=%v", effects.revoked, err)
	}
	intent := admission.Intent().Value()
	if _, found, _ := store.LoadActive(context.Background(), intent.ExtensionID, intent.OrganizationID, intent.TenantID); found {
		t.Fatal("partial activation published")
	}
	transition, _, _ := store.LoadTransition(context.Background(), intent.RequestID)
	if transition.Phase != InactivePhase || transition.FailureCode != "effect_stage" {
		t.Fatalf("transition=%+v", transition)
	}
	for _, digest := range transition.RegistrationReceiptDigests {
		receipt, found, loadErr := store.LoadReceipt(context.Background(), digest)
		if loadErr != nil || !found || receipt.State != "revoked" || receipt.RevokedAt == "" {
			t.Fatalf("revoked receipt=%+v found=%v err=%v", receipt, found, loadErr)
		}
	}
}

func TestLostStageResponseResolvesIdempotentlyAndFailedUnwindResumes(t *testing.T) {
	fixture := multiRegistrationFixture(t, 3)
	store, effects, audit := newMemoryActivationStore(), newStagedEffects(), &activationAuditStub{fail: true}
	effects.lostOrdinal, effects.failRevoke = 1, true
	controller, _ := NewActivationController(store, effects, audit, fixedClock{testNow})
	admission, _ := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
	if _, err := controller.Activate(context.Background(), admission); Reason(err) != "effect_revoke" {
		t.Fatalf("first err=%v", err)
	}
	if _, err := controller.Activate(context.Background(), admission); Reason(err) != "activation_unwound" {
		t.Fatalf("recovery err=%v", err)
	}
	if !slices.Equal(effects.stagedOrdinals, []uint64{0, 1, 2}) || !slices.Equal(effects.revoked, []uint64{2, 1, 0}) {
		t.Fatalf("staged=%v revoked=%v", effects.stagedOrdinals, effects.revoked)
	}
}

func multiRegistrationFixture(t *testing.T, count int) admissionFixture {
	t.Helper()
	manifest := validManifest()
	manifest.Registrations = nil
	for index := range count {
		manifest.Registrations = append(manifest.Registrations, Registration{RegistrationID: fmt.Sprintf("timeline_%02d", index), Role: "provider", Capability: CapabilityRef{CapabilityID: fmt.Sprintf("analysis.timeline_%02d", index), CapabilityVersion: "1.0.0"}, ProviderID: fmt.Sprintf("extension.timeline_%02d", index), Permissions: []string{"read.timeline"}, ScopeTypes: []string{"case", "organization", "tenant"}, ResourceLimitsDigest: testDigest(byte('1' + index))})
	}
	return newAdmissionFixtureForManifest(t, manifest)
}
