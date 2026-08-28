package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/profileactivation"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

var profileActivationTime = time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)

type activationClock struct{ now time.Time }

func (clock activationClock) Now() time.Time { return clock.now }

type maintenanceGateStub struct {
	attestation string
	released    bool
	failRelease bool
	quiesce     int
	releases    int
	invalid     bool
}

func (gate *maintenanceGateStub) Quiesce(_ context.Context,
	plan profileactivation.QuiescencePlan) (profileactivation.QuiescenceAttestation, error) {
	if plan.MaxDrainDurationMS != 30000 {
		return profileactivation.QuiescenceAttestation{}, errors.New("unbounded drain plan")
	}
	gate.quiesce++
	gate.released = false
	attestation := profileactivation.QuiescenceAttestation{TransitionID: plan.TransitionID,
		AttestationDigest: gate.attestation, AdmissionsStopped: true, Durable: true}
	if gate.invalid {
		attestation.ActiveWork = 1
		attestation.Durable = false
	}
	return attestation, nil
}
func (gate *maintenanceGateStub) Release(context.Context, profileactivation.QuiescenceAttestation) error {
	gate.releases++
	gate.released = true
	if gate.failRelease {
		gate.failRelease = false
		return errors.New("release response lost")
	}
	return nil
}

type lostActivationResponseStore struct {
	profileactivation.Store
	failOperation string
	fired         bool
}

type concurrentMaintenanceGate struct {
	mu     sync.Mutex
	digest string
}

func (gate *concurrentMaintenanceGate) Quiesce(_ context.Context,
	plan profileactivation.QuiescencePlan) (profileactivation.QuiescenceAttestation, error) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return profileactivation.QuiescenceAttestation{TransitionID: plan.TransitionID,
		AttestationDigest: gate.digest, AdmissionsStopped: true, Durable: true}, nil
}
func (gate *concurrentMaintenanceGate) Release(context.Context, profileactivation.QuiescenceAttestation) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return nil
}

func (store *lostActivationResponseStore) fail(operation string) error {
	if !store.fired && store.failOperation == operation {
		store.fired = true
		return errors.New("durable response lost")
	}
	return nil
}
func (store *lostActivationResponseStore) CreateTransition(ctx context.Context,
	value profileactivation.Transition) (profileactivation.Transition, error) {
	result, err := store.Store.CreateTransition(ctx, value)
	if err == nil {
		err = store.fail("create")
	}
	return result, err
}
func (store *lostActivationResponseStore) AdvanceTransition(ctx context.Context, id string, sequence uint64,
	digest string, phase profileactivation.Phase, quiescence string) (profileactivation.Transition, error) {
	result, err := store.Store.AdvanceTransition(ctx, id, sequence, digest, phase, quiescence)
	if err == nil {
		err = store.fail("advance_" + string(phase))
	}
	return result, err
}
func (store *lostActivationResponseStore) Publish(ctx context.Context, id string, sequence uint64,
	digest string, active profileactivation.ActiveProfile, quiescence string) (profileactivation.Transition, error) {
	result, err := store.Store.Publish(ctx, id, sequence, digest, active, quiescence)
	if err == nil {
		err = store.fail("publish")
	}
	return result, err
}

func TestProfileActivationRecoversEveryDurableBoundaryAfterSQLiteRestart(t *testing.T) {
	for _, operation := range []string{"create", "advance_quiescent", "publish", "release", "advance_active"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			path, backup := filepath.Join(root, "coh.sqlite3"), filepath.Join(root, "backups")
			if err := os.Mkdir(backup, 0o700); err != nil {
				t.Fatal(err)
			}
			store := openProfileActivationStore(t, path, backup)
			gate := &maintenanceGateStub{attestation: "sha256:" + strings.Repeat("a", 64), failRelease: operation == "release"}
			fault := &lostActivationResponseStore{Store: store, failOperation: operation}
			controller, err := profileactivation.NewController(fault, gate, activationClock{profileActivationTime})
			if err != nil {
				t.Fatal(err)
			}
			request := profileActivationRequest(1, "1")
			if _, err := controller.Activate(context.Background(), request); profileactivation.Code(err) != profileactivation.Unavailable {
				t.Fatalf("first activation code=%s err=%v", profileactivation.Code(err), err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := openProfileActivationStore(t, path, backup)
			t.Cleanup(func() { _ = restarted.Close() })
			controller, err = profileactivation.NewController(restarted, gate, activationClock{profileActivationTime.Add(time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			result, err := controller.Activate(context.Background(), request)
			if err != nil || !result.Replayed || result.Transition.Phase != profileactivation.Active ||
				result.Profile.CompositionDigest != request.Candidate.CompositionDigest || !gate.released {
				t.Fatalf("recovered=%+v gate=%+v err=%v", result, gate, err)
			}
			replay, err := controller.Activate(context.Background(), request)
			if err != nil || !replay.Replayed || replay.Profile.ActiveDigest != result.Profile.ActiveDigest {
				t.Fatalf("replay=%+v err=%v", replay, err)
			}
		})
	}
}

func TestProfileActivationUpgradeReplayHotReloadAndTamperDenials(t *testing.T) {
	store := openEphemeralProfileActivationStore(t)
	gate := &maintenanceGateStub{attestation: "sha256:" + strings.Repeat("a", 64)}
	controller, err := profileactivation.NewController(store, gate, activationClock{profileActivationTime})
	if err != nil {
		t.Fatal(err)
	}
	first := profileActivationRequest(1, "1")
	if _, err := controller.Activate(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	hot := profileActivationRequest(2, "2")
	hot.Mode = profileactivation.LiveReload
	hot.ExpectedActiveRevision = 1
	hot.ExpectedCompositionDigest = first.Candidate.CompositionDigest
	before := gate.quiesce
	if _, err := controller.Activate(context.Background(), hot); profileactivation.Code(err) != profileactivation.Denied ||
		profileactivation.Reason(err) != "live_hot_reload" || gate.quiesce != before {
		t.Fatalf("hot reload gate=%+v err=%v", gate, err)
	}
	upgrade := hot
	upgrade.Mode = profileactivation.Maintenance
	result, err := controller.Activate(context.Background(), upgrade)
	if err != nil || result.Profile.ProfileRevision != 2 {
		t.Fatalf("upgrade=%+v err=%v", result, err)
	}
	drift := upgrade
	drift.Candidate.InspectionDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := controller.Activate(context.Background(), drift); profileactivation.Code(err) != profileactivation.Denied ||
		profileactivation.Reason(err) != "transition_replay_drift" {
		t.Fatalf("drift err=%v", err)
	}
	if _, err := store.db.Exec(`UPDATE coh_profile_activation_transitions SET canonical=x'7b7d'
WHERE transition_id=?`, upgrade.TransitionID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadTransition(context.Background(), upgrade.TransitionID); workflow.StorageCode(err) != workflow.StorageDenied {
		t.Fatalf("tamper code=%s err=%v", workflow.StorageCode(err), err)
	}
}

func TestProfileActivationRejectsFalseQuiescenceAndCancellationWithoutPublication(t *testing.T) {
	store := openEphemeralProfileActivationStore(t)
	gate := &maintenanceGateStub{attestation: "sha256:" + strings.Repeat("a", 64), invalid: true}
	controller, err := profileactivation.NewController(store, gate, activationClock{profileActivationTime})
	if err != nil {
		t.Fatal(err)
	}
	request := profileActivationRequest(1, "1")
	if _, err := controller.Activate(context.Background(), request); profileactivation.Code(err) != profileactivation.Denied ||
		profileactivation.Reason(err) != "quiescence_attestation" {
		t.Fatalf("attestation err=%v", err)
	}
	if _, found, err := store.LoadActive(context.Background(), request.Candidate.ProfileID, request.Candidate.Target); err != nil || found {
		t.Fatalf("active found=%v err=%v", found, err)
	}
	transition, found, err := store.LoadTransition(context.Background(), request.TransitionID)
	if err != nil || !found || transition.Phase != profileactivation.Prepared {
		t.Fatalf("transition=%+v found=%v err=%v", transition, found, err)
	}
	canceledRequest := profileActivationRequest(2, "2")
	canceledRequest.Mode = profileactivation.Maintenance
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.Activate(ctx, canceledRequest); profileactivation.Code(err) != profileactivation.Canceled {
		t.Fatalf("cancel err=%v", err)
	}
	if _, found, err := store.LoadTransition(context.Background(), canceledRequest.TransitionID); err != nil || found {
		t.Fatalf("canceled transition found=%v err=%v", found, err)
	}
}

func TestConcurrentExactActivationConvergesOnOneDurablePublication(t *testing.T) {
	store := openEphemeralProfileActivationStore(t)
	gate := &concurrentMaintenanceGate{digest: "sha256:" + strings.Repeat("a", 64)}
	controller, err := profileactivation.NewController(store, gate, activationClock{profileActivationTime})
	if err != nil {
		t.Fatal(err)
	}
	request := profileActivationRequest(1, "1")
	const workers = 16
	results := make(chan profileactivation.Result, workers)
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, activateErr := controller.Activate(context.Background(), request)
			if activateErr != nil {
				errorsFound <- activateErr
				return
			}
			results <- result
		}()
	}
	group.Wait()
	close(results)
	close(errorsFound)
	successes := 0
	for result := range results {
		successes++
		if result.Profile.CompositionDigest != request.Candidate.CompositionDigest {
			t.Fatalf("result=%+v", result)
		}
	}
	for activateErr := range errorsFound {
		if profileactivation.Code(activateErr) != profileactivation.Unavailable {
			t.Fatalf("unexpected concurrent error=%v", activateErr)
		}
	}
	if successes == 0 {
		t.Fatal("no concurrent activation succeeded")
	}
	final, err := controller.Activate(context.Background(), request)
	if err != nil || !final.Replayed || final.Transition.Phase != profileactivation.Active {
		t.Fatalf("final=%+v err=%v", final, err)
	}
}

func profileActivationRequest(revision uint64, hexValue string) profileactivation.Request {
	digest := "sha256:" + strings.Repeat(hexValue, 64)
	transitionID := "018f0000-0000-7000-8000-00000000090" + string(rune('0'+revision))
	mode := profileactivation.Maintenance
	if revision == 1 {
		mode = profileactivation.Startup
	}
	return profileactivation.Request{TransitionID: transitionID, Mode: mode,
		MaxDrainDurationMS: 30000,
		Candidate: profileactivation.Candidate{ProfileID: "018f0000-0000-7000-8000-000000000900",
			ProfileRevision: revision, Target: profileactivation.Target{DeploymentKind: "native_workstation",
				ConnectivityMode: "connected", Platform: "darwin_arm64", Surface: "web"},
			ProfileBindingDigest: digest, CompositionDigest: digest,
			CapabilityGraphDigest: digest, InspectionDigest: digest}}
}

func openProfileActivationStore(t *testing.T, path, backup string) *Store {
	t.Helper()
	store, err := Open(context.Background(), Config{Path: path, BackupDirectory: backup,
		Clock: func() time.Time { return profileActivationTime }})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func openEphemeralProfileActivationStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	store := openProfileActivationStore(t, filepath.Join(root, "coh.sqlite3"), backup)
	t.Cleanup(func() { _ = store.Close() })
	return store
}
