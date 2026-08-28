package sqlite

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/extensionlifecycle"
)

func TestExtensionLifecycleRecoversAfterSQLiteProcessExit(t *testing.T) {
	path, backup := lifecycleStorePaths(t)
	command := exec.Command(os.Args[0], "-test.run=^TestExtensionLifecycleCrashWriter$")
	command.Env = append(os.Environ(), "COH_EXTENSION_CRASH_PATH="+path, "COH_EXTENSION_CRASH_BACKUP="+backup)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crash writer: %v\n%s", err, output)
	}
	store := openProfileActivationStore(t, path, backup)
	t.Cleanup(func() { _ = store.Close() })
	admission := verifyLifecycleFixture(t, newLifecycleFixture(t))
	controller, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(),
		&persistentEffects{results: map[string]extensionlifecycle.EffectResult{}}, &lifecycleAudit{},
		lifecycleClock{profileActivationTime})
	result, err := controller.Activate(context.Background(), admission)
	if err != nil || !result.Replayed || result.Transition.Phase != extensionlifecycle.ActivePhase {
		t.Fatalf("crash recovery=%+v err=%v", result, err)
	}
}

func TestExtensionLifecycleCrashWriter(t *testing.T) {
	path, backup := os.Getenv("COH_EXTENSION_CRASH_PATH"), os.Getenv("COH_EXTENSION_CRASH_BACKUP")
	if path == "" || backup == "" {
		t.Skip("subprocess helper")
	}
	store := openProfileActivationStore(t, path, backup)
	admission := verifyLifecycleFixture(t, newLifecycleFixture(t))
	controller, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(),
		&persistentEffects{results: map[string]extensionlifecycle.EffectResult{}}, &lifecycleAudit{},
		lifecycleClock{profileActivationTime})
	if _, err := controller.Activate(context.Background(), admission); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestConcurrentExactExtensionActivationConvergesWithoutDuplicateEffects(t *testing.T) {
	store := openEphemeralProfileActivationStore(t)
	admission := verifyLifecycleFixture(t, newLifecycleFixture(t))
	effects, audit := &persistentEffects{results: map[string]extensionlifecycle.EffectResult{}}, &lifecycleAudit{}
	const workers = 12
	errorsByWorker := make([]error, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := range workers {
		go func(index int) {
			defer wait.Done()
			controller, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(), effects, audit,
				lifecycleClock{profileActivationTime})
			_, errorsByWorker[index] = controller.Activate(context.Background(), admission)
		}(index)
	}
	wait.Wait()
	allowed := 0
	for _, err := range errorsByWorker {
		if err == nil {
			allowed++
			continue
		}
		if code := extensionlifecycle.Code(err); code != extensionlifecycle.Unavailable && code != extensionlifecycle.Denied {
			t.Fatalf("concurrent error=%v", err)
		}
	}
	if allowed == 0 {
		t.Fatalf("no activation completed: %v", errorsByWorker)
	}
	controller, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(), effects, audit,
		lifecycleClock{profileActivationTime})
	result, err := controller.Activate(context.Background(), admission)
	if err != nil || !result.Replayed || result.Transition.Phase != extensionlifecycle.ActivePhase {
		t.Fatalf("convergence result=%+v err=%v", result, err)
	}
	assertLifecycleRowCount(t, store, "coh_active_extensions", 1)
	assertLifecycleRowCount(t, store, "coh_extension_registration_receipts", 1)
	assertLifecycleRowCount(t, store, "coh_extension_lifecycle_transitions", 1)
}

func TestConcurrentActivationDeactivationConvergesToScopedInactiveState(t *testing.T) {
	store := openEphemeralProfileActivationStore(t)
	fixture := newLifecycleFixture(t)
	admission := verifyLifecycleFixture(t, fixture)
	effects, audit := &persistentEffects{results: map[string]extensionlifecycle.EffectResult{}}, &lifecycleAudit{}
	activate, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(), effects, audit,
		lifecycleClock{profileActivationTime})
	active, err := activate.Activate(context.Background(), admission)
	if err != nil {
		t.Fatal(err)
	}
	deactivation := verifyLifecycleFixture(t, lifecycleDeactivationFixture(t, fixture, active.Active))
	const workers = 8
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := range workers {
		go func(index int) {
			defer wait.Done()
			if index%2 == 0 {
				controller, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(), effects, audit,
					lifecycleClock{profileActivationTime})
				_, _ = controller.Activate(context.Background(), admission)
				return
			}
			controller, _ := extensionlifecycle.NewDeactivationController(store.ExtensionLifecycle(), effects, audit,
				&lifecycleDrain{}, lifecycleClock{profileActivationTime})
			_, _ = controller.Deactivate(context.Background(), deactivation)
		}(index)
	}
	wait.Wait()
	deactivate, _ := extensionlifecycle.NewDeactivationController(store.ExtensionLifecycle(), effects, audit,
		&lifecycleDrain{}, lifecycleClock{profileActivationTime})
	result, err := deactivate.Deactivate(context.Background(), deactivation)
	if err != nil || result.Transition.Phase != extensionlifecycle.InactivePhase {
		t.Fatalf("deactivation convergence=%+v err=%v", result, err)
	}
	intent := deactivation.Intent().Value()
	if _, found, err := store.ExtensionLifecycle().LoadActive(context.Background(), intent.ExtensionID,
		intent.OrganizationID, intent.TenantID); err != nil || found {
		t.Fatalf("active after convergence found=%v err=%v", found, err)
	}
	assertLifecycleRowCount(t, store, "coh_active_extensions", 0)
}

func TestSQLiteExtensionLifecycleRejectsDurableTamper(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*Store, extensionlifecycle.ActivationResult) error
		load   func(*Store, extensionlifecycle.ActivationResult) error
	}{
		{"manifest", func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, err := store.db.Exec("UPDATE coh_extension_manifests SET canonical=? WHERE manifest_digest=?", []byte("{}"), result.Active.ManifestDigest)
			return err
		}, func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, _, err := store.ExtensionLifecycle().LoadManifest(context.Background(), result.Active.ManifestDigest)
			return err
		}},
		{"transition column", func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, err := store.db.Exec("UPDATE coh_extension_lifecycle_transitions SET phase='inactive' WHERE transition_id=?", result.Transition.TransitionID)
			return err
		}, func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, _, err := store.ExtensionLifecycle().LoadTransition(context.Background(), result.Transition.TransitionID)
			return err
		}},
		{"receipt handle", func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, err := store.db.Exec("UPDATE coh_extension_registration_receipts SET handle_digest=? WHERE receipt_digest=?",
				lifecycleDigest('0'), result.Active.RegistrationReceiptDigests[0])
			return err
		}, func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, _, err := store.ExtensionLifecycle().LoadReceipt(context.Background(), result.Active.RegistrationReceiptDigests[0])
			return err
		}},
		{"active canonical", func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, err := store.db.Exec("UPDATE coh_active_extensions SET canonical=? WHERE active_digest=?", []byte("{}"), result.Active.ActiveDigest)
			return err
		}, func(store *Store, result extensionlifecycle.ActivationResult) error {
			_, _, err := store.ExtensionLifecycle().LoadActive(context.Background(), result.Active.ExtensionID,
				result.Active.OrganizationID, result.Active.TenantID)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := openEphemeralProfileActivationStore(t)
			admission := verifyLifecycleFixture(t, newLifecycleFixture(t))
			controller, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(),
				&persistentEffects{results: map[string]extensionlifecycle.EffectResult{}}, &lifecycleAudit{},
				lifecycleClock{profileActivationTime})
			result, err := controller.Activate(context.Background(), admission)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.tamper(store, result); err != nil {
				t.Fatal(err)
			}
			if err := test.load(store, result); err == nil {
				t.Fatal("tampered durable record was accepted")
			}
		})
	}
}

func assertLifecycleRowCount(t *testing.T, store *Store, table string, want int) {
	t.Helper()
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s count=%d want=%d", table, count, want)
	}
}
