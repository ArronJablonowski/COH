package extensionlifecycle

import (
	"context"
	"testing"
)

func TestUpgradeAndAuthorizedRollbackRequireDurableInactiveLineage(t *testing.T) {
	store, effects, audit := newMemoryActivationStore(), newStagedEffects(), &activationAuditStub{}
	activate, _ := NewActivationController(store, effects, audit, fixedClock{testNow})
	deactivate, _ := NewDeactivationController(store, effects, audit, &drainGateStub{}, fixedClock{testNow})

	versionOne := newAdmissionFixture(t)
	admissionOne, _ := VerifyAdmission(context.Background(), versionOne.envelope, versionOne.intent, versionOne.snapshot, fixedClock{testNow})
	activeOne, err := activate.Activate(context.Background(), admissionOne)
	if err != nil {
		t.Fatal(err)
	}
	deactivateOne := deactivationFixture(t, versionOne, activeOne.Active)
	deactivationOne, _ := VerifyAdmission(context.Background(), deactivateOne.envelope, deactivateOne.intent, deactivateOne.snapshot, fixedClock{testNow})
	if _, err := deactivate.Deactivate(context.Background(), deactivationOne); err != nil {
		t.Fatal(err)
	}

	manifestTwo := validManifest()
	manifestTwo.ExtensionVersion = "2.0.0"
	manifestTwo.PredecessorManifestDigest = admissionOne.Envelope().ManifestDigest()
	versionTwo := mutateLifecycleIntent(t, newAdmissionFixtureForManifest(t, manifestTwo), func(intent *ActivationIntent, _ *AuthoritySnapshot) {
		intent.RequestID, intent.IdempotencyKey = "0198d6c4-0030-7000-8000-000000000030", "0198d6c4-0031-7000-8000-000000000031"
		intent.Mode = "upgrade"
		intent.ExpectedPredecessorManifestDigest = admissionOne.Envelope().ManifestDigest()
		intent.ExpectedLifecycleRevision = activeOne.Active.LifecycleRevision
	})
	upgrade, err := VerifyAdmission(context.Background(), versionTwo.envelope, versionTwo.intent, versionTwo.snapshot, fixedClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	activeTwo, err := activate.Activate(context.Background(), upgrade)
	if err != nil || activeTwo.Active.LifecycleRevision != 2 {
		t.Fatalf("upgrade=%+v err=%v", activeTwo, err)
	}

	deactivateTwo := mutateLifecycleIntent(t, deactivationFixture(t, versionTwo, activeTwo.Active), func(intent *ActivationIntent, _ *AuthoritySnapshot) {
		intent.RequestID, intent.IdempotencyKey = "0198d6c4-0035-7000-8000-000000000035", "0198d6c4-0036-7000-8000-000000000036"
	})
	deactivationTwo, _ := VerifyAdmission(context.Background(), deactivateTwo.envelope, deactivateTwo.intent, deactivateTwo.snapshot, fixedClock{testNow})
	if _, err := deactivate.Deactivate(context.Background(), deactivationTwo); err != nil {
		t.Fatal(err)
	}

	rollbackDigest := testDigest('9')
	rollbackFixture := mutateLifecycleIntent(t, newAdmissionFixture(t), func(intent *ActivationIntent, snapshot *AuthoritySnapshot) {
		intent.RequestID, intent.IdempotencyKey = "0198d6c4-0040-7000-8000-000000000040", "0198d6c4-0041-7000-8000-000000000041"
		intent.Mode = "rollback"
		intent.ExpectedPredecessorManifestDigest = upgrade.Envelope().ManifestDigest()
		intent.ExpectedLifecycleRevision = activeTwo.Active.LifecycleRevision
		intent.RollbackAuthorizationDigest = rollbackDigest
		snapshot.RollbackAllowed, snapshot.RollbackAuthorizationDigest = true, rollbackDigest
	})
	rollback, err := VerifyAdmission(context.Background(), rollbackFixture.envelope, rollbackFixture.intent, rollbackFixture.snapshot, fixedClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := activate.Activate(context.Background(), rollback)
	if err != nil || rolledBack.Active.LifecycleRevision != 3 || rolledBack.Active.ManifestDigest != admissionOne.Envelope().ManifestDigest() {
		t.Fatalf("rollback=%+v err=%v", rolledBack, err)
	}
}

func TestUpgradeRollbackAndStaleRevisionFailClosed(t *testing.T) {
	base := newAdmissionFixture(t)
	tests := []struct {
		name   string
		mutate func(*ActivationIntent, *AuthoritySnapshot)
		reason string
	}{
		{"upgrade without predecessor", func(intent *ActivationIntent, _ *AuthoritySnapshot) { intent.Mode = "upgrade" }, "lineage_binding"},
		{"rollback without independent authorization", func(intent *ActivationIntent, _ *AuthoritySnapshot) {
			intent.Mode, intent.ExpectedPredecessorManifestDigest, intent.RollbackAuthorizationDigest = "rollback", testDigest('8'), testDigest('9')
		}, "lineage_binding"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := mutateLifecycleIntent(t, base, test.mutate)
			_, err := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
			if Reason(err) != test.reason {
				t.Fatalf("reason=%q want=%q err=%v", Reason(err), test.reason, err)
			}
		})
	}

	store, effects, audit := newMemoryActivationStore(), newStagedEffects(), &activationAuditStub{}
	controller, _ := NewActivationController(store, effects, audit, fixedClock{testNow})
	stale := mutateLifecycleIntent(t, base, func(intent *ActivationIntent, _ *AuthoritySnapshot) {
		intent.ExpectedLifecycleRevision = 7
	})
	admission, _ := VerifyAdmission(context.Background(), stale.envelope, stale.intent, stale.snapshot, fixedClock{testNow})
	if _, err := controller.Activate(context.Background(), admission); Reason(err) != "lifecycle_lineage" {
		t.Fatalf("stale revision err=%v", err)
	}
}

func mutateLifecycleIntent(t *testing.T, source admissionFixture, mutate func(*ActivationIntent, *AuthoritySnapshot)) admissionFixture {
	t.Helper()
	validated, err := DecodeIntent(context.Background(), source.intent)
	if err != nil {
		t.Fatal(err)
	}
	intent, snapshot := validated.Value(), source.snapshot
	mutate(&intent, &snapshot)
	intent, err = SealIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.AdministratorSignature = testSignature("administrator", intent.ActorID, intent.IntentDigest,
		administratorSignatureDomain, testKey("administrator"))
	return admissionFixture{envelope: append([]byte(nil), source.envelope...), intent: canonicalJSON(t, intent), snapshot: snapshot}
}
