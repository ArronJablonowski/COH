package extensionlifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

type drainGateStub struct {
	calls   int
	closed  bool
	invalid bool
	fail    bool
}

func (gate *drainGateStub) CloseAdmissionsAndDrain(_ context.Context, request DrainRequest) (DrainAttestation, error) {
	gate.calls++
	if gate.fail {
		return DrainAttestation{}, errors.New("drain failed")
	}
	gate.closed = true
	result := DrainAttestation{TransitionID: request.TransitionID, AdmissionsClosed: true, Durable: true,
		TerminalOutcomesDigest: testDigest('c')}
	if gate.invalid {
		result.ActiveWork, result.Durable = 1, false
	}
	return result, nil
}

func TestScopedDeactivationDrainsRevokesAuditsThenRemovesOnlyOwner(t *testing.T) {
	fixture := multiRegistrationFixture(t, 3)
	store, effects, audit := newMemoryActivationStore(), newStagedEffects(), &activationAuditStub{}
	activateController, _ := NewActivationController(store, effects, audit, fixedClock{testNow})
	activationAdmission, _ := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
	activeResult, err := activateController.Activate(context.Background(), activationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	deactivationFixture := deactivationFixture(t, fixture, activeResult.Active)
	deactivationAdmission, err := VerifyAdmission(context.Background(), deactivationFixture.envelope, deactivationFixture.intent, deactivationFixture.snapshot, fixedClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	gate := &drainGateStub{}
	controller, _ := NewDeactivationController(store, effects, audit, gate, fixedClock{testNow})
	result, err := controller.Deactivate(context.Background(), deactivationAdmission)
	if err != nil || result.Transition.Phase != InactivePhase || !result.Transition.AdmissionClosed ||
		result.Transition.TerminalWorkDigest == "" || result.Transition.TerminalAuditDigest == "" || audit.deactivationCalls != 1 ||
		!gate.closed || !slices.Equal(effects.revoked, []uint64{2, 1, 0}) {
		t.Fatalf("result=%+v gate=%+v effects=%+v audit=%+v err=%v", result, gate, effects, audit, err)
	}
	intent := deactivationAdmission.Intent().Value()
	if _, found, _ := store.LoadActive(context.Background(), intent.ExtensionID, intent.OrganizationID, intent.TenantID); found {
		t.Fatal("active pointer remains")
	}
	for _, digest := range result.Transition.RegistrationReceiptDigests {
		receipt, found, loadErr := store.LoadReceipt(context.Background(), digest)
		if loadErr != nil || !found || receipt.State != "revoked" {
			t.Fatalf("receipt=%+v found=%v err=%v", receipt, found, loadErr)
		}
	}
	replay, err := controller.Deactivate(context.Background(), deactivationAdmission)
	if err != nil || !replay.Replayed || gate.calls != 1 || audit.deactivationCalls != 1 {
		t.Fatalf("replay=%+v gate=%+v err=%v", replay, gate, err)
	}
}

func TestDeactivationDeniesFalseDrainAndResumesFailedRevocationWithoutRemoval(t *testing.T) {
	fixture := multiRegistrationFixture(t, 2)
	store, effects, audit := newMemoryActivationStore(), newStagedEffects(), &activationAuditStub{}
	activateController, _ := NewActivationController(store, effects, audit, fixedClock{testNow})
	activationAdmission, _ := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
	activeResult, _ := activateController.Activate(context.Background(), activationAdmission)
	deactivationFixture := deactivationFixture(t, fixture, activeResult.Active)
	deactivationAdmission, _ := VerifyAdmission(context.Background(), deactivationFixture.envelope, deactivationFixture.intent, deactivationFixture.snapshot, fixedClock{testNow})
	invalidGate := &drainGateStub{invalid: true}
	controller, _ := NewDeactivationController(store, effects, audit, invalidGate, fixedClock{testNow})
	if _, err := controller.Deactivate(context.Background(), deactivationAdmission); Reason(err) != "drain_attestation" {
		t.Fatalf("false drain err=%v", err)
	}
	intent := deactivationAdmission.Intent().Value()
	if _, found, _ := store.LoadActive(context.Background(), intent.ExtensionID, intent.OrganizationID, intent.TenantID); !found {
		t.Fatal("false drain removed active")
	}

	validGate := &drainGateStub{}
	controller, _ = NewDeactivationController(store, effects, audit, validGate, fixedClock{testNow})
	effects.failRevoke = true
	if _, err := controller.Deactivate(context.Background(), deactivationAdmission); Reason(err) != "effect_revoke" {
		t.Fatalf("revoke failure err=%v", err)
	}
	if _, found, _ := store.LoadActive(context.Background(), intent.ExtensionID, intent.OrganizationID, intent.TenantID); !found {
		t.Fatal("failed revoke removed active")
	}
	result, err := controller.Deactivate(context.Background(), deactivationAdmission)
	if err != nil || result.Transition.Phase != InactivePhase {
		t.Fatalf("recovered=%+v err=%v", result, err)
	}
}

func deactivationFixture(t *testing.T, source admissionFixture, active ActiveExtension) admissionFixture {
	t.Helper()
	validated, err := DecodeIntent(context.Background(), source.intent)
	if err != nil {
		t.Fatal(err)
	}
	intent := validated.Value()
	intent.RequestID = "0198d6c4-0020-7000-8000-000000000020"
	intent.IdempotencyKey = "0198d6c4-0021-7000-8000-000000000021"
	intent.Operation, intent.Mode, intent.ExpectedLifecycleRevision = "deactivate", "maintenance", active.LifecycleRevision
	intent.ExpectedPredecessorManifestDigest, intent.RollbackAuthorizationDigest = "", ""
	intent, err = SealIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	private := testKey("administrator")
	raw, _ := hex.DecodeString(intent.IntentDigest[len("sha256:"):])
	intent.AdministratorSignature = Signature{ActorID: intent.ActorID, KeyID: "administrator_key", KeyRevision: 1,
		ApprovalRevision: 1, Algorithm: SignatureAlgorithm,
		Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(administratorSignatureDomain), raw...)))}
	return admissionFixture{envelope: slices.Clone(source.envelope), intent: canonicalJSON(t, intent), snapshot: source.snapshot}
}
