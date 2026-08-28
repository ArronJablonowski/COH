package extensionlifecycle

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCanceledAndTimedOutLifecycleContextsDoNotMutate(t *testing.T) {
	fixture := newAdmissionFixture(t)
	admission, err := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		ctx  func() context.Context
		code ErrorCode
	}{
		{"canceled", func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }, Canceled},
		{"timeout", func() context.Context {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer cancel()
			return ctx
		}, Timeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newMemoryActivationStore()
			controller, _ := NewActivationController(store, newStagedEffects(), &activationAuditStub{}, fixedClock{testNow})
			_, err := controller.Activate(test.ctx(), admission)
			if Code(err) != test.code || len(store.transitions) != 0 || len(store.active) != 0 || len(store.receipts) != 0 {
				t.Fatalf("code=%q store=%+v err=%v", Code(err), store, err)
			}
		})
	}
}

func FuzzDecodeLifecycleTransitionRoundTrip(f *testing.F) {
	seed, err := SealTransition(context.Background(), Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion,
		TransitionID: "0198d6c4-0010-7000-8000-000000000010", IntentDigest: fuzzDigest('1'),
		ExtensionID: "0198d6c4-0001-7000-8000-000000000001", ManifestDigest: fuzzDigest('2'),
		OrganizationID: "0198d6c4-0005-7000-8000-000000000005", TenantID: "0198d6c4-0006-7000-8000-000000000006",
		Direction: ActivateDirection, Phase: PreparedPhase, Sequence: 1, RegistryRevision: 1,
		NextRevokeOrdinal: -1, RegistrationReceiptDigests: []string{}, CreatedAt: "2026-08-28T08:00:00Z", UpdatedAt: "2026-08-28T08:00:00Z"})
	if err != nil {
		f.Fatal(err)
	}
	canonical, _, _ := CanonicalTransition(context.Background(), seed)
	f.Add(canonical)
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, input []byte) {
		value, err := DecodeTransition(context.Background(), input)
		if err != nil {
			return
		}
		roundTrip, digest, err := CanonicalTransition(context.Background(), value)
		if err != nil || digest != value.TransitionDigest || !bytes.Equal(roundTrip, input) {
			t.Fatalf("accepted transition is not an exact canonical round trip: digest=%q err=%v", digest, err)
		}
	})
}

func TestDurableRecordDecoderRejectsNonCanonicalBytes(t *testing.T) {
	value, err := SealTransition(context.Background(), Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion,
		TransitionID: "0198d6c4-0010-7000-8000-000000000010", IntentDigest: fuzzDigest('1'),
		ExtensionID: "0198d6c4-0001-7000-8000-000000000001", ManifestDigest: fuzzDigest('2'),
		OrganizationID: "0198d6c4-0005-7000-8000-000000000005", TenantID: "0198d6c4-0006-7000-8000-000000000006",
		Direction: ActivateDirection, Phase: PreparedPhase, Sequence: 1, RegistryRevision: 1,
		NextRevokeOrdinal: -1, RegistrationReceiptDigests: []string{}, CreatedAt: "2026-08-28T08:00:00Z", UpdatedAt: "2026-08-28T08:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, _ := CanonicalTransition(context.Background(), value)
	if _, err := DecodeTransition(context.Background(), append([]byte(" "), canonical...)); Reason(err) != "record_canonical" {
		t.Fatalf("non-canonical err=%v", err)
	}
}

func FuzzDecodeLifecycleDocumentsNeverPanic(f *testing.F) {
	f.Add(uint8(0), []byte("{}"))
	f.Add(uint8(1), []byte("null"))
	f.Add(uint8(2), []byte("{\"unknown\":true}"))
	f.Fuzz(func(t *testing.T, kind uint8, input []byte) {
		switch kind % 3 {
		case 0:
			_, _ = DecodeEnvelope(context.Background(), input)
		case 1:
			_, _ = DecodeIntent(context.Background(), input)
		case 2:
			_, _ = DecodeReceipt(context.Background(), input)
		}
	})
}

func fuzzDigest(value byte) string { return "sha256:" + string(bytes.Repeat([]byte{value}, 64)) }
