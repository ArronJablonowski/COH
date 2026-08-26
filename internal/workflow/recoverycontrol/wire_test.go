package recoverycontrol

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"
)

func TestPublishedRecoveryControlFixturesStrictlyDecodeAndAreCanonical(t *testing.T) {
	for _, name := range []string{"recovery-control-recovery.json", "recovery-control-cancellation.json",
		"recovery-control-fallback.json"} {
		input, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/" + name)
		if err != nil {
			t.Fatal(err)
		}
		value, err := DecodeRecord(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		canonical, err := CanonicalRecord(value)
		if err != nil || !bytes.Equal(bytes.TrimSpace(input), canonical) {
			t.Fatalf("%s canonical=%s err=%v", name, canonical, err)
		}
	}
}

func TestRecoveryCancellationAndFallbackRecordsRoundTripEveryField(t *testing.T) {
	for name, makeRecord := range map[string]func(*testing.T) Record{
		"recovery": func(t *testing.T) Record {
			store := &memoryStore{}
			controller := newController(t, store, nil, nil, nil, nil)
			if _, err := controller.Recover(context.Background(), validRecoverRequest()); err != nil {
				t.Fatal(err)
			}
			return store.current
		},
		"cancellation": func(t *testing.T) Record {
			store := &memoryStore{}
			controller := newController(t, store, nil, nil, nil, nil)
			if _, err := controller.Cancel(context.Background(), validCancelRequest()); err != nil {
				t.Fatal(err)
			}
			return store.current
		},
		"fallback": func(t *testing.T) Record {
			store := &memoryStore{}
			provider := &providerStub{outcomes: []providerOutcome{
				{err: NewDependencyError(Unavailable, "primary_unavailable", true, false)}, {},
			}}
			controller := newController(t, store, nil, nil, nil, provider)
			if _, err := controller.Invoke(context.Background(), validInvokeRequest()); err != nil {
				t.Fatal(err)
			}
			return store.current
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := makeRecord(t)
			encoded, err := CanonicalRecord(value)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeRecord(encoded)
			if err != nil || !reflect.DeepEqual(decoded, value) {
				t.Fatalf("decoded=%+v value=%+v err=%v", decoded, value, err)
			}
		})
	}
}

func TestRecoveryControlWireRejectsUnknownDuplicateMissingNestedTrailingAndOversized(t *testing.T) {
	valid, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/recovery-control-recovery.json")
	if err != nil {
		t.Fatal(err)
	}
	malformed := map[string][]byte{
		"unknown":   append(append([]byte{}, valid[:len(valid)-2]...), []byte(`,"executor":"forbidden"}\n`)...),
		"duplicate": bytes.Replace(valid, []byte(`"run_id":"`+testRun+`"`), []byte(`"run_id":"`+testRun+`","run_id":"`+testRun+`"`), 1),
		"missing":   bytes.Replace(valid, []byte(`"policy_digest":"`+testDigest1+`",`), nil, 1),
		"nested":    bytes.Replace(valid, []byte(`"side_effect":"none",`), nil, 1),
		"trailing":  append(append([]byte{}, valid...), []byte(` {}`)...),
		"oversized": bytes.Repeat([]byte{'x'}, maximumRecordBytes+1),
	}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRecord(input); ErrorCode(err) != DeniedCode {
				t.Fatalf("accepted malformed record: %v", err)
			}
		})
	}
}
