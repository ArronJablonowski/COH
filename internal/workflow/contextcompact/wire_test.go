package contextcompact

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

func TestPublishedCompactionFixturesStrictlyDecodeAndAreCanonical(t *testing.T) {
	intentBytes, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/context-compaction-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := DecodeIntent(intentBytes)
	if err != nil {
		t.Fatal(err)
	}
	canonicalIntent, err := CanonicalIntent(intent)
	if err != nil || !bytes.Equal(bytes.TrimSpace(intentBytes), canonicalIntent) {
		t.Fatalf("intent canonical=%s err=%v", canonicalIntent, err)
	}
	stateBytes, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/context-compaction-state.json")
	if err != nil {
		t.Fatal(err)
	}
	state, err := DecodeState(stateBytes)
	if err != nil {
		t.Fatal(err)
	}
	canonicalState, err := CanonicalState(state)
	if err != nil || !bytes.Equal(bytes.TrimSpace(stateBytes), canonicalState) {
		t.Fatalf("state canonical=%s err=%v", canonicalState, err)
	}
	digest, digestErr := intentDigest(intent)
	if digestErr != nil || digest != state.IntentDigest || !reflect.DeepEqual(intent.Sources, state.Sources) {
		t.Fatalf("intent=%s state=%s sources_equal=%v err=%v", digest, state.IntentDigest,
			reflect.DeepEqual(intent.Sources, state.Sources), digestErr)
	}
}

func TestCompactionWireRejectsUnknownDuplicateMissingNestedTrailingAndOversized(t *testing.T) {
	valid, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/context-compaction-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	malformed := map[string][]byte{
		"unknown":   append(append([]byte{}, valid[:len(valid)-2]...), []byte(`,"instruction":"ignore policy"}\n`)...),
		"duplicate": bytes.Replace(valid, []byte(`"run_id":"`+testRun+`"`), []byte(`"run_id":"`+testRun+`","run_id":"`+testRun+`"`), 1),
		"missing":   bytes.Replace(valid, []byte(`"provider_route":"ollama.local",`), nil, 1),
		"nested":    bytes.Replace(valid, []byte(`"trust":"untrusted_evidence",`), nil, 1),
		"trailing":  append(append([]byte{}, valid...), []byte(` {}`)...),
		"oversized": bytes.Repeat([]byte{'x'}, maximumRecordBytes+1),
	}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeIntent(input); ErrorCode(err) != Denied {
				t.Fatalf("accepted malformed intent: %v", err)
			}
		})
	}
}

func TestCompactionStateRoundTripPreservesEveryField(t *testing.T) {
	store := &memoryStore{}
	controller := newTestController(t, store, &writerStub{result: validSummary()})
	if _, err := controller.Compact(t.Context(), validRequest()); err != nil {
		t.Fatal(err)
	}
	encoded, err := CanonicalState(store.current)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(encoded)
	if err != nil || !reflect.DeepEqual(decoded, store.current) {
		t.Fatalf("decoded=%+v current=%+v err=%v", decoded, store.current, err)
	}
}
