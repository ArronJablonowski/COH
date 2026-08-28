package profileactivation

import (
	"context"
	"testing"
)

func FuzzProfileActivationDecodersRecoverAcceptedRecords(f *testing.F) {
	request := activationTestRequest()
	intent, err := intentDigest(request)
	if err != nil {
		f.Fatal(err)
	}
	transition := Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion,
		TransitionID: request.TransitionID, IntentDigest: intent, Mode: request.Mode,
		MaxDrainDurationMS: request.MaxDrainDurationMS, Candidate: request.Candidate,
		Phase: Prepared, Sequence: 1, CreatedAt: "2026-08-28T08:00:00Z", UpdatedAt: "2026-08-28T08:00:00Z"}
	transitionBytes, _, err := CanonicalTransition(context.Background(), transition)
	if err != nil {
		f.Fatal(err)
	}
	sealedTransition, err := DecodeTransition(context.Background(), transitionBytes)
	if err != nil {
		f.Fatal(err)
	}
	activeBytes, _, err := CanonicalActive(context.Background(),
		activeFromTransition(sealedTransition, "2026-08-28T08:00:01Z"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(transitionBytes)
	f.Add(activeBytes)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if value, decodeErr := DecodeTransition(context.Background(), input); decodeErr == nil {
			canonical, canonicalErr := canonicalValue(value)
			replay, replayErr := DecodeTransition(context.Background(), canonical)
			if canonicalErr != nil || replayErr != nil || replay.TransitionDigest != value.TransitionDigest {
				t.Fatalf("accepted transition did not replay: canonical=%v replay=%v", canonicalErr, replayErr)
			}
		}
		if value, decodeErr := DecodeActive(context.Background(), input); decodeErr == nil {
			canonical, canonicalErr := canonicalValue(value)
			replay, replayErr := DecodeActive(context.Background(), canonical)
			if canonicalErr != nil || replayErr != nil || replay.ActiveDigest != value.ActiveDigest {
				t.Fatalf("accepted active profile did not replay: canonical=%v replay=%v", canonicalErr, replayErr)
			}
		}
	})
}
