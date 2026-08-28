package profilecomposition

import (
	"context"
	"testing"
)

func FuzzProfileLayerDecoderAndVerifierRecoverAcceptedDocuments(f *testing.F) {
	f.Add(readFixture(f, "layer.signed.valid.json"))
	f.Add([]byte(`{"schema_version":"coh.signed-profile-layer/v1"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if decoded, err := Decode(context.Background(), input); err == nil {
			replay, replayErr := Decode(context.Background(), decoded.CanonicalEnvelopeBytes())
			if replayErr != nil || replay.LayerDigest() != decoded.LayerDigest() {
				t.Fatalf("accepted layer did not replay: %v", replayErr)
			}
		}
		if verified, err := Verify(context.Background(), input, fixtureTrust(), fixedClock{fixtureTime}); err == nil {
			replay, replayErr := Verify(context.Background(), verified.CanonicalEnvelopeBytes(),
				fixtureTrust(), fixedClock{fixtureTime})
			if replayErr != nil || replay.LayerDigest() != verified.LayerDigest() ||
				replay.TrustRevision() != verified.TrustRevision() ||
				replay.RevocationRevision() != verified.RevocationRevision() {
				t.Fatalf("verified layer did not replay: %v", replayErr)
			}
		}
	})
}
