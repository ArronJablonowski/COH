package entityresolution

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func TestComposeConfidenceIsDeterministicBoundedAndCeilingLimited(t *testing.T) {
	first := confidenceEvidence(t, 1, 900_000, "source-a", "group-a", "high", "current")
	second := confidenceEvidence(t, 7, 800_000, "source-b", "group-b", "standard", "recent")
	third := confidenceEvidence(t, 8, 950_000, "source-c", "group-c", "limited", "stale")
	input := ConfidenceInput{Evidence: []ConfidenceEvidenceInput{third, first, second}, MatchingEntityCount: 1}
	confidence, canonical, digest, err := ComposeConfidence(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if confidence.PreCeilingMillionths != 1_000_000 || confidence.CeilingMillionths != 800_000 ||
		confidence.FinalMillionths != 800_000 || confidence.Label != "high" || len(confidence.Components) != 6 ||
		confidence.Components[1].ValueMillionths != 300_000 || confidence.Components[2].ValueMillionths != 100_000 ||
		confidence.Components[3].ValueMillionths != 100_000 {
		t.Fatalf("confidence=%+v", confidence)
	}
	if digest != "sha256:47b2669c8d7307a17bc732eb72c8644efb706319938750a2bb75fdbc8a1849fa" {
		t.Fatalf("digest=%s", digest)
	}
	input.Evidence = []ConfidenceEvidenceInput{second, third, first}
	again, againCanonical, againDigest, err := ComposeConfidence(context.Background(), input)
	if err != nil || !bytes.Equal(canonical, againCanonical) || digest != againDigest || confidence.FinalMillionths != again.FinalMillionths {
		t.Fatalf("again=%+v digest=%s err=%v", again, againDigest, err)
	}
}

func TestConfidenceMethodFixtureIsCanonicalAndPinned(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/entity/v1/fixtures/confidence-method-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil || !bytes.Equal(input, append(canonical, '\n')) {
		t.Fatalf("fixture is not canonical: %v", err)
	}
	if digest := digestBytes(canonical); digest != "sha256:8d23a955b9dbe1421912110420558383bf903112aa56e3c4e231fef94c09e2d6" {
		t.Fatalf("fixture digest=%s", digest)
	}
	for _, required := range [][]byte{[]byte(`"exact_match_millionths":500000`),
		[]byte(`"maximum_counted":2`), []byte(`"analyst_rejection":{"blocks_merge":true`),
		[]byte(`"method_version":"1.0.0"`)} {
		if !bytes.Contains(canonical, required) {
			t.Fatalf("fixture missing %q", required)
		}
	}
}

func TestComposeConfidenceDoesNotDoubleCountSourceFamilies(t *testing.T) {
	input := ConfidenceInput{Evidence: []ConfidenceEvidenceInput{
		confidenceEvidence(t, 1, 900_000, "same-source", "group-a", "standard", "recent"),
		confidenceEvidence(t, 7, 900_000, "same-source", "group-b", "standard", "recent"),
		confidenceEvidence(t, 8, 900_000, "same-source", "group-c", "standard", "recent"),
	}}
	confidence, _, _, err := ComposeConfidence(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if confidence.Components[1].ValueMillionths != 0 || confidence.PreCeilingMillionths != 600_000 ||
		confidence.FinalMillionths != 600_000 || confidence.Label != "medium" {
		t.Fatalf("confidence=%+v", confidence)
	}
}

func TestComposeConfidenceRecordsCounterevidenceAndAmbiguity(t *testing.T) {
	evidence := confidenceEvidence(t, 1, 900_000, "source-a", "group-a", "high", "current")
	counter := validCounterevidence(t, 7, "shared_identifier", evidence.Link)
	confidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{
		Evidence: []ConfidenceEvidenceInput{evidence}, Counterevidence: []Counterevidence{counter}, MatchingEntityCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	if confidence.Components[4].ValueMillionths != -250_000 || confidence.Components[5].ValueMillionths != -250_000 ||
		confidence.PreCeilingMillionths != 200_000 || confidence.FinalMillionths != 200_000 || confidence.Label != "very_low" ||
		len(confidence.Counterevidence) != 1 || confidence.Counterevidence[0].RecordDigest != counter.RecordDigest {
		t.Fatalf("confidence=%+v", confidence)
	}
}

func TestComposeConfidenceClampsCounterevidenceAndLabels(t *testing.T) {
	evidence := confidenceEvidence(t, 1, 1_000_000, "source-a", "group-a", "high", "current")
	first := validCounterevidence(t, 7, "explicit_separation", evidence.Link)
	second := validCounterevidence(t, 8, "analyst_rejection", evidence.Link)
	confidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{
		Evidence: []ConfidenceEvidenceInput{evidence}, Counterevidence: []Counterevidence{second, first}})
	if err != nil {
		t.Fatal(err)
	}
	if confidence.Components[4].ValueMillionths != -1_000_000 || confidence.PreCeilingMillionths != 0 ||
		confidence.FinalMillionths != 0 || confidence.Label != "very_low" ||
		!confidence.Counterevidence[0].BlocksMerge || !confidence.Counterevidence[1].BlocksMerge {
		t.Fatalf("confidence=%+v", confidence)
	}
	for score, label := range map[uint32]string{249_999: "very_low", 250_000: "low", 499_999: "low", 500_000: "medium",
		749_999: "medium", 750_000: "high", 899_999: "high", 900_000: "very_high", 1_000_000: "very_high"} {
		if actual := confidenceLabel(score); actual != label {
			t.Fatalf("label(%d)=%s", score, actual)
		}
	}
}

func TestComposeConfidenceRejectsUndeclaredOrMutatedInputs(t *testing.T) {
	tests := map[string]func(*ConfidenceInput){
		"unknown quality":       func(value *ConfidenceInput) { value.Evidence[0].SourceQuality = "trusted" },
		"binding drift":         func(value *ConfidenceInput) { value.Evidence[0].Link.EvidenceBindingDigest = testDigest("changed") },
		"observation drift":     func(value *ConfidenceInput) { value.Evidence[0].ObservationDigest = testDigest("changed") },
		"duplicate observation": func(value *ConfidenceInput) { value.Evidence = append(value.Evidence, value.Evidence[0]) },
		"counter weight":        func(value *ConfidenceInput) { value.Counterevidence[0].WeightMillionths++ },
		"counter blocking":      func(value *ConfidenceInput) { value.Counterevidence[0].BlocksMerge = false },
		"counter digest":        func(value *ConfidenceInput) { value.Counterevidence[0].RecordDigest = testDigest("changed") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := confidenceEvidence(t, 1, 900_000, "source-a", "group-a", "high", "current")
			input := ConfidenceInput{Evidence: []ConfidenceEvidenceInput{evidence},
				Counterevidence: []Counterevidence{validCounterevidence(t, 7, "temporal_impossibility", evidence.Link)}}
			mutate(&input)
			confidence, canonical, digest, err := ComposeConfidence(context.Background(), input)
			if Code(err) != InvalidInputError || ErrorReason(err) != ConfidenceInvalid || !reflect.DeepEqual(confidence, Confidence{}) || canonical != nil || digest != "" {
				t.Fatalf("confidence=%+v canonical=%q digest=%q err=%v", confidence, canonical, digest, err)
			}
		})
	}
}

func TestComposeConfidenceCancellationAndRecovery(t *testing.T) {
	input := ConfidenceInput{Evidence: []ConfidenceEvidenceInput{confidenceEvidence(t, 1, 900_000, "source-a", "group-a", "high", "current")}}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := ComposeConfidence(canceled, input); Code(err) != CanceledError || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err=%v", err)
	}
	if _, _, _, err := ComposeConfidence(context.Background(), input); err != nil {
		t.Fatalf("recovery err=%v", err)
	}
}

func confidenceEvidence(t *testing.T, suffix int, ceiling uint32, source, group, quality, recency string) ConfidenceEvidenceInput {
	t.Helper()
	input := validObservationInput()
	input.ObservationID = testUUID(suffix)
	input.Hint.ConfidenceCeilingMillionths = ceiling
	observation, _, digest, err := NewObservation(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	_, bindingDigest, err := canonicalValue(observation.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	return ConfidenceEvidenceInput{Observation: observation, ObservationDigest: digest, SourceQuality: quality, Recency: recency,
		Link: EvidenceLink{ObservationID: observation.ObservationID, ObservationDigest: digest, EvidenceBindingDigest: bindingDigest,
			SourceFamilyDigest: testDigest(source), IndependenceGroupDigest: testDigest(group)}}
}

func validCounterevidence(t *testing.T, suffix int, reason string, link EvidenceLink) Counterevidence {
	t.Helper()
	value := Counterevidence{CounterevidenceID: testUUID(suffix), Reason: reason, EvidenceLinks: []EvidenceLink{link},
		WeightMillionths: counterWeights[reason],
		BlocksMerge:      slicesContains([]string{"temporal_impossibility", "explicit_separation", "analyst_rejection"}, reason)}
	digest, err := CounterevidenceRecordDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.RecordDigest = digest
	return value
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
