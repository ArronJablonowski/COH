package entityresolution

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/mappingregistry"
)

func TestNewObservationBindsHintEvidenceAndCanonicalDigest(t *testing.T) {
	input := validObservationInput()
	observation, canonical, digest, err := NewObservation(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Identifier != (IdentifierBinding{Role: input.Hint.Role, IdentifierType: input.Hint.IdentifierType,
		Normalization: input.Hint.Normalization, MatchDigest: input.MatchDigest, DerivationKeyRevision: input.DerivationKeyRevision}) {
		t.Fatalf("identifier=%+v", observation.Identifier)
	}
	if observation.Evidence.RuleID != input.Hint.RuleID || observation.Evidence.OutputField != input.Hint.OutputPath ||
		observation.Evidence.SourceFieldDigest != input.Hint.SourceFieldDigest ||
		observation.Evidence.OutputFieldDigest != digestBytes([]byte(input.Hint.OutputPath)) ||
		observation.ConfidenceCeilingMillionths != input.Hint.ConfidenceCeilingMillionths {
		t.Fatalf("observation=%+v", observation)
	}
	if digest != "sha256:70914b9881a9fb48bd76d8a00131caf638d57847db87e896be4b2aebf8d3cb00" {
		t.Fatalf("digest=%s", digest)
	}
	decoded, decodedCanonical, decodedDigest, err := DecodeObservation(context.Background(), canonical)
	if err != nil || decoded != observation || !bytes.Equal(decodedCanonical, canonical) || decodedDigest != digest {
		t.Fatalf("decoded=%+v digest=%s err=%v", decoded, decodedDigest, err)
	}
	again, againCanonical, againDigest, err := NewObservation(context.Background(), input)
	if err != nil || again != observation || !bytes.Equal(againCanonical, canonical) || againDigest != digest {
		t.Fatalf("repeat=%+v digest=%s err=%v", again, againDigest, err)
	}
	for _, forbidden := range [][]byte{[]byte(`"raw_identifier"`), []byte(`"identifier_value"`), []byte(`ws-01`)} {
		if bytes.Contains(canonical, forbidden) {
			t.Fatalf("canonical observation exposes forbidden value %q", forbidden)
		}
	}
}

func TestObservationRejectsHintAndBindingDrift(t *testing.T) {
	tests := map[string]func(*ObservationInput){
		"scope":              func(value *ObservationInput) { value.Scope.TenantID = testDigest("tenant") },
		"role":               func(value *ObservationInput) { value.Hint.Role = "unknown.role" },
		"type confusion":     func(value *ObservationInput) { value.Hint.IdentifierType = "ipv4" },
		"normalization":      func(value *ObservationInput) { value.Hint.Normalization = "ip_canonical" },
		"match digest":       func(value *ObservationInput) { value.MatchDigest = testUUID(9) },
		"key revision":       func(value *ObservationInput) { value.DerivationKeyRevision = 0 },
		"confidence ceiling": func(value *ObservationInput) { value.Hint.ConfidenceCeilingMillionths = 1_000_001 },
		"mapping revision":   func(value *ObservationInput) { value.Evidence.MappingRevision = 0 },
		"output path":        func(value *ObservationInput) { value.Hint.OutputPath = "ocsf.device.*" },
		"source field":       func(value *ObservationInput) { value.Hint.SourceFieldDigest = testUUID(8) },
		"classification":     func(value *ObservationInput) { value.Evidence.Classification = "secret" },
		"timestamp":          func(value *ObservationInput) { value.ObservedAt = "2026-08-27T00:00:00Z" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := validObservationInput()
			mutate(&input)
			observation, canonical, digest, err := NewObservation(context.Background(), input)
			if Code(err) != InvalidInputError || ErrorReason(err) != InvalidInput || observation != (Observation{}) || canonical != nil || digest != "" {
				t.Fatalf("observation=%+v canonical=%q digest=%q err=%v", observation, canonical, digest, err)
			}
		})
	}
}

func TestDecodeObservationRejectsUnknownDuplicateOversizeAndMutation(t *testing.T) {
	observation, canonical, _, err := NewObservation(context.Background(), validObservationInput())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(canonical,
		[]byte(`"schema_version":"coh.entity-observation/v1"`),
		[]byte(`"schema_version":"coh.entity-observation/v1","schema_version":"coh.entity-observation/v1"`), 1)
	unknown := append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"unexpected":true}`)...)
	mutated := append([]byte(nil), canonical...)
	mutated = bytes.Replace(mutated, []byte(observation.Evidence.OutputFieldDigest), []byte(testDigest("changed-output")), 1)
	for name, value := range map[string][]byte{
		"duplicate": duplicate,
		"unknown":   unknown,
		"mutation":  mutated,
		"oversize":  bytes.Repeat([]byte{'x'}, MaximumInputBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			decoded, decodedCanonical, digest, err := DecodeObservation(context.Background(), value)
			if Code(err) != InvalidInputError || decoded != (Observation{}) || decodedCanonical != nil || digest != "" {
				t.Fatalf("decoded=%+v canonical=%q digest=%q err=%v", decoded, decodedCanonical, digest, err)
			}
		})
	}
}

func TestObservationContextCancellationTimeoutAndRecovery(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := NewObservation(canceled, validObservationInput()); Code(err) != CanceledError || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err=%v", err)
	}
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	if _, _, _, err := NewObservation(deadline, validObservationInput()); Code(err) != TimeoutError || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline err=%v", err)
	}
	if _, _, _, err := NewObservation(context.Background(), validObservationInput()); err != nil {
		t.Fatalf("recovery err=%v", err)
	}
}

func validObservationInput() ObservationInput {
	return ObservationInput{
		ObservationID: testUUID(1), OperationID: testUUID(2),
		Scope:       Scope{OrganizationID: testUUID(3), TenantID: testUUID(4), CaseID: testUUID(5)},
		MatchDigest: testDigest("case-keyed-hostname"), DerivationKeyRevision: 7,
		Hint: mappingregistry.EmittedEntityHint{RuleID: "host-name", OutputPath: "ocsf.device.name",
			SourceFieldDigest: testDigest("source-field"), Role: "host.name", IdentifierType: "hostname",
			Normalization: "lowercase_ascii", ConfidenceCeilingMillionths: 900_000},
		Evidence: ObservationEvidence{
			EnvelopeID: testUUID(6), EnvelopeDigest: testDigest("envelope"), Classification: "confidential",
			SourceIdentityDigest: testDigest("source-identity"), TransformationDigest: testDigest("transformation"),
			ArtifactDigest: testDigest("artifact"), RawManifestDigest: testDigest("raw-manifest"),
			IngestReceiptDigest: testDigest("ingest-receipt"), SourceProvenanceDigest: testDigest("source-provenance"),
			MappingManifestDigest: testDigest("mapping-manifest"), MappingRevision: 3,
			MappingOutcomeDigest: testDigest("mapping-outcome"),
		},
		ObservedAt: "2026-08-27T00:00:00.000000000Z",
	}
}

func testUUID(suffix int) string {
	return "0198e300-1000-7000-8000-00000000000" + string(rune('0'+suffix))
}

func testDigest(value string) string { return digestBytes([]byte(value)) }
