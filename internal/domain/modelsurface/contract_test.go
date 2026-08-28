package modelsurface

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalRecordsRoundTripAsImmutableOwnedValues(t *testing.T) {
	tests := []struct {
		name      string
		canonical func() ([]byte, string, error)
		decode    func([]byte) ([]byte, string, error)
	}{
		{"vocabulary", func() ([]byte, string, error) { return CanonicalVocabulary(context.Background(), validVocabulary()) }, decodeVocabularyTest},
		{"source", func() ([]byte, string, error) { return CanonicalSource(context.Background(), validSource()) }, decodeSourceTest},
		{"projection", func() ([]byte, string, error) { return CanonicalProjection(context.Background(), validProjection()) }, decodeProjectionTest},
		{"binding", func() ([]byte, string, error) { return CanonicalBinding(context.Background(), validBinding()) }, decodeBindingTest},
		{"stream", func() ([]byte, string, error) { return CanonicalStreamEvent(context.Background(), validStream()) }, decodeStreamTest},
		{"compaction", func() ([]byte, string, error) { return CanonicalCompaction(context.Background(), validCompaction()) }, decodeCompactionTest},
		{"transition", func() ([]byte, string, error) { return CanonicalTransition(context.Background(), validTransition()) }, decodeTransitionTest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			canonical, digest, err := test.canonical()
			if err != nil || !validDigest(digest) {
				t.Fatalf("canonical digest=%q err=%v", digest, err)
			}
			owned, decodedDigest, err := test.decode(canonical)
			if err != nil || decodedDigest != digest || !bytes.Equal(owned, canonical) {
				t.Fatalf("decode digest=%q err=%v", decodedDigest, err)
			}
			owned[0] = 'x'
			replayed, _, err := test.decode(canonical)
			if err != nil || replayed[0] != '{' {
				t.Fatalf("owned bytes aliased: %v", err)
			}
		})
	}
}

func TestPositiveFixturesAreExactCanonicalRecords(t *testing.T) {
	tests := []struct {
		name      string
		canonical func() ([]byte, string, error)
		decode    func([]byte) ([]byte, string, error)
	}{
		{"event-vocabulary.valid.json", func() ([]byte, string, error) { return CanonicalVocabulary(context.Background(), validVocabulary()) }, decodeVocabularyTest},
		{"source.valid.json", func() ([]byte, string, error) { return CanonicalSource(context.Background(), validSource()) }, decodeSourceTest},
		{"projection.valid.json", func() ([]byte, string, error) { return CanonicalProjection(context.Background(), validProjection()) }, decodeProjectionTest},
		{"binding.valid.json", func() ([]byte, string, error) { return CanonicalBinding(context.Background(), validBinding()) }, decodeBindingTest},
		{"stream.valid.json", func() ([]byte, string, error) { return CanonicalStreamEvent(context.Background(), validStream()) }, decodeStreamTest},
		{"compaction.valid.json", func() ([]byte, string, error) { return CanonicalCompaction(context.Background(), validCompaction()) }, decodeCompactionTest},
		{"transition.valid.json", func() ([]byte, string, error) { return CanonicalTransition(context.Background(), validTransition()) }, decodeTransitionTest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, err := os.ReadFile(filepath.Join("../../../contracts/model-surface/v1/fixtures", test.name))
			if err != nil {
				t.Fatal(err)
			}
			fixture = bytes.TrimSuffix(fixture, []byte{'\n'})
			canonical, _, err := test.canonical()
			if err != nil || !bytes.Equal(fixture, canonical) {
				t.Fatalf("fixture drift err=%v\nwant=%s\ngot=%s", err, canonical, fixture)
			}
			if _, _, err := test.decode(fixture); err != nil {
				t.Fatalf("fixture decode: %v", err)
			}
		})
	}
}

func TestValidatedValuesDoNotAliasReturnedSlices(t *testing.T) {
	canonical, _, err := CanonicalVocabulary(context.Background(), validVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	validated, err := DecodeVocabulary(context.Background(), canonical)
	if err != nil {
		t.Fatal(err)
	}
	first := validated.Value()
	first.Definitions[0].ConsumerModules[0] = "mutated.module"
	first.Definitions = nil
	second := validated.Value()
	if len(second.Definitions) != 3 || second.Definitions[0].ConsumerModules[0] != "model.projector" {
		t.Fatal("validated value aliases returned slices")
	}
}

func TestStrictDecodingRejectsMalformedNoncanonicalDeepAndTamperedRecords(t *testing.T) {
	canonical, _, err := CanonicalSource(context.Background(), validSource())
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	duplicate := bytes.Replace(canonical, []byte(`"contract_version":"1.0.0"`), []byte(`"contract_version":"1.0.0","contract_version":"1.0.0"`), 1)
	noncanonical := append(append([]byte(nil), canonical...), '\n')
	tampered := append([]byte(nil), canonical...)
	index := bytes.Index(tampered, []byte(`"source_digest":"sha256:`)) + len(`"source_digest":"sha256:`)
	if index <= 0 {
		t.Fatal("digest not found")
	}
	if tampered[index] == '0' {
		tampered[index] = '1'
	} else {
		tampered[index] = '0'
	}
	deep := []byte(strings.Repeat("[", MaximumDepth+1) + strings.Repeat("]", MaximumDepth+1))
	for name, test := range map[string]struct {
		input  []byte
		reason string
	}{
		"unknown_field":      {unknown, "document_decoding"},
		"duplicate_member":   {duplicate, "document_decoding"},
		"noncanonical_bytes": {noncanonical, "document_canonical"},
		"digest_tamper":      {tampered, "record_digest_mismatch"},
		"excessive_depth":    {deep, "document_depth"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSource(context.Background(), test.input); Reason(err) != test.reason {
				t.Fatalf("reason=%q err=%v", Reason(err), err)
			}
		})
	}
}

func TestCrossFieldBoundsAndTrustInvariantsFailClosed(t *testing.T) {
	for name, test := range map[string]struct {
		run    func() error
		reason string
	}{
		"event_class_mismatch": {func() error {
			value := validVocabulary()
			value.Definitions[0].Persistence = "ephemeral"
			_, err := SealVocabulary(context.Background(), value)
			return err
		}, "event_class_binding"},
		"content_length_bound": {func() error {
			value := validSource()
			value.Content.Length = MaximumInputBytes + 1
			_, err := SealSource(context.Background(), value)
			return err
		}, "source"},
		"untrusted_instruction": {func() error {
			value := validSource()
			value.InstructionDisposition = "trusted_system_instruction"
			_, err := SealSource(context.Background(), value)
			return err
		}, "instruction_disposition"},
		"projection_order": {func() error {
			value := validProjection()
			value.OrderedItems[1].Ordinal = 3
			_, err := SealProjection(context.Background(), value)
			return err
		}, "projected_item"},
		"artifact_set_drift": {func() error {
			value := validProjection()
			value.ArtifactDigests = []string{digest('f')}
			_, err := SealProjection(context.Background(), value)
			return err
		}, "projection_artifact_set"},
		"deadline_not_after_creation": {func() error {
			value := validBinding()
			value.Deadline = value.CreatedAt
			_, err := SealBinding(context.Background(), value)
			return err
		}, "binding"},
		"implicit_empty_stream": {func() error {
			value := validStream()
			value.Kind, value.Outcome = "terminal", "empty"
			_, err := SealStreamEvent(context.Background(), value)
			return err
		}, "stream_outcome"},
		"self_covering_compaction": {func() error {
			value := validCompaction()
			value.ReplacementSourceRecordID = value.CoveredSources[0].SourceRecordID
			_, err := SealCompaction(context.Background(), value)
			return err
		}, "compaction_coverage"},
		"prepared_with_binding": {func() error {
			value := validTransition()
			value.BindingDigest = digest('a')
			_, err := SealTransition(context.Background(), value)
			return err
		}, "transition_phase"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := test.run(); Reason(err) != test.reason {
				t.Fatalf("reason=%q err=%v", Reason(err), err)
			}
		})
	}
}

func TestDenialCorpusMatchesCoveredFailureClasses(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/model-surface/v1/fixtures/denial-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion   string `json:"schema_version"`
		ContractVersion string `json:"contract_version"`
		Cases           []struct {
			Name           string `json:"name"`
			Record         string `json:"record"`
			ExpectedReason string `json:"expected_reason"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(input, &corpus); err != nil || corpus.SchemaVersion != "coh.model-surface-denial-corpus/v1" || corpus.ContractVersion != ContractVersion {
		t.Fatalf("corpus err=%v value=%#v", err, corpus)
	}
	expected := map[string]string{
		"unknown_field": "document_decoding", "duplicate_member": "document_decoding",
		"noncanonical_bytes": "document_canonical", "excessive_depth": "document_depth",
		"digest_tamper": "record_digest_mismatch", "event_class_mismatch": "event_class_binding",
		"untrusted_instruction": "instruction_disposition", "projection_order": "projected_item",
		"artifact_set_drift": "projection_artifact_set", "deadline_not_after_creation": "binding",
		"implicit_empty_stream": "stream_outcome", "self_covering_compaction": "compaction_coverage",
		"prepared_with_binding": "transition_phase",
	}
	if len(corpus.Cases) != len(expected) {
		t.Fatalf("cases=%d expected=%d", len(corpus.Cases), len(expected))
	}
	for _, test := range corpus.Cases {
		if test.Record == "" || expected[test.Name] != test.ExpectedReason {
			t.Fatalf("uncovered corpus case %#v", test)
		}
		delete(expected, test.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing corpus cases=%v", expected)
	}
}

func TestCanceledContextDeniesCanonicalizationAndDecode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := CanonicalSource(ctx, validSource()); Code(err) != Canceled {
		t.Fatalf("canonical err=%v", err)
	}
	canonical, _, err := CanonicalSource(context.Background(), validSource())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSource(ctx, canonical); Code(err) != Canceled {
		t.Fatalf("decode err=%v", err)
	}
}

func validVocabulary() EventVocabulary {
	return EventVocabulary{SchemaVersion: VocabularySchema, ContractVersion: ContractVersion, VocabularyRevision: 1,
		Definitions: []EventDefinition{
			{EventType: "agent.message", EventVersion: 1, EventClass: "model_surface", Persistence: "durable", ProducerModule: "agent.phase", ConsumerModules: []string{"model.projector", "workflow.agent"}, ProjectionRule: "message", PayloadSchemaDigest: digest('1')},
			{EventType: "audit.record", EventVersion: 1, EventClass: "log_only", Persistence: "durable", ProducerModule: "audit.writer", ConsumerModules: []string{"audit.reader"}, ProjectionRule: "none", PayloadSchemaDigest: digest('2')},
			{EventType: "workflow.signal", EventVersion: 1, EventClass: "live_coordination", Persistence: "ephemeral", ProducerModule: "workflow.engine", ConsumerModules: []string{"workflow.agent"}, ProjectionRule: "none", PayloadSchemaDigest: digest('3')},
		}}
}

func validScopeValue() Scope {
	return Scope{OrganizationID: uuid(1), TenantID: uuid(2), CaseID: uuid(3), TaskID: uuid(4)}
}

func validSource() Source {
	return Source{SchemaVersion: SourceSchema, ContractVersion: ContractVersion, SourceRecordID: uuid(5), EventType: "retrieval.item", EventVersion: 1, EventClass: "model_surface", ProjectionRule: "retrieved_context", Scope: validScopeValue(), RunID: uuid(6), RecordRevision: 2, RecordDigest: digest('4'), Content: ContentBinding{Kind: "immutable_artifact", ContentID: "evidence.context", Digest: digest('5'), MediaType: "application/json", Length: 512, Classification: "restricted", Immutable: true}, Trust: "untrusted_retrieval", InstructionDisposition: "untrusted_data_only", OccurredAt: timestamp(1), Sequence: 7, Immutable: true}
}

func validProjection() Projection {
	items := []ProjectedItem{
		{Ordinal: 1, SurfaceKind: "message", Role: "system", SourceRecordID: uuid(5), SourceRevision: 1, SourceDigest: digest('6'), ContentKind: "durable_record", ContentID: "agent.message", ContentDigest: digest('7'), RenderedDigest: digest('8'), RenderedLength: 32, InstructionDisposition: "trusted_system_instruction"},
		{Ordinal: 2, SurfaceKind: "retrieved_context", Role: "data", SourceRecordID: uuid(7), SourceRevision: 2, SourceDigest: digest('9'), ContentKind: "immutable_artifact", ContentID: "evidence.context", ContentDigest: digest('a'), RenderedDigest: digest('b'), RenderedLength: 512, InstructionDisposition: "untrusted_data_only"},
	}
	return Projection{SchemaVersion: ProjectionSchema, ContractVersion: ContractVersion, ProjectionID: uuid(8), ProjectionVersion: ProjectionVersion, Scope: validScopeValue(), RunID: uuid(6), VocabularyDigest: digest('c'), CompositionDigest: digest('d'), OrderedItems: items, OrderedSourceRecordIDs: []string{uuid(5), uuid(7)}, ArtifactDigests: []string{digest('a')}, SurfaceDigest: digest('e'), CreatedAt: timestamp(2)}
}

func validBinding() InferenceBinding {
	projection, _ := SealProjection(context.Background(), validProjection())
	return InferenceBinding{SchemaVersion: BindingSchema, ContractVersion: ContractVersion, RequestID: uuid(9), AttemptID: uuid(10), Scope: validScopeValue(), RunID: uuid(6), ActorID: uuid(11), ProviderID: "ollama.local", ProjectionID: projection.ProjectionID, ProjectionVersion: ProjectionVersion, ProjectionDigest: projection.ProjectionDigest, OrderedSourceRecordIDs: append([]string(nil), projection.OrderedSourceRecordIDs...), ArtifactDigests: append([]string(nil), projection.ArtifactDigests...), VocabularyDigest: projection.VocabularyDigest, CompositionDigest: projection.CompositionDigest, SurfaceDigest: projection.SurfaceDigest, AuthorizationDigest: digest('1'), PolicyDecisionDigest: digest('2'), ApprovalDecisionDigest: digest('3'), AuditReservationDigest: digest('4'), CreatedAt: timestamp(3), Deadline: timestamp(4)}
}

func validStream() StreamEvent {
	binding, _ := SealBinding(context.Background(), validBinding())
	return StreamEvent{SchemaVersion: StreamSchema, ContractVersion: ContractVersion, RequestID: binding.RequestID, AttemptID: binding.AttemptID, BindingDigest: binding.BindingDigest, ProjectionDigest: binding.ProjectionDigest, InputSurfaceDigest: binding.SurfaceDigest, Sequence: 1, Kind: "started", SourceRecordIDs: []string{uuid(5), uuid(7)}, ChunkDigest: "", AssembledDigest: "", Outcome: "pending", ObservedAt: timestamp(5)}
}

func validCompaction() CompactionReplacement {
	return CompactionReplacement{SchemaVersion: CompactionSchema, ContractVersion: ContractVersion, ReplacementID: uuid(12), Scope: validScopeValue(), RunID: uuid(6), CompactionID: uuid(13), ReplacementSourceRecordID: uuid(14), CoveredSources: []CoveredSource{
		{Ordinal: 1, SourceRecordID: uuid(5), SourceDigest: digest('5'), EvidenceIDs: []string{uuid(15)}, NormalizedTime: timestamp(1), OriginalTimezone: "America/Denver", Precision: "second", ClockUncertaintyNanoseconds: 1000000000, OrderConfidence: "strict", ResultState: "observed", Completeness: "complete", Uncertainty: "clock"},
		{Ordinal: 2, SourceRecordID: uuid(7), SourceDigest: digest('7'), EvidenceIDs: []string{uuid(16)}, NormalizedTime: timestamp(2), OriginalTimezone: "UTC", Precision: "millisecond", ClockUncertaintyNanoseconds: 500000000, OrderConfidence: "overlap", ResultState: "negative", Completeness: "partial", Uncertainty: "bounded"},
	}, SummaryArtifact: Artifact{ArtifactID: "compaction.summary", Digest: digest('8'), MediaType: "application/json", Length: 256, Classification: "restricted", Immutable: true}, CreatedAt: timestamp(6)}
}

func validTransition() Transition {
	projection, _ := SealProjection(context.Background(), validProjection())
	return Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion, TransitionID: uuid(17), RequestID: uuid(9), AttemptID: uuid(10), Scope: validScopeValue(), RunID: uuid(6), Phase: "prepared", Revision: 1, ProjectionDigest: projection.ProjectionDigest, BindingDigest: "", ProviderRoute: "ollama.local", ProviderAttempt: 1, StreamCursor: 0, TerminalOutcome: "", PreviousTransitionDigest: "", CreatedAt: timestamp(3), UpdatedAt: timestamp(3)}
}

func decodeVocabularyTest(input []byte) ([]byte, string, error) {
	value, err := DecodeVocabulary(context.Background(), input)
	return value.CanonicalBytes(), value.Digest(), err
}
func decodeSourceTest(input []byte) ([]byte, string, error) {
	value, err := DecodeSource(context.Background(), input)
	return value.CanonicalBytes(), value.Digest(), err
}
func decodeProjectionTest(input []byte) ([]byte, string, error) {
	value, err := DecodeProjection(context.Background(), input)
	return value.CanonicalBytes(), value.Digest(), err
}
func decodeBindingTest(input []byte) ([]byte, string, error) {
	value, err := DecodeBinding(context.Background(), input)
	return value.CanonicalBytes(), value.Digest(), err
}
func decodeStreamTest(input []byte) ([]byte, string, error) {
	value, err := DecodeStreamEvent(context.Background(), input)
	return value.CanonicalBytes(), value.Digest(), err
}
func decodeCompactionTest(input []byte) ([]byte, string, error) {
	value, err := DecodeCompaction(context.Background(), input)
	return value.CanonicalBytes(), value.Digest(), err
}
func decodeTransitionTest(input []byte) ([]byte, string, error) {
	value, err := DecodeTransition(context.Background(), input)
	return value.CanonicalBytes(), value.Digest(), err
}

func uuid(value int) string {
	return "0199a213-0000-7000-8000-" + strings.Repeat("0", 12-len(formatUint(uint64(value)))) + formatUint(uint64(value))
}
func digest(value byte) string    { return "sha256:" + string(bytes.Repeat([]byte{value}, 64)) }
func timestamp(second int) string { return "2026-08-28T09:00:" + leftPad(second, 2) + ".000000000Z" }
func leftPad(value, width int) string {
	text := formatUint(uint64(value))
	return strings.Repeat("0", width-len(text)) + text
}
