package mappingregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/normalizedevent"
)

func TestApplyVerifiedMappingPreservesEnvelopeAndEmitsDeterministicResults(t *testing.T) {
	fixture := newApplicationFixture(t)
	result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	before, after := fixture.input.Value(), result.Envelope.Value()
	if result.Coverage != "complete" || len(result.UnmappedPaths) != 0 || len(result.LossyPaths) != 0 ||
		len(result.AppliedRules) != len(fixture.selected.Signed.Manifest.Rules) || len(result.ReverseResults) != 4 || len(result.EntityHints) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if !bytes.Equal(before.Original.Fields, after.Original.Fields) || before.Original.FieldsDigest != after.Original.FieldsDigest ||
		before.Case != after.Case || before.Source != after.Source || before.Classification != after.Classification ||
		before.Lineage.RawArtifact != after.Lineage.RawArtifact || before.Lineage.RawManifestDigest != after.Lineage.RawManifestDigest ||
		before.Lineage.IngestReceiptDigest != after.Lineage.IngestReceiptDigest || before.Lineage.SourceProvenanceDigest != after.Lineage.SourceProvenanceDigest {
		t.Fatalf("preservation failed before=%+v after=%+v", before, after)
	}
	if after.EnvelopeID != fixture.command.OperationID || result.Envelope.Digest() == fixture.input.Digest() ||
		!reflect.DeepEqual(after.Lineage.ParentEnvelopeDigests, []string{fixture.input.Digest()}) {
		t.Fatalf("identity/lineage after=%+v digest=%s", after.Lineage, result.Envelope.Digest())
	}
	if after.Normalization.MappingSetDigest != fixture.selected.ManifestDigest || after.Normalization.Normalizer.Name != fixture.selected.Signed.Manifest.Name ||
		after.Normalization.Coverage != "complete" || len(after.Normalization.UnmappedVendorPaths) != 0 {
		t.Fatalf("normalization=%+v", after.Normalization)
	}
	if !bytes.Contains(after.OCSF.Event, []byte(`"type_uid":300201`)) || after.ECS == nil ||
		!bytes.Contains(after.ECS.Fields, []byte(`"event":{"code":"4624"}`)) {
		t.Fatalf("OCSF=%s ECS=%+v", after.OCSF.Event, after.ECS)
	}
	hint := result.EntityHints[0]
	if hint.RuleID != "host-name" || hint.OutputPath != "ocsf.device.name" || hint.SourceFieldDigest == "" ||
		bytes.Contains(result.Envelope.CanonicalBytes(), []byte(hint.SourceFieldDigest+`ws-01`)) {
		t.Fatalf("hint=%+v", hint)
	}
	again, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
	if err != nil || again.Envelope.Digest() != result.Envelope.Digest() || !reflect.DeepEqual(again, result) {
		t.Fatalf("repeat digest=%s err=%v result=%+v", again.Envelope.Digest(), err, again)
	}
}

func TestApplyVerifiedMappingRecordsUnmappedLossyAndOptionalState(t *testing.T) {
	t.Run("unmapped partial", func(t *testing.T) {
		fixture := newApplicationFixture(t)
		removeApplicationRule(&fixture.selected.Signed.Manifest, "message")
		fixture.selected.Signed.Manifest.UnmappedPolicy = "record_partial"
		refreshApplicationMapping(t, fixture)
		result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
		if err != nil || result.Coverage != "partial" || !reflect.DeepEqual(result.UnmappedPaths, []string{"original.message"}) ||
			!reflect.DeepEqual(result.Envelope.Value().Normalization.UnmappedVendorPaths, []string{"message"}) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})

	t.Run("deny unmapped", func(t *testing.T) {
		fixture := newApplicationFixture(t)
		removeApplicationRule(&fixture.selected.Signed.Manifest, "message")
		refreshApplicationMapping(t, fixture)
		result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
		if Code(err) != DeniedError || ErrorReason(err) != UnmappedFieldDenied || result.Envelope.Digest() != "" {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})

	t.Run("optional absent", func(t *testing.T) {
		fixture := newApplicationFixture(t)
		path := "original.optional"
		rule := executionRule("optional", uint16(len(fixture.selected.Signed.Manifest.Rules)+1), Copy, &path, "ecs", "ecs.optional.value", String, String)
		rule.Required = false
		fixture.selected.Signed.Manifest.Rules = append(fixture.selected.Signed.Manifest.Rules, rule)
		fixture.selected.Signed.Manifest.UnmappedPolicy = "record_partial"
		refreshApplicationMapping(t, fixture)
		result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
		if err != nil || !reflect.DeepEqual(result.UnmappedPaths, []string{"original.optional"}) || result.Coverage != "partial" {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})

	t.Run("lossy conversion", func(t *testing.T) {
		fixture := newApplicationFixture(t)
		for index := range fixture.selected.Signed.Manifest.Rules {
			rule := &fixture.selected.Signed.Manifest.Rules[index]
			if rule.RuleID == "event-code" {
				rule.Operation, rule.OutputType = ToInteger, Integer
				rule.IntegerRange = &IntegerRange{Minimum: 0, Maximum: 999999}
				rule.Reversibility, rule.LossState, rule.LossReason = "not_reversible", "lossy", "type_narrowing"
			}
		}
		refreshApplicationMapping(t, fixture)
		result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
		if err != nil || result.Coverage != "partial" || len(result.UnmappedPaths) != 0 ||
			!reflect.DeepEqual(result.LossyPaths, []string{"original.event.code"}) ||
			!reflect.DeepEqual(result.Envelope.Value().Normalization.UnmappedVendorPaths, []string{"event.code"}) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
}

func TestApplyVerifiedMappingPreservesFixedDecimalAsExplicitUnmapped(t *testing.T) {
	fixture := newApplicationFixture(t)
	value := fixture.input.Value()
	value.Original.Fields = json.RawMessage(`{"event":{"code":"4624"},"host":{"name":"ws-01"},"message":"An account was successfully logged on.","score":0.125,"winlog":{"event_id":4624}}`)
	value.Original.FieldsDigest = digestBytes(value.Original.Fields)
	transformation, err := normalizedevent.TransformationDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.Normalization.TransformationDigest = transformation
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fixture.input, err = normalizedevent.Decode(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	bindApplicationInput(fixture)
	fixture.selected.Signed.Manifest.UnmappedPolicy = "record_partial"
	refreshApplicationMapping(t, fixture)
	result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
	if err != nil || !bytes.Equal(result.Envelope.Value().Original.Fields, value.Original.Fields) ||
		!reflect.DeepEqual(result.UnmappedPaths, []string{"original.score"}) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestApplyVerifiedMappingDeniesBindingReverseAndCandidateFailures(t *testing.T) {
	mutations := map[string]func(*applicationFixture){
		"case":            func(value *applicationFixture) { value.command.Case.TenantID = applicationOtherUUID },
		"envelope":        func(value *applicationFixture) { value.command.SourceBinding.EnvelopeID = applicationOtherUUID },
		"envelope digest": func(value *applicationFixture) { value.command.SourceBinding.EnvelopeDigest = testDigest },
		"artifact":        func(value *applicationFixture) { value.command.SourceBinding.ArtifactDigest = testDigest },
		"source method":   func(value *applicationFixture) { value.command.Source.CollectionMethod = "other-method" },
		"source identity": func(value *applicationFixture) {
			digest := testDigest
			value.command.Source.SourceIdentityDigest = &digest
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newApplicationFixture(t)
			mutate(fixture)
			result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input)
			if Code(err) != DeniedError || ErrorReason(err) != EvidenceBindingMismatch || result.Envelope.Digest() != "" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}

	fixture := newApplicationFixture(t)
	fixture.selected.Signed.Manifest.Name = "substituted.mapping"
	if result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input); ErrorReason(err) != ManifestDigestMismatch || result.Envelope.Digest() != "" {
		t.Fatalf("manifest substitution result=%+v err=%v", result, err)
	}
	fixture = newApplicationFixture(t)
	fixture.command.ExpectedRegistryRevision++
	if result, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input); ErrorReason(err) != ManifestDigestMismatch || result.Envelope.Digest() != "" {
		t.Fatalf("revision substitution result=%+v err=%v", result, err)
	}

	fixture = newApplicationFixture(t)
	original := applicationOriginal(t, fixture.input)
	mapped, err := executeMapping(context.Background(), fixture.selected.Signed.Manifest, original)
	if err != nil {
		t.Fatal(err)
	}
	mapped.OCSF = bytes.Replace(mapped.OCSF, []byte(`"name":"ws-01"`), []byte(`"name":"changed"`), 1)
	if _, _, err := validateReverseAndHints(fixture.selected.Signed.Manifest, original, mapped); ErrorReason(err) != ReverseValidationFailed {
		t.Fatalf("reverse tamper err=%v", err)
	}

	fixture = newApplicationFixture(t)
	removeApplicationRule(&fixture.selected.Signed.Manifest, "type-uid")
	refreshApplicationMapping(t, fixture)
	if _, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input); ErrorReason(err) != CoverageInvalid {
		t.Fatalf("invalid candidate err=%v", err)
	}
}

func TestApplyVerifiedMappingCancellationAndRecovery(t *testing.T) {
	fixture := newApplicationFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := applyVerifiedMapping(canceled, fixture.command, fixture.selected, fixture.input); Code(err) != CanceledError || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation err=%v", err)
	}
	if _, err := applyVerifiedMapping(context.Background(), fixture.command, fixture.selected, fixture.input); err != nil {
		t.Fatalf("recovery err=%v", err)
	}
}

const applicationOtherUUID = "0198e300-1000-7000-8000-000000000099"

type applicationFixture struct {
	input    normalizedevent.ValidatedEnvelope
	command  Command
	selected verifiedMapping
}

func newApplicationFixture(t *testing.T) *applicationFixture {
	t.Helper()
	inputBytes, err := os.ReadFile("../../../contracts/normalization/v1/fixtures/valid/event.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	input, err := normalizedevent.Decode(context.Background(), bytes.TrimSpace(inputBytes))
	if err != nil {
		t.Fatal(err)
	}
	manifest := applicationManifest(input.Value())
	_, digest, err := CanonicalManifest(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &applicationFixture{input: input, selected: verifiedMapping{
		Signed: SignedMapping{Manifest: manifest, ManifestDigest: digest}, ManifestDigest: digest, RegistryRevision: 3,
	}}
	fixture.command = Command{OperationID: "0198e300-1000-7000-8000-000000000001", Operation: Apply,
		Source: manifest.Source, MappingDigest: digest, ExpectedRegistryRevision: 3}
	bindApplicationInput(fixture)
	return fixture
}

func bindApplicationInput(fixture *applicationFixture) {
	value := fixture.input.Value()
	fixture.command.Case = Case{OrganizationID: value.Case.OrganizationID, TenantID: value.Case.TenantID, CaseID: value.Case.CaseID}
	fixture.command.SourceBinding = SourceBinding{EnvelopeID: value.EnvelopeID, EnvelopeDigest: fixture.input.Digest(),
		ArtifactDigest: value.Lineage.RawArtifact.Digest, ManifestDigest: value.Lineage.RawManifestDigest,
		IngestReceiptDigest: value.Lineage.IngestReceiptDigest, SourceProvenanceDigest: value.Lineage.SourceProvenanceDigest,
		OriginalFieldsDigest: value.Original.FieldsDigest}
}

func applicationManifest(input normalizedevent.Envelope) Manifest {
	manifest := validManifest()
	identity := input.Source.IdentityDigest
	manifest.Source.SourceKind = input.Source.Kind
	manifest.Source.CollectionMethod = input.Source.CollectionMethod
	manifest.Source.CollectionMethodVersion = input.Source.CollectionMethodVersion
	manifest.Source.SourceIdentityDigest = &identity
	manifest.IgnoredFields = []IgnoredField{}
	manifest.Limits = Limits{MaxRules: 32, MaxInputLeaves: 64, MaxOutputLeaves: 64, MaxValueBytes: 4096, MaxDepth: 16}
	host, code, message, eventID := "original.host.name", "original.event.code", "original.message", "original.winlog.event_id"
	manifest.Rules = []Rule{
		applicationConstant("activity-id", 1, "ocsf.activity_id", Integer, `1`),
		applicationConstant("category-uid", 2, "ocsf.category_uid", Integer, `3`),
		applicationConstant("class-uid", 3, "ocsf.class_uid", Integer, `3002`),
		applicationConstant("severity-id", 4, "ocsf.severity_id", Integer, `1`),
		applicationConstant("event-time", 5, "ocsf.time", Integer, `1787798400000`),
		applicationConstant("type-uid", 6, "ocsf.type_uid", Integer, `300201`),
		applicationConstant("metadata-version", 7, "ocsf.metadata.version", String, `"1.9.0"`),
		applicationConstant("product-name", 8, "ocsf.metadata.product.name", String, `"COH fixture"`),
		executionRule("event-code", 9, Copy, &code, "ecs", "ecs.event.code", String, String),
		executionRule("host-name", 10, Copy, &host, "ocsf", "ocsf.device.name", String, String),
		executionRule("message", 11, Copy, &message, "ocsf", "ocsf.message", String, String),
		executionRule("winlog-id", 12, Copy, &eventID, "ecs", "ecs.winlog.event_id", Integer, Integer),
	}
	manifest.Rules[9].EntityHint = &EntityHint{Role: "host.name", IdentifierType: "hostname", Normalization: "lowercase_ascii", ConfidenceCeilingMillionths: 900_000}
	return manifest
}

func applicationConstant(id string, sequence uint16, output string, outputType ValueType, value string) Rule {
	return Rule{RuleID: id, Sequence: sequence, Operation: Constant, OutputNamespace: "ocsf", OutputPath: output,
		InputType: outputType, OutputType: outputType, ConstantValue: json.RawMessage(value), EnumTable: []EnumEntry{},
		Reversibility: "not_reversible", LossState: "lossless", LossReason: "constant"}
}

func removeApplicationRule(manifest *Manifest, id string) {
	filtered := manifest.Rules[:0]
	for _, rule := range manifest.Rules {
		if rule.RuleID != id {
			filtered = append(filtered, rule)
		}
	}
	manifest.Rules = filtered
	for index := range manifest.Rules {
		manifest.Rules[index].Sequence = uint16(index + 1)
	}
}

func refreshApplicationMapping(t *testing.T, fixture *applicationFixture) {
	t.Helper()
	_, digest, err := CanonicalManifest(context.Background(), fixture.selected.Signed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.selected.Signed.ManifestDigest = digest
	fixture.selected.ManifestDigest = digest
	fixture.command.MappingDigest = digest
}

func applicationOriginal(t *testing.T, input normalizedevent.ValidatedEnvelope) map[string]any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input.Value().Original.Fields))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
