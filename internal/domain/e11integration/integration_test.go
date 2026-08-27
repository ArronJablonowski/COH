package e11integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/entityresolution"
	"github.com/ArronJablonowski/COH/internal/domain/investigationprojection"
	"github.com/ArronJablonowski/COH/internal/domain/mappingregistry"
	"github.com/ArronJablonowski/COH/internal/domain/normalizedevent"
	"github.com/ArronJablonowski/COH/internal/domain/temporaltime"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func TestPinnedVendorEnvelopeReproducesEntityAndInvestigationViews(t *testing.T) {
	chain := integrationChain(t)
	value := chain.Envelope.Value()
	original := append([]byte(nil), value.Original.Fields...)
	if !bytes.Contains(original, []byte(`"event":{"code":"4624"}`)) ||
		!bytes.Contains(original, []byte(`"host":{"name":"ws-01"}`)) ||
		!bytes.Contains(original, []byte(`"winlog":{"event_id":4624}`)) {
		t.Fatalf("original vendor fields not recoverable: %s", original)
	}
	value.Original.Fields[0] = '['
	if bytes.Equal(value.Original.Fields, chain.Envelope.Value().Original.Fields) {
		t.Fatal("validated envelope exposed mutable original vendor fields")
	}
	if err := Verify(context.Background(), chain); err != nil {
		t.Fatal(err)
	}
	if chain.TimeComparison.Outcome != temporaltime.UnknownComparison ||
		chain.TimeComparison.Confidence != temporaltime.UnknownConfidence || chain.TimeRecord.NormalizedUTC != nil ||
		chain.TimeRecord.TimezoneResult.Assertion.Kind != temporaltime.MissingTimezone {
		t.Fatalf("time chain invented certainty: record=%+v comparison=%+v", chain.TimeRecord, chain.TimeComparison)
	}
	first := replayViews(t, chain.Facts, chain.StateVersion)
	second := replayViews(t, chain.Facts, chain.StateVersion)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("pinned chain did not reproduce: first=%+v second=%+v", first, second)
	}
	if len(first[investigationprojection.Correlation].Value.Claims) != 1 ||
		len(first[investigationprojection.Hypothesis].Value.Hypotheses) != 1 ||
		len(first[investigationprojection.Timeline].Value.Timeline) != 1 {
		t.Fatalf("incomplete views: %+v", first)
	}
	timeline := first[investigationprojection.Timeline].Value.Timeline[0]
	if timeline.RelationToPrevious != "uncertain" || timeline.TimeRef.Precision != "unknown" ||
		timeline.TimeRef.TimeRecordDigest != chain.TimeRecordDigest || timeline.TimeRef.ComparisonDigest == nil ||
		*timeline.TimeRef.ComparisonDigest != chain.TimeComparisonDigest || len(timeline.Unknowns) != 1 {
		t.Fatalf("timeline lost uncertainty: %+v", timeline)
	}
}

func TestIntegrationVerifierRejectsEveryCrossLeafBindingDrift(t *testing.T) {
	tests := map[string]func(*Chain){
		"mapping envelope": func(chain *Chain) {
			changed := digest("changed-envelope")
			chain.MappingOutcome.NormalizedEnvelopeDigest = &changed
			_, chain.MappingOutcomeDigest, _ = mappingregistry.CanonicalOutcome(context.Background(), chain.MappingOutcome)
		},
		"entity mapping": func(chain *Chain) {
			chain.Observation.Evidence.MappingOutcomeDigest = digest("changed-mapping-outcome")
			_, chain.ObservationDigest, _ = entityresolution.CanonicalObservation(context.Background(), chain.Observation)
		},
		"entity revision": func(chain *Chain) { chain.EntityRef.RecordDigest = digest("changed-entity") },
		"time envelope": func(chain *Chain) {
			chain.TimeRecord.SourceBinding.EnvelopeDigest = digest("changed-time-envelope")
			_, chain.TimeRecordDigest, _ = temporaltime.CanonicalRecord(context.Background(), chain.TimeRecord)
		},
		"time comparison": func(chain *Chain) { chain.TimeComparisonDigest = digest("changed-comparison") },
		"projection envelope": func(chain *Chain) {
			chain.Facts[0].Binding.NormalizedEventDigest = digest("changed-projection-envelope")
		},
		"projection entity": func(chain *Chain) {
			chain.Facts[0].Binding.EntityRefs[0].RecordDigest = digest("changed-projection-entity")
			chain.Facts[0].EntityRefs[0].RecordDigest = digest("changed-projection-entity")
		},
		"projection time": func(chain *Chain) {
			chain.Facts[0].Binding.TimeRefs[0].TimeRecordDigest = digest("changed-projection-time")
			chain.Facts[0].TimeRefs[0].TimeRecordDigest = digest("changed-projection-time")
		},
		"state mapping": func(chain *Chain) { chain.StateVersion.MappingRevision++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			chain := integrationChain(t)
			mutate(&chain)
			if err := Verify(context.Background(), chain); !IsBindingError(err) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Verify(canceled, integrationChain(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err=%v", err)
	}
}

func integrationChain(t *testing.T) Chain {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "normalization", "v1", "fixtures", "valid", "event.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := normalizedevent.Decode(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	mappingOutcome, mappingDigest, hint := mappedEnvelopeOutcome(t, envelope)
	observation, observationDigest := mappedObservation(t, envelope, mappingOutcome, mappingDigest, hint)
	entity, entityRef := resolvedEntity(t, observation, observationDigest)
	left, _, comparison, timeDigest, comparisonDigest := unresolvedTimeChain(t, envelope)
	facts, version := projectionFacts(t, envelope, mappingOutcome, mappingDigest, observationDigest, entityRef,
		timeDigest, comparisonDigest)
	return Chain{Envelope: envelope, MappingOutcome: mappingOutcome, MappingOutcomeDigest: mappingDigest,
		Observation: observation, ObservationDigest: observationDigest, Entity: entity, EntityRef: entityRef,
		TimeRecord: left, TimeRecordDigest: timeDigest, TimeComparison: comparison,
		TimeComparisonDigest: comparisonDigest, Facts: facts, StateVersion: version}
}

func mappedEnvelopeOutcome(t *testing.T, envelope normalizedevent.ValidatedEnvelope) (mappingregistry.Outcome, string,
	mappingregistry.EmittedEntityHint) {
	t.Helper()
	value := envelope.Value()
	hint := mappingregistry.EmittedEntityHint{RuleID: "host-name", OutputPath: "ocsf.device.name",
		SourceFieldDigest: digest("original.host.name"), Role: "host.name", IdentifierType: "hostname",
		Normalization: "lowercase_ascii", ConfidenceCeilingMillionths: 900_000}
	envelopeDigest := envelope.Digest()
	outcome := mappingregistry.Outcome{SchemaVersion: mappingregistry.OutcomeSchemaVersion,
		ContractVersion: mappingregistry.ContractVersion, OperationID: uuid(20), CommandDigest: digest("mapping-command"),
		MappingDigest: value.Normalization.MappingSetDigest, RegistryRevision: 7, Status: mappingregistry.Applied,
		ReasonCode: mappingregistry.AppliedReason, NormalizedEnvelopeDigest: &envelopeDigest,
		Coverage: value.Normalization.Coverage, AppliedRules: []string{"host-name"}, UnmappedPaths: []string{},
		LossyPaths: []string{}, EntityHints: []mappingregistry.EmittedEntityHint{hint},
		ReverseResults: []mappingregistry.ReverseResult{}, CreatedAt: "2026-08-27T00:00:01.000000000Z"}
	_, outcomeDigest, err := mappingregistry.CanonicalOutcome(context.Background(), outcome)
	if err != nil {
		t.Fatal(err)
	}
	return outcome, outcomeDigest, hint
}

func mappedObservation(t *testing.T, envelope normalizedevent.ValidatedEnvelope, outcome mappingregistry.Outcome,
	outcomeDigest string, hint mappingregistry.EmittedEntityHint) (entityresolution.Observation, string) {
	t.Helper()
	value := envelope.Value()
	observation, _, observationDigest, err := entityresolution.NewObservation(context.Background(), entityresolution.ObservationInput{
		ObservationID: uuid(30), OperationID: uuid(31), Scope: entityresolution.Scope{OrganizationID: value.Case.OrganizationID,
			TenantID: value.Case.TenantID, CaseID: value.Case.CaseID}, MatchDigest: digest("case-keyed-host"),
		DerivationKeyRevision: 1, Hint: hint, Evidence: entityresolution.ObservationEvidence{
			EnvelopeID: value.EnvelopeID, EnvelopeDigest: envelope.Digest(), Classification: value.Classification,
			SourceIdentityDigest: value.Source.IdentityDigest, TransformationDigest: value.Normalization.TransformationDigest,
			ArtifactDigest: value.Lineage.RawArtifact.Digest, RawManifestDigest: value.Lineage.RawManifestDigest,
			IngestReceiptDigest:    value.Lineage.IngestReceiptDigest,
			SourceProvenanceDigest: value.Lineage.SourceProvenanceDigest, MappingManifestDigest: outcome.MappingDigest,
			MappingRevision: outcome.RegistryRevision, MappingOutcomeDigest: outcomeDigest},
		ObservedAt: "2026-08-27T00:00:02.000000000Z"})
	if err != nil {
		t.Fatal(err)
	}
	return observation, observationDigest
}

func resolvedEntity(t *testing.T, observation entityresolution.Observation, observationDigest string) (entityresolution.Entity,
	entityresolution.EntityRef) {
	t.Helper()
	bindingDigest := canonicalDigest(t, observation.Evidence)
	link := entityresolution.EvidenceLink{ObservationID: observation.ObservationID, ObservationDigest: observationDigest,
		EvidenceBindingDigest: bindingDigest, SourceFamilyDigest: digest("windows-security"),
		IndependenceGroupDigest: digest("collector-a")}
	confidence, _, _, err := entityresolution.ComposeConfidence(context.Background(), entityresolution.ConfidenceInput{
		Evidence: []entityresolution.ConfidenceEvidenceInput{{Observation: observation, ObservationDigest: observationDigest,
			Link: link, SourceQuality: "high", Recency: "current"}}, Counterevidence: []entityresolution.Counterevidence{}})
	if err != nil {
		t.Fatal(err)
	}
	entity := entityresolution.Entity{SchemaVersion: entityresolution.EntitySchemaVersion,
		ContractVersion: entityresolution.ContractVersion, MethodVersion: entityresolution.MethodVersion,
		EntityID: uuid(40), Revision: 1, Scope: observation.Scope, Status: "active",
		Classification: observation.Evidence.Classification,
		MemberObservations: []entityresolution.ObservationRef{{ObservationID: observation.ObservationID,
			ObservationDigest: observationDigest}}, AliasProofs: []entityresolution.AliasProof{}, Confidence: confidence,
		CreationDecisionDigest: digest("entity-decision"), HistoryHeadDigest: digest("entity-history"),
		AuditDigest: digest("entity-audit"), PreviousProvenanceDigests: []string{},
		ProvenanceDigest: digest("entity-provenance"), CreatedAt: "2026-08-27T00:00:03.000000000Z",
		UpdatedAt: "2026-08-27T00:00:03.000000000Z"}
	_, recordDigest, err := entityresolution.EntityRecordDigest(context.Background(), entity)
	if err != nil {
		t.Fatal(err)
	}
	return entity, entityresolution.EntityRef{EntityID: entity.EntityID, Revision: entity.Revision, RecordDigest: recordDigest}
}

func unresolvedTimeChain(t *testing.T, envelope normalizedevent.ValidatedEnvelope) (temporaltime.Record, temporaltime.Record,
	temporaltime.Comparison, string, string) {
	t.Helper()
	left := unresolvedTimeRecord(t, envelope, 50, "time-left")
	right := unresolvedTimeRecord(t, envelope, 51, "time-right")
	comparison, err := temporaltime.CompareRecords(context.Background(), uuid(52), left, right,
		mustTime("2026-08-27T00:00:06.000000000Z"))
	if err != nil {
		t.Fatal(err)
	}
	_, leftDigest, err := temporaltime.CanonicalRecord(context.Background(), left)
	if err != nil {
		t.Fatal(err)
	}
	_, comparisonDigest, err := temporaltime.CanonicalComparison(context.Background(), comparison)
	if err != nil {
		t.Fatal(err)
	}
	return left, right, comparison, leftDigest, comparisonDigest
}

func unresolvedTimeRecord(t *testing.T, envelope normalizedevent.ValidatedEnvelope, suffix int, dedup string) temporaltime.Record {
	t.Helper()
	value := envelope.Value()
	estimate, radius := int64(0), int64(time.Second)
	command := temporaltime.Command{SchemaVersion: temporaltime.CommandSchemaVersion,
		ContractVersion: temporaltime.ContractVersion, OperationID: uuid(suffix), IdempotencyKey: digest("time-command-" + dedup),
		Case: temporaltime.Case{OrganizationID: value.Case.OrganizationID, TenantID: value.Case.TenantID, CaseID: value.Case.CaseID},
		SourceBinding: temporaltime.SourceBinding{EnvelopeID: value.EnvelopeID, EnvelopeDigest: envelope.Digest(),
			ArtifactDigest: value.Lineage.RawArtifact.Digest, ManifestDigest: value.Lineage.RawManifestDigest,
			IngestReceiptDigest:    value.Lineage.IngestReceiptDigest,
			SourceProvenanceDigest: value.Lineage.SourceProvenanceDigest, SourceIdentityDigest: value.Source.IdentityDigest,
			FieldSelector: "original.event.created", DeduplicationDigest: digest(dedup)},
		OriginalTime: temporaltime.OriginalTime{Text: "2026-11-01 01:30:00", Format: "vendor_local",
			Precision: temporaltime.Second}, Parser: temporaltime.ParserIdentity{Name: "vendor_time", Version: "1.0.0",
			Digest: digest("time-parser")}, Timezone: temporaltime.TimezoneAssertion{Kind: temporaltime.MissingTimezone},
		Calibration: temporaltime.Calibration{State: temporaltime.KnownCalibration, ClockKind: temporaltime.DeviceClock,
			Identity: "sensor-17", IdentityDigest: digest("clock"), EstimateNanoseconds: &estimate,
			RadiusNanoseconds: &radius}, EvidenceState: temporaltime.Partial,
		Completeness: temporaltime.PartialCompleteness, RequestedAt: "2026-08-27T00:00:04.000000000Z",
		Deadline: "2026-08-27T00:00:10.000000000Z"}
	record, err := temporaltime.BuildRecord(context.Background(), command,
		temporaltime.CivilTime{Year: 2026, Month: time.November, Day: 1, Hour: 1, Minute: 30,
			Precision: temporaltime.Second}, temporaltime.TimezoneResolution{DSTState: temporaltime.DSTUnresolved},
		command.Calibration, mustTime("2026-08-27T00:00:05.000000000Z"))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func projectionFacts(t *testing.T, envelope normalizedevent.ValidatedEnvelope, mapping mappingregistry.Outcome,
	mappingDigest, observationDigest string, entity entityresolution.EntityRef, timeDigest, comparisonDigest string) (
	[]investigationprojection.Fact, investigationprojection.StateVersion) {
	t.Helper()
	value := envelope.Value()
	scope := investigationprojection.Scope{OrganizationID: value.Case.OrganizationID, TenantID: value.Case.TenantID,
		CaseID: value.Case.CaseID}
	entityRef := investigationprojection.EntityRef{EntityID: entity.EntityID, Revision: entity.Revision,
		RecordDigest: entity.RecordDigest}
	comparison := comparisonDigest
	timeRef := investigationprojection.TimeRef{TimeRecordDigest: timeDigest, ComparisonDigest: &comparison,
		Precision: "unknown", UncertaintyDigest: digest("timezone-unresolved")}
	authoritative := digest("e11-authoritative-state")
	binding := investigationprojection.AuthoritativeBinding{CaseRevision: 1, CaseDigest: digest("case"),
		ArtifactDigest: value.Lineage.RawArtifact.Digest, ManifestDigest: value.Lineage.RawManifestDigest,
		IngestReceiptDigest: value.Lineage.IngestReceiptDigest, CustodyHeadDigest: digest("custody-head"),
		AuditHeadDigest: digest("audit-head"), SourceProvenanceDigest: value.Lineage.SourceProvenanceDigest,
		NormalizedEventDigest: envelope.Digest(), NormalizedEventSchemaVersion: normalizedevent.EnvelopeSchemaVersion,
		MappingOutcomeDigest: mappingDigest, MappingManifestDigest: mapping.MappingDigest,
		MappingRevision: mapping.RegistryRevision, EntityRefs: []investigationprojection.EntityRef{entityRef},
		TimeRefs: []investigationprojection.TimeRef{timeRef}, AuthoritativeStateDigest: authoritative}
	unknown := investigationprojection.Unknown{Code: "missing_timezone", BasisDigest: timeDigest}
	completeness := investigationprojection.Completeness{Status: "partial",
		QueriedSourceDigests: []string{value.Source.IdentityDigest}, CompletedSourceDigests: []string{},
		GapDigests: []string{digest("time-gap")}, NegativeEvidenceDigests: []string{},
		ConflictDigests: []string{}}
	confidence := investigationprojection.Confidence{Method: "coh.projection-confidence",
		MethodVersion: investigationprojection.ReducerVersion, BasisDigest: observationDigest,
		ValueMillionths: 700_000, Label: "medium"}
	claimID, hypothesisID := "claim-login", "hypothesis-account-use"
	first := investigationprojection.Fact{SchemaVersion: investigationprojection.FactSchemaVersion,
		ContractVersion: investigationprojection.ContractVersion, ReducerVersion: investigationprojection.ReducerVersion,
		FactID: uuid(60), Scope: scope, Sequence: 1, FactType: "claim", SubjectID: "login-event",
		ClaimID: &claimID, GapDigests: []string{}, ConflictDigests: []string{},
		SupportingEvidenceDigests: []string{observationDigest}, CounterevidenceDigests: []string{},
		Unknowns: []investigationprojection.Unknown{unknown}, EntityRefs: []investigationprojection.EntityRef{entityRef},
		TimeRefs: []investigationprojection.TimeRef{timeRef}, Confidence: &confidence, Completeness: completeness,
		Binding: binding, PayloadDigest: digest("claim-payload"), CommittedAt: "2026-08-27T00:00:07.000000000Z"}
	_, head, err := investigationprojection.CanonicalFact(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	previousFirst := head
	disposition := "inconclusive"
	second := first
	second.FactID, second.Sequence, second.PreviousFactDigest = uuid(61), 2, &previousFirst
	second.FactType, second.SubjectID, second.HypothesisID = "hypothesis_disposition", "account-use", &hypothesisID
	second.HypothesisDisposition, second.PayloadDigest = &disposition, digest("hypothesis-payload")
	second.CommittedAt = "2026-08-27T00:00:08.000000000Z"
	_, head, err = investigationprojection.CanonicalFact(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	previousSecond := head
	relation, order := "uncertain", uint32(200_000)
	third := first
	third.FactID, third.Sequence, third.PreviousFactDigest = uuid(62), 3, &previousSecond
	third.FactType, third.SubjectID = "time_order", "login-time"
	third.HypothesisID, third.HypothesisDisposition = nil, nil
	third.TimeRelation, third.OrderConfidenceMillionths = &relation, &order
	third.GapDigests, third.PayloadDigest = []string{digest("time-gap")}, digest("timeline-payload")
	third.CommittedAt = "2026-08-27T00:00:09.000000000Z"
	if _, _, err := investigationprojection.CanonicalFact(context.Background(), third); err != nil {
		t.Fatal(err)
	}
	version := investigationprojection.StateVersion{ReducerVersion: investigationprojection.ReducerVersion,
		ProjectionSchemaVersion:      investigationprojection.ProjectionSchemaVersion,
		NormalizedEventSchemaVersion: normalizedevent.EnvelopeSchemaVersion,
		MappingContractVersion:       mappingregistry.ContractVersion, MappingManifestDigest: mapping.MappingDigest,
		MappingRevision: mapping.RegistryRevision, EntityContractVersion: entityresolution.ContractVersion,
		EntityHeadDigest: entity.RecordDigest, TimeContractVersion: temporaltime.ContractVersion,
		TimeMethodVersion: investigationprojection.ReducerVersion, AuthoritativeStateDigest: authoritative}
	return []investigationprojection.Fact{first, second, third}, version
}

func replayViews(t *testing.T, facts []investigationprojection.Fact, version investigationprojection.StateVersion) map[investigationprojection.Kind]*investigationprojection.ReductionState {
	t.Helper()
	result := make(map[investigationprojection.Kind]*investigationprojection.ReductionState)
	for _, kind := range []investigationprojection.Kind{investigationprojection.Correlation,
		investigationprojection.Hypothesis, investigationprojection.Timeline} {
		reducer, err := investigationprojection.NewReducer(kind)
		if err != nil {
			t.Fatal(err)
		}
		var state *investigationprojection.ReductionState
		for _, fact := range facts {
			state, err = reducer.Reduce(context.Background(), state, fact, version)
			if err != nil {
				t.Fatalf("kind=%s sequence=%d: %v", kind, fact.Sequence, err)
			}
		}
		result[kind] = state
	}
	return result
}

func canonicalDigest(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return digestBytes(canonical)
}

func digest(value string) string { return digestBytes([]byte(value)) }
func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func uuid(value int) string { return fmt.Sprintf("0198e300-1100-7000-8000-%012d", value) }
func mustTime(value string) time.Time {
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	if err != nil {
		panic(err)
	}
	return parsed
}
