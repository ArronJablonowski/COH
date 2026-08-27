package investigationprojection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestReducersArePureOrderedAndDeterministicAtCommonWatermark(t *testing.T) {
	for _, kind := range []Kind{Correlation, Hypothesis, Timeline} {
		t.Run(string(kind), func(t *testing.T) {
			reducer, err := NewReducer(kind)
			if err != nil {
				t.Fatal(err)
			}
			first := validProjectionFact(t, 1, nil, "claim")
			firstState, err := reducer.Reduce(context.Background(), nil, first, fixtureStateVersion())
			if err != nil {
				t.Fatal(err)
			}
			_, firstDigest, err := CanonicalFact(context.Background(), first)
			if err != nil {
				t.Fatal(err)
			}
			second := validProjectionFact(t, 2, &firstDigest, "observation")
			secondState, err := reducer.Reduce(context.Background(), firstState, second, fixtureStateVersion())
			if err != nil {
				t.Fatal(err)
			}
			againFirst, err := reducer.Reduce(context.Background(), nil, first, fixtureStateVersion())
			if err != nil {
				t.Fatal(err)
			}
			againSecond, err := reducer.Reduce(context.Background(), againFirst, second, fixtureStateVersion())
			if err != nil || !reflect.DeepEqual(secondState, againSecond) || secondState.Watermark.Sequence != 2 ||
				secondState.FactCount != 2 || secondState.StateVersion != fixtureStateVersion() {
				t.Fatalf("state=%+v again=%+v err=%v", secondState, againSecond, err)
			}
		})
	}
}

func TestReducersExposeClaimsHypothesesTimelineAndNoOpIdentity(t *testing.T) {
	claimFact := validProjectionFact(t, 1, nil, "claim")
	_, claimDigest, err := CanonicalFact(context.Background(), claimFact)
	if err != nil {
		t.Fatal(err)
	}

	correlation, _ := NewReducer(Correlation)
	correlationState, err := correlation.Reduce(context.Background(), nil, claimFact, fixtureStateVersion())
	if err != nil || len(correlationState.Value.Claims) != 1 || correlationState.Value.Claims[0].ClaimDigest != claimFact.PayloadDigest {
		t.Fatalf("correlation=%+v err=%v", correlationState, err)
	}
	noOp := validProjectionFact(t, 2, &claimDigest, "observation")
	noOpState, err := correlation.Reduce(context.Background(), correlationState, noOp, fixtureStateVersion())
	if err != nil || noOpState.Value != correlationState.Value || noOpState.Watermark.Sequence != 2 {
		t.Fatalf("no-op=%+v err=%v", noOpState, err)
	}

	hypothesis, _ := NewReducer(Hypothesis)
	hypothesisState, err := hypothesis.Reduce(context.Background(), nil, claimFact, fixtureStateVersion())
	if err != nil {
		t.Fatal(err)
	}
	disposition := validProjectionFact(t, 2, &claimDigest, "hypothesis_disposition")
	hypothesisState, err = hypothesis.Reduce(context.Background(), hypothesisState, disposition, fixtureStateVersion())
	if err != nil || len(hypothesisState.Value.Claims) != 1 || len(hypothesisState.Value.Hypotheses) != 1 ||
		hypothesisState.Value.Hypotheses[0].Disposition != "supported" {
		t.Fatalf("hypothesis=%+v err=%v", hypothesisState, err)
	}

	timeline, _ := NewReducer(Timeline)
	timelineState, err := timeline.Reduce(context.Background(), nil, claimFact, fixtureStateVersion())
	if err != nil {
		t.Fatal(err)
	}
	timeFact := validProjectionFact(t, 2, &claimDigest, "time_order")
	timelineState, err = timeline.Reduce(context.Background(), timelineState, timeFact, fixtureStateVersion())
	if err != nil || len(timelineState.Value.Claims) != 1 || len(timelineState.Value.Timeline) != 1 ||
		timelineState.Value.Timeline[0].RelationToPrevious != "after" || timelineState.Value.Timeline[0].OrderConfidenceMillionths != 700_000 {
		t.Fatalf("timeline=%+v err=%v", timelineState, err)
	}
}

func TestReducerRejectsGapForkScopeAndVersionDrift(t *testing.T) {
	reducer, _ := NewReducer(Correlation)
	first := validProjectionFact(t, 1, nil, "claim")
	state, err := reducer.Reduce(context.Background(), nil, first, fixtureStateVersion())
	if err != nil {
		t.Fatal(err)
	}
	_, head, _ := CanonicalFact(context.Background(), first)
	tests := map[string]func(*Fact, *StateVersion){
		"gap": func(value *Fact, _ *StateVersion) { value.Sequence = 3 },
		"fork": func(value *Fact, _ *StateVersion) {
			changed := projectionDigest("fork")
			value.PreviousFactDigest = &changed
		},
		"scope":   func(value *Fact, _ *StateVersion) { value.Scope.CaseID = projectionUUID(99) },
		"version": func(_ *Fact, version *StateVersion) { version.MappingRevision++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fact := validProjectionFact(t, 2, &head, "observation")
			version := fixtureStateVersion()
			mutate(&fact, &version)
			result, err := reducer.Reduce(context.Background(), state, fact, version)
			if err == nil || result != nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestReducerDoesNotMutatePriorValue(t *testing.T) {
	reducer, _ := NewReducer(Correlation)
	first := validProjectionFact(t, 1, nil, "claim")
	state, err := reducer.Reduce(context.Background(), nil, first, fixtureStateVersion())
	if err != nil {
		t.Fatal(err)
	}
	prior := cloneValue(*state.Value)
	_, head, _ := CanonicalFact(context.Background(), first)
	second := validProjectionFact(t, 2, &head, "evidence_support")
	second.SupportingEvidenceDigests = []string{projectionDigest("support")}
	next, err := reducer.Reduce(context.Background(), state, second, fixtureStateVersion())
	if err != nil || next.Value == state.Value || !reflect.DeepEqual(*state.Value, prior) ||
		len(next.Value.Claims[0].SupportingEvidenceDigests) != 1 {
		t.Fatalf("prior=%+v next=%+v err=%v", state.Value, next, err)
	}
}

func TestFactBoundaryRejectsMalformedInputAndHonorsContext(t *testing.T) {
	fact := validProjectionFact(t, 1, nil, "claim")
	encoded, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(bytes.TrimSuffix(encoded, []byte("}")), []byte(`,"unexpected":true}`)...)
	duplicate := append(bytes.TrimSuffix(encoded, []byte("}")), []byte(`,"fact_id":"0198e300-3000-7000-8000-000000000001"}`)...)
	for name, input := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "oversize": bytes.Repeat([]byte("x"), MaximumBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := DecodeFact(context.Background(), input); Code(err) != InvalidInputError {
				t.Fatalf("code=%q err=%v", Code(err), err)
			}
		})
	}
	missingConfidence := fact
	missingConfidence.Confidence = nil
	if _, _, err := CanonicalFact(context.Background(), missingConfidence); Code(err) != InvalidInputError {
		t.Fatalf("missing confidence code=%q err=%v", Code(err), err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := CanonicalFact(canceled, fact); Code(err) != CanceledError ||
		ErrorReason(err) != ContextCanceled || !errors.Is(err, context.Canceled) {
		t.Fatalf("code=%q reason=%q err=%v", Code(err), ErrorReason(err), err)
	}
}

func validProjectionFact(t testing.TB, sequence uint64, previous *string, factType string) Fact {
	t.Helper()
	claimID, hypothesisID := "claim-a", "hypothesis-a"
	confidence := Confidence{Method: "coh.projection-confidence", MethodVersion: ReducerVersion,
		BasisDigest: projectionDigest("confidence"), ValueMillionths: 700_000, Label: "medium"}
	completeness := Completeness{Status: "complete", QueriedSourceDigests: []string{}, CompletedSourceDigests: []string{},
		GapDigests: []string{}, NegativeEvidenceDigests: []string{}, ConflictDigests: []string{}}
	binding := AuthoritativeBinding{CaseRevision: 4, CaseDigest: projectionDigest("case"),
		ArtifactDigest: projectionDigest("artifact"), ManifestDigest: projectionDigest("manifest"),
		IngestReceiptDigest: projectionDigest("receipt"), CustodyHeadDigest: projectionDigest("custody"),
		AuditHeadDigest: projectionDigest("audit"), SourceProvenanceDigest: projectionDigest("provenance"),
		NormalizedEventDigest: projectionDigest("event"), NormalizedEventSchemaVersion: "coh.normalized-event-envelope/v1",
		MappingOutcomeDigest: projectionDigest("mapping-outcome"), MappingManifestDigest: projectionDigest("mapping-manifest"),
		MappingRevision: 3, EntityRefs: []EntityRef{}, TimeRefs: []TimeRef{},
		AuthoritativeStateDigest: projectionDigest("authoritative")}
	fact := Fact{SchemaVersion: FactSchemaVersion, ContractVersion: ContractVersion, ReducerVersion: ReducerVersion,
		FactID: projectionUUID(int(sequence)), Scope: validProjectionScope(), Sequence: sequence, PreviousFactDigest: previous,
		FactType: factType, SubjectID: fmt.Sprintf("subject-%d", sequence), GapDigests: []string{}, ConflictDigests: []string{},
		SupportingEvidenceDigests: []string{}, CounterevidenceDigests: []string{}, Unknowns: []Unknown{},
		EntityRefs: []EntityRef{}, TimeRefs: []TimeRef{}, Completeness: completeness, Binding: binding,
		PayloadDigest: projectionDigest(fmt.Sprintf("payload-%d", sequence)), CommittedAt: fmt.Sprintf("2026-08-27T01:00:%02d.000000000Z", sequence)}
	switch factType {
	case "claim":
		fact.ClaimID, fact.Confidence = &claimID, &confidence
	case "evidence_support", "evidence_refute", "unknown", "entity_revision":
		fact.ClaimID = &claimID
	case "hypothesis_disposition":
		disposition := "supported"
		fact.ClaimID, fact.HypothesisID, fact.HypothesisDisposition, fact.Confidence = &claimID, &hypothesisID, &disposition, &confidence
	case "time_order":
		relation, order := "after", uint32(700_000)
		comparison := projectionDigest("time-comparison")
		fact.ClaimID, fact.TimeRelation, fact.OrderConfidenceMillionths = &claimID, &relation, &order
		fact.TimeRefs = []TimeRef{{TimeRecordDigest: projectionDigest("time-record"), ComparisonDigest: &comparison,
			Precision: "second", UncertaintyDigest: projectionDigest("uncertainty")}}
		fact.Binding.TimeRefs = cloneSlice(fact.TimeRefs)
	}
	return fact
}

func fixtureStateVersion() StateVersion {
	return StateVersion{ReducerVersion: ReducerVersion, ProjectionSchemaVersion: ProjectionSchemaVersion,
		NormalizedEventSchemaVersion: "coh.normalized-event-envelope/v1", MappingContractVersion: ContractVersion,
		MappingManifestDigest: projectionDigest("mapping-manifest"), MappingRevision: 3, EntityContractVersion: ContractVersion,
		EntityHeadDigest: projectionDigest("entity-head"), TimeContractVersion: ContractVersion,
		TimeMethodVersion: ReducerVersion, AuthoritativeStateDigest: projectionDigest("authoritative")}
}

func validProjectionScope() Scope {
	return Scope{OrganizationID: projectionUUID(91), TenantID: projectionUUID(92), CaseID: projectionUUID(93)}
}

func projectionUUID(value int) string { return fmt.Sprintf("0198e300-3000-7000-8000-%012d", value) }

func projectionDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
