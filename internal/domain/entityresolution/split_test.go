package entityresolution

import (
	"context"
	"reflect"
	"testing"
)

func TestPlanSplitPartitionsEveryMemberAndPersistsReversal(t *testing.T) {
	firstEvidence := confidenceEvidence(t, 1, 900_000, "split-source-a", "split-group-a", "high", "current")
	secondEvidence := confidenceEvidence(t, 7, 850_000, "split-source-b", "split-group-b", "standard", "recent")
	alias := validAliasProofFixture("split-alias-a", "split-alias-b", 1, 2)
	input, mergeHistoryDigest, mergeHistory := transitionEntity(t, 20, 30,
		[]ConfidenceEvidenceInput{firstEvidence, secondEvidence}, "restricted", Merge, alias)
	store := &transitionStore{current: map[string]storedTransitionEntity{input.reference.EntityID: input},
		histories: map[string]History{mergeHistoryDigest: mergeHistory}}
	counter := validCounterevidence(t, 8, "explicit_separation", firstEvidence.Link)
	metadata := transitionMetadata(t, []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, []Counterevidence{counter}, "counterevidence_split")
	metadata.ReversesHistoryDigest = &mergeHistoryDigest
	request := validSplitRequest(t, metadata, input.reference, firstEvidence, secondEvidence)
	aliasDigest, err := AliasProofDigest(alias)
	if err != nil {
		t.Fatal(err)
	}
	request.Partitions[0].AliasProofDigests = []string{aliasDigest}

	plan, err := PlanSplit(context.Background(), Dependencies{Entities: store, Authorization: validTransitionAuthorization(), Matches: validTransitionMatches()}, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != Split || len(plan.Outputs) != 2 || len(plan.Superseded) != 1 || len(plan.Decision.Partitions) != 2 ||
		plan.Decision.ReversesHistoryDigest == nil || *plan.Decision.ReversesHistoryDigest != mergeHistoryDigest ||
		plan.History.ReversesHistoryDigest == nil || *plan.History.ReversesHistoryDigest != mergeHistoryDigest ||
		len(plan.History.PreviousHistoryDigests) != 1 || plan.History.PreviousHistoryDigests[0] != mergeHistoryDigest {
		t.Fatalf("plan=%+v", plan)
	}
	for index, output := range plan.Outputs {
		if output.Entity.Status != "active" || output.Entity.Classification != "restricted" ||
			len(output.Entity.MemberObservations) != 1 || output.Entity.EntityID != plan.Decision.Partitions[index].OutputEntityID {
			t.Fatalf("output=%+v partition=%+v", output, plan.Decision.Partitions[index])
		}
		_, digest, digestErr := EntityRecordDigest(context.Background(), output.Entity)
		if digestErr != nil || digest != output.Reference.RecordDigest {
			t.Fatalf("digest=%s err=%v", digest, digestErr)
		}
	}
	if len(plan.Outputs[0].Entity.AliasProofs) != 1 || len(plan.Outputs[1].Entity.AliasProofs) != 0 {
		t.Fatalf("alias partitioning outputs=%+v", plan.Outputs)
	}
	if plan.Superseded[0].Entity.Revision != 2 || plan.Superseded[0].Entity.Status != "superseded" ||
		store.current[input.reference.EntityID].entity.Status != "active" {
		t.Fatalf("superseded=%+v", plan.Superseded)
	}
	again, err := PlanSplit(context.Background(), Dependencies{Entities: store, Authorization: validTransitionAuthorization(), Matches: validTransitionMatches()}, request)
	if err != nil || again.DecisionDigest != plan.DecisionDigest || again.HistoryDigest != plan.HistoryDigest {
		t.Fatalf("again=%+v err=%v", again, err)
	}
}

func TestPlanSplitRejectsIncompleteOverlapWrongConfidenceAndUnknownReversal(t *testing.T) {
	firstEvidence := confidenceEvidence(t, 1, 900_000, "split-source-a", "split-group-a", "high", "current")
	secondEvidence := confidenceEvidence(t, 7, 850_000, "split-source-b", "split-group-b", "standard", "recent")
	input, mergeHistoryDigest, mergeHistory := transitionEntity(t, 20, 30,
		[]ConfidenceEvidenceInput{firstEvidence, secondEvidence}, "restricted", Merge)
	store := &transitionStore{current: map[string]storedTransitionEntity{input.reference.EntityID: input},
		histories: map[string]History{mergeHistoryDigest: mergeHistory}}
	counter := validCounterevidence(t, 8, "explicit_separation", firstEvidence.Link)
	metadata := transitionMetadata(t, []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, []Counterevidence{counter}, "counterevidence_split")
	metadata.ReversesHistoryDigest = &mergeHistoryDigest
	base := func(t *testing.T) SplitRequest {
		return validSplitRequest(t, metadata, input.reference, firstEvidence, secondEvidence)
	}
	tests := map[string]func(*SplitRequest){
		"overlapping member": func(value *SplitRequest) {
			value.Partitions[1].MemberObservations = append([]ObservationRef(nil), value.Partitions[0].MemberObservations...)
			value.Partitions[1].Confidence = value.Partitions[0].Confidence
		},
		"wrong partition confidence": func(value *SplitRequest) { value.Partitions[0].Confidence = value.Partitions[1].Confidence },
		"unknown reversal": func(value *SplitRequest) {
			digest := testDigest("unknown-history")
			value.Metadata.ReversesHistoryDigest = &digest
		},
		"missing counterevidence": func(value *SplitRequest) {
			value.Metadata = transitionMetadata(t, []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, nil, "counterevidence_split")
			value.Metadata.ReversesHistoryDigest = &mergeHistoryDigest
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := base(t)
			mutate(&request)
			plan, err := PlanSplit(context.Background(), Dependencies{Entities: store, Authorization: validTransitionAuthorization()}, request)
			if Code(err) != InvalidInputError || ErrorReason(err) != TransitionInvalid || !reflect.DeepEqual(plan, TransitionPlan{}) {
				t.Fatalf("plan=%+v err=%v", plan, err)
			}
		})
	}
}

func validSplitRequest(t *testing.T, metadata TransitionMetadata, input EntityRef,
	first, second ConfidenceEvidenceInput) SplitRequest {
	t.Helper()
	firstConfidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{Evidence: []ConfidenceEvidenceInput{first}})
	if err != nil {
		t.Fatal(err)
	}
	secondConfidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{Evidence: []ConfidenceEvidenceInput{second}})
	if err != nil {
		t.Fatal(err)
	}
	return SplitRequest{Metadata: metadata, InputEntity: input, Partitions: []SplitPartitionRequest{
		{PartitionID: "partition-a", OutputEntityID: transitionUUID(22),
			MemberObservations: []ObservationRef{{ObservationID: first.Observation.ObservationID, ObservationDigest: first.ObservationDigest}},
			AliasProofDigests:  []string{}, Confidence: firstConfidence},
		{PartitionID: "partition-b", OutputEntityID: transitionUUID(23),
			MemberObservations: []ObservationRef{{ObservationID: second.Observation.ObservationID, ObservationDigest: second.ObservationDigest}},
			AliasProofDigests:  []string{}, Confidence: secondConfidence},
	}}
}
