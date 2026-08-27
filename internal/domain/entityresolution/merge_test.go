package entityresolution

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestPlanMergeCreatesAppendOnlyDeterministicTransition(t *testing.T) {
	firstEvidence := confidenceEvidence(t, 1, 900_000, "merge-source-a", "merge-group-a", "high", "current")
	secondEvidence := confidenceEvidence(t, 7, 850_000, "merge-source-b", "merge-group-b", "standard", "recent")
	alias := validAliasProofFixture("merge-alias-a", "merge-alias-b", 1, 2)
	first, firstHistoryDigest, firstHistory := transitionEntity(t, 20, 30, []ConfidenceEvidenceInput{firstEvidence}, "confidential", Resolve, alias)
	second, secondHistoryDigest, secondHistory := transitionEntity(t, 21, 31, []ConfidenceEvidenceInput{secondEvidence}, "restricted", Resolve)
	store := &transitionStore{current: map[string]storedTransitionEntity{first.reference.EntityID: first, second.reference.EntityID: second},
		histories: map[string]History{firstHistoryDigest: firstHistory, secondHistoryDigest: secondHistory}}
	authorization := validTransitionAuthorization()
	metadata := transitionMetadata(t, []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, nil, "independent_corroboration")
	request := MergeRequest{Metadata: metadata, InputEntities: []EntityRef{second.reference, first.reference}, OutputEntityID: transitionUUID(22)}

	plan, err := PlanMerge(context.Background(), Dependencies{Entities: store, Authorization: authorization, Matches: validTransitionMatches()}, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != Merge || len(plan.Outputs) != 1 || len(plan.Superseded) != 2 ||
		plan.Outputs[0].Entity.Status != "active" || plan.Outputs[0].Entity.Classification != "restricted" ||
		len(plan.Outputs[0].Entity.MemberObservations) != 2 || len(plan.Outputs[0].Entity.AliasProofs) != 1 || len(plan.History.PreviousHistoryDigests) != 2 ||
		plan.Decision.ReversesHistoryDigest != nil || plan.History.ReversesHistoryDigest != nil {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.Decision.InputEntities[0] != first.reference || plan.Decision.InputEntities[1] != second.reference ||
		plan.History.PreviousHistoryDigests[0] != min(firstHistoryDigest, secondHistoryDigest) {
		t.Fatalf("ordering decision=%+v history=%+v", plan.Decision, plan.History)
	}
	for _, draft := range append(append([]EntityRevisionDraft(nil), plan.Outputs...), plan.Superseded...) {
		_, digest, digestErr := EntityRecordDigest(context.Background(), draft.Entity)
		if digestErr != nil || digest != draft.Reference.RecordDigest || draft.Entity.CreationDecisionDigest != plan.DecisionDigest ||
			draft.Entity.HistoryHeadDigest != plan.HistoryDigest {
			t.Fatalf("draft=%+v digest=%s err=%v", draft, digest, digestErr)
		}
	}
	if plan.Superseded[0].Entity.Revision != 2 || plan.Superseded[0].Entity.Status != "superseded" ||
		store.current[first.reference.EntityID].entity.Status != "active" || authorization.last.Operation != Merge ||
		!reflect.DeepEqual(authorization.last.InputEntities, plan.Decision.InputEntities) {
		t.Fatalf("superseded=%+v auth=%+v", plan.Superseded, authorization.last)
	}
	again, err := PlanMerge(context.Background(), Dependencies{Entities: store, Authorization: authorization, Matches: validTransitionMatches()}, request)
	if err != nil || again.DecisionDigest != plan.DecisionDigest || again.HistoryDigest != plan.HistoryDigest {
		t.Fatalf("again decision=%s history=%s err=%v", again.DecisionDigest, again.HistoryDigest, err)
	}
}

func TestPlanMergeFailsClosedOnBlockingCounterevidenceStaleRevisionAndAuthority(t *testing.T) {
	firstEvidence := confidenceEvidence(t, 1, 900_000, "merge-source-a", "merge-group-a", "high", "current")
	secondEvidence := confidenceEvidence(t, 7, 850_000, "merge-source-b", "merge-group-b", "standard", "recent")
	first, firstHistoryDigest, firstHistory := transitionEntity(t, 20, 30, []ConfidenceEvidenceInput{firstEvidence}, "confidential", Resolve)
	second, secondHistoryDigest, secondHistory := transitionEntity(t, 21, 31, []ConfidenceEvidenceInput{secondEvidence}, "confidential", Resolve)
	baseStore := func() *transitionStore {
		return &transitionStore{current: map[string]storedTransitionEntity{first.reference.EntityID: first, second.reference.EntityID: second},
			histories: map[string]History{firstHistoryDigest: firstHistory, secondHistoryDigest: secondHistory}}
	}
	baseRequest := func(t *testing.T) MergeRequest {
		return MergeRequest{Metadata: transitionMetadata(t, []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, nil, "manual_merge"),
			InputEntities: []EntityRef{first.reference, second.reference}, OutputEntityID: transitionUUID(22)}
	}

	t.Run("blocking counterevidence", func(t *testing.T) {
		request := baseRequest(t)
		counter := validCounterevidence(t, 8, "explicit_separation", firstEvidence.Link)
		request.Metadata = transitionMetadata(t, []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, []Counterevidence{counter}, "manual_merge")
		plan, err := PlanMerge(context.Background(), Dependencies{Entities: baseStore(), Authorization: validTransitionAuthorization()}, request)
		if Code(err) != DeniedError || ErrorReason(err) != CounterevidenceBlocked || !reflect.DeepEqual(plan, TransitionPlan{}) {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})
	t.Run("stale revision", func(t *testing.T) {
		request := baseRequest(t)
		request.InputEntities[0].Revision++
		plan, err := PlanMerge(context.Background(), Dependencies{Entities: baseStore(), Authorization: validTransitionAuthorization()}, request)
		if Code(err) != ConflictError || ErrorReason(err) != RevisionConflict || !reflect.DeepEqual(plan, TransitionPlan{}) {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})
	t.Run("authorization denied", func(t *testing.T) {
		authorization := validTransitionAuthorization()
		authorization.decision.Allowed = false
		plan, err := PlanMerge(context.Background(), Dependencies{Entities: baseStore(), Authorization: authorization}, baseRequest(t))
		if Code(err) != DeniedError || ErrorReason(err) != AuthorizationDenied || !reflect.DeepEqual(plan, TransitionPlan{}) {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})
	t.Run("output identity collision", func(t *testing.T) {
		store := baseStore()
		request := baseRequest(t)
		store.current[request.OutputEntityID] = first
		plan, err := PlanMerge(context.Background(), Dependencies{Entities: store, Authorization: validTransitionAuthorization()}, request)
		if Code(err) != ConflictError || ErrorReason(err) != RevisionConflict || !reflect.DeepEqual(plan, TransitionPlan{}) {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})
	t.Run("history mutation", func(t *testing.T) {
		store := baseStore()
		mutated := store.histories[firstHistoryDigest]
		mutated.DecisionDigest = testDigest("mutated-history")
		store.histories[firstHistoryDigest] = mutated
		plan, err := PlanMerge(context.Background(), Dependencies{Entities: store, Authorization: validTransitionAuthorization()}, baseRequest(t))
		if Code(err) != InvalidInputError || ErrorReason(err) != TransitionInvalid || !reflect.DeepEqual(plan, TransitionPlan{}) {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})
	t.Run("dependency canceled", func(t *testing.T) {
		authorization := validTransitionAuthorization()
		authorization.err = context.Canceled
		_, err := PlanMerge(context.Background(), Dependencies{Entities: baseStore(), Authorization: authorization}, baseRequest(t))
		if Code(err) != CanceledError || !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
}
