package entityresolution

import (
	"context"
	"slices"
	"testing"
)

func TestEntityRecordDigestBreaksLifecycleCyclesAndBindsCore(t *testing.T) {
	entity, reference := validEntityRevision(t, 8)
	canonical, digest, err := EntityRecordDigest(context.Background(), entity)
	if err != nil || len(canonical) == 0 || digest != reference.RecordDigest {
		t.Fatalf("digest=%s err=%v", digest, err)
	}
	changedBindings := entity
	changedBindings.CreationDecisionDigest = testDigest("new-decision")
	changedBindings.HistoryHeadDigest = testDigest("new-history")
	changedBindings.AuditDigest = testDigest("new-audit")
	changedBindings.ProvenanceDigest = testDigest("new-provenance")
	_, bindingIndependentDigest, err := EntityRecordDigest(context.Background(), changedBindings)
	if err != nil || bindingIndependentDigest != digest {
		t.Fatalf("binding digest=%s err=%v", bindingIndependentDigest, err)
	}
	changedCore := entity
	changedCore.Status = "superseded"
	_, changedCoreDigest, err := EntityRecordDigest(context.Background(), changedCore)
	if err != nil || changedCoreDigest == digest {
		t.Fatalf("core digest=%s err=%v", changedCoreDigest, err)
	}
	if err := ValidateEntityRevision(context.Background(), entity, reference); err != nil {
		t.Fatal(err)
	}
}

func TestValidateEntityRevisionRejectsCoreAndBindingMutation(t *testing.T) {
	tests := map[string]func(*Entity, *EntityRef){
		"reference digest": func(_ *Entity, ref *EntityRef) { ref.RecordDigest = testDigest("changed") },
		"scope":            func(value *Entity, _ *EntityRef) { value.Scope.CaseID = testUUID(7) },
		"revision":         func(value *Entity, _ *EntityRef) { value.Revision++ },
		"unordered members": func(value *Entity, _ *EntityRef) {
			value.MemberObservations = append(value.MemberObservations, ObservationRef{ObservationID: testUUID(7), ObservationDigest: testDigest("a")})
			slices.SortFunc(value.MemberObservations, compareObservationRef)
			value.MemberObservations[0], value.MemberObservations[1] = value.MemberObservations[1], value.MemberObservations[0]
		},
		"confidence arithmetic": func(value *Entity, _ *EntityRef) { value.Confidence.PreCeilingMillionths++ },
		"decision binding":      func(value *Entity, _ *EntityRef) { value.CreationDecisionDigest = "" },
		"history binding":       func(value *Entity, _ *EntityRef) { value.HistoryHeadDigest = testUUID(7) },
		"provenance binding":    func(value *Entity, _ *EntityRef) { value.ProvenanceDigest = testUUID(7) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			entity, reference := validEntityRevision(t, 8)
			mutate(&entity, &reference)
			if err := ValidateEntityRevision(context.Background(), entity, reference); Code(err) != InvalidInputError || ErrorReason(err) != TransitionInvalid {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestEntityAliasProofsRejectCyclesAndAcceptCanonicalChains(t *testing.T) {
	entity, _ := validEntityRevision(t, 8)
	first := validAliasProofFixture("alias-a", "alias-b", 1, 2)
	second := validAliasProofFixture("alias-b", "alias-c", 2, 3)
	entity.AliasProofs = []AliasProof{first, second}
	slices.SortFunc(entity.AliasProofs, compareAliasProof)
	_, referenceDigest, err := EntityRecordDigest(context.Background(), entity)
	if err != nil || referenceDigest == "" {
		t.Fatalf("digest=%s err=%v", referenceDigest, err)
	}
	cycle := validAliasProofFixture("alias-c", "alias-a", 3, 1)
	entity.AliasProofs = append(entity.AliasProofs, cycle)
	slices.SortFunc(entity.AliasProofs, compareAliasProof)
	if _, _, err := EntityRecordDigest(context.Background(), entity); Code(err) != InvalidInputError || ErrorReason(err) != TransitionInvalid {
		t.Fatalf("cycle err=%v", err)
	}
}

func TestEntityRecordValidationDoesNotMutateCaller(t *testing.T) {
	entity, reference := validEntityRevision(t, 8)
	before, _, err := canonicalValue(entity)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEntityRevision(context.Background(), entity, reference); err != nil {
		t.Fatal(err)
	}
	after, _, err := canonicalValue(entity)
	if err != nil || !slices.Equal(before, after) {
		t.Fatalf("entity mutated: before=%s after=%s err=%v", before, after, err)
	}
}

func validEntityRevision(t *testing.T, suffix int) (Entity, EntityRef) {
	t.Helper()
	evidence := confidenceEvidence(t, 1, 900_000, "entity-source", "entity-group", "high", "current")
	confidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{Evidence: []ConfidenceEvidenceInput{evidence}})
	if err != nil {
		t.Fatal(err)
	}
	entity := Entity{SchemaVersion: EntitySchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		EntityID: testUUID(suffix), Revision: 1, Scope: evidence.Observation.Scope, Status: "active",
		Classification:     evidence.Observation.Evidence.Classification,
		MemberObservations: []ObservationRef{{ObservationID: evidence.Observation.ObservationID, ObservationDigest: evidence.ObservationDigest}},
		AliasProofs:        []AliasProof{}, Confidence: confidence, CreationDecisionDigest: testDigest("creation-decision"),
		HistoryHeadDigest: testDigest("history-head"), AuditDigest: testDigest("audit"), ProvenanceDigest: testDigest("provenance"),
		CreatedAt: "2026-08-27T00:00:00.000000000Z", UpdatedAt: "2026-08-27T00:00:00.000000000Z"}
	_, digest, err := EntityRecordDigest(context.Background(), entity)
	if err != nil {
		t.Fatal(err)
	}
	return entity, EntityRef{EntityID: entity.EntityID, Revision: entity.Revision, RecordDigest: digest}
}

func validAliasProofFixture(from, to string, fromRevision, toRevision uint64) AliasProof {
	return AliasProof{IdentifierType: "hostname", FromMatchDigest: testDigest(from), FromKeyRevision: fromRevision,
		ToMatchDigest: testDigest(to), ToKeyRevision: toRevision, VerifierDecisionDigest: testDigest("alias-verifier"),
		EvidenceLinkDigests: []string{testDigest("alias-evidence")}, CreatedAt: "2026-08-27T00:00:00.000000000Z"}
}
