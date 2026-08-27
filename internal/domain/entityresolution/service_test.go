package entityresolution

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

type entityServiceFixture struct {
	store    *memoryEntityServiceStore
	evidence *serviceEvidenceVerifier
	service  *Service
	command  Command
}

func newEntityServiceFixture(t *testing.T) *entityServiceFixture {
	t.Helper()
	store := newMemoryEntityServiceStore()
	evidence := &serviceEvidenceVerifier{}
	authorization := validTransitionAuthorization()
	authorization.decision.ExpiresAt = "2099-08-27T02:00:00.000000000Z"
	clock := serviceClock{now: time.Date(2026, 8, 27, 1, 5, 0, 0, time.UTC)}
	dependencies := Dependencies{Evidence: evidence, Matches: &serviceMatchVerifier{}, Authorization: authorization,
		Observations: store, Entities: store, Candidates: store, Durable: store, Audit: &serviceAuditBuilder{},
		Provenance: &serviceProvenanceBuilder{}, Clock: clock}
	service, err := NewService(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	operationID := transitionUUID(50)
	observationInput := validObservationInput()
	observationInput.OperationID = operationID
	observation, _, observationDigest, err := NewObservation(context.Background(), observationInput)
	if err != nil {
		t.Fatal(err)
	}
	_, bindingDigest, err := canonicalValue(observation.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	link := EvidenceLink{ObservationID: observation.ObservationID, ObservationDigest: observationDigest,
		EvidenceBindingDigest: bindingDigest, SourceFamilyDigest: testDigest("service-source"),
		IndependenceGroupDigest: testDigest("service-group")}
	assessment := ConfidenceAssessment{Observation: ObservationRef{ObservationID: observation.ObservationID, ObservationDigest: observationDigest},
		EvidenceLink: link, SourceQuality: "high", Recency: "current"}
	confidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{Evidence: []ConfidenceEvidenceInput{{
		Observation: observation, ObservationDigest: observationDigest, Link: link, SourceQuality: "high", Recency: "current"}},
		Counterevidence: []Counterevidence{}})
	if err != nil {
		t.Fatal(err)
	}
	candidateID := transitionUUID(51)
	command := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: operationID, IdempotencyKey: testDigest("service-idempotency"), Operation: Observe, Scope: observation.Scope,
		ActorID: transitionUUID(52), ActorRevision: 3, CandidateID: &candidateID, Confidence: &confidence,
		ConfidenceAssessments: []ConfidenceAssessment{assessment}, Observation: &observation, InputEntities: []EntityRef{},
		Partitions: []Partition{}, SupportingEvidence: append([]EvidenceLink(nil), confidence.SupportingEvidence...),
		Counterevidence: []Counterevidence{}, Reason: "new_observation",
		RequestedAt: "2026-08-27T01:00:00.000000000Z", Deadline: "2099-08-27T01:30:00.000000000Z"}
	if _, _, err := CanonicalCommand(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	return &entityServiceFixture{store: store, evidence: evidence, service: service, command: command}
}

func TestServicePersistsObservationCandidateAndExactReplay(t *testing.T) {
	fixture := newEntityServiceFixture(t)
	receipt, err := fixture.service.Execute(context.Background(), fixture.command)
	if err != nil || receipt.Status != Observed || receipt.ReasonCode != ObservedReason {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	fixture.store.mu.Lock()
	if len(fixture.store.commits) != 1 || fixture.store.commits[0].Observation == nil || fixture.store.commits[0].Candidate == nil ||
		fixture.store.commits[0].Candidate.Result != "new_candidate" || fixture.store.commits[0].Outcome.ObservationDigest == nil ||
		fixture.store.commits[0].Outcome.CandidateDigest == nil {
		fixture.store.mu.Unlock()
		t.Fatalf("commits=%+v", fixture.store.commits)
	}
	fixture.store.mu.Unlock()
	replayed, err := fixture.service.Execute(context.Background(), fixture.command)
	if err != nil || replayed != receipt {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if len(fixture.store.commits) != 1 {
		t.Fatalf("commits=%d", len(fixture.store.commits))
	}
}

func TestServiceResolvesCandidateIntoAtomicRootEntity(t *testing.T) {
	fixture := newEntityServiceFixture(t)
	observed, err := fixture.service.Execute(context.Background(), fixture.command)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	candidateDigest := *fixture.store.outcomes[observed.OutcomeDigest].CandidateDigest
	candidate := fixture.store.candidates[candidateDigest]
	fixture.store.mu.Unlock()
	decisionID, historyID, outputEntityID := transitionUUID(53), transitionUUID(54), transitionUUID(55)
	historySequence := uint64(1)
	confidence := candidate.Confidence
	command := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: transitionUUID(56), IdempotencyKey: testDigest("service-resolve-idempotency"), Operation: Resolve,
		Scope: fixture.command.Scope, ActorID: fixture.command.ActorID, ActorRevision: fixture.command.ActorRevision,
		DecisionID: &decisionID, HistoryID: &historyID, HistorySequence: &historySequence, OutputEntityID: &outputEntityID,
		Confidence: &confidence, ConfidenceAssessments: cloneSlice(fixture.command.ConfidenceAssessments),
		CandidateDigest: &candidateDigest, InputEntities: []EntityRef{}, Partitions: []Partition{},
		SupportingEvidence: cloneSlice(confidence.SupportingEvidence), Counterevidence: cloneSlice(confidence.Counterevidence),
		Reason: "exact_typed_match", RequestedAt: "2026-08-27T02:00:00.000000000Z", Deadline: fixture.command.Deadline}
	receipt, err := fixture.service.Execute(context.Background(), command)
	if err != nil || receipt.Status != Resolved || receipt.ReasonCode != ResolvedReason {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	fixture.store.mu.Lock()
	if len(fixture.store.commits) != 2 || fixture.store.commits[1].Decision == nil || fixture.store.commits[1].History == nil ||
		len(fixture.store.commits[1].Entities) != 1 || fixture.store.commits[1].Entities[0].EntityID != outputEntityID ||
		fixture.store.commits[1].Entities[0].Revision != 1 || fixture.store.commits[1].Entities[0].Status != "active" ||
		fixture.store.commits[1].Entities[0].PreviousProvenanceDigests == nil ||
		len(fixture.store.commits[1].Entities[0].PreviousProvenanceDigests) != 0 {
		fixture.store.mu.Unlock()
		t.Fatalf("commits=%+v", fixture.store.commits)
	}
	fixture.store.mu.Unlock()
	replayed, err := fixture.service.Execute(context.Background(), command)
	if err != nil || replayed != receipt {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if len(fixture.store.commits) != 2 {
		t.Fatalf("commits=%d", len(fixture.store.commits))
	}
}

func TestServiceAtomicallyMergesAndReversesWithSplit(t *testing.T) {
	fixture := newEntityServiceFixture(t)
	firstEvidence := confidenceEvidence(t, 1, 900_000, "service-merge-source-a", "service-merge-group-a", "high", "current")
	secondEvidence := confidenceEvidence(t, 7, 850_000, "service-merge-source-b", "service-merge-group-b", "standard", "recent")
	first, firstHistoryDigest, firstHistory := transitionEntity(t, 20, 30, []ConfidenceEvidenceInput{firstEvidence}, "confidential", Resolve)
	second, secondHistoryDigest, secondHistory := transitionEntity(t, 21, 31, []ConfidenceEvidenceInput{secondEvidence}, "restricted", Resolve)
	first.entity.ProvenanceDigest = testDigest("service-parent-provenance-a")
	second.entity.ProvenanceDigest = testDigest("service-parent-provenance-b")
	fixture.store.entities[first.reference.EntityID], fixture.store.entities[second.reference.EntityID] = first, second
	fixture.store.histories[firstHistoryDigest], fixture.store.histories[secondHistoryDigest] = firstHistory, secondHistory
	firstRef := ObservationRef{ObservationID: firstEvidence.Observation.ObservationID, ObservationDigest: firstEvidence.ObservationDigest}
	secondRef := ObservationRef{ObservationID: secondEvidence.Observation.ObservationID, ObservationDigest: secondEvidence.ObservationDigest}
	fixture.store.observations[firstRef], fixture.store.observations[secondRef] = firstEvidence.Observation, secondEvidence.Observation
	assessments := []ConfidenceAssessment{confidenceAssessment(firstEvidence), confidenceAssessment(secondEvidence)}
	slices.SortFunc(assessments, func(left, right ConfidenceAssessment) int {
		return compareObservationRef(left.Observation, right.Observation)
	})
	mergeConfidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{
		Evidence: []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, Counterevidence: []Counterevidence{}})
	if err != nil {
		t.Fatal(err)
	}
	decisionID, historyID, outputEntityID := transitionUUID(57), transitionUUID(58), transitionUUID(59)
	historySequence := uint64(2)
	inputs := []EntityRef{first.reference, second.reference}
	slices.SortFunc(inputs, compareEntityRef)
	mergeCommand := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: transitionUUID(60), IdempotencyKey: testDigest("service-merge-idempotency"), Operation: Merge,
		Scope: firstEvidence.Observation.Scope, ActorID: fixture.command.ActorID, ActorRevision: fixture.command.ActorRevision,
		DecisionID: &decisionID, HistoryID: &historyID, HistorySequence: &historySequence, OutputEntityID: &outputEntityID,
		Confidence: &mergeConfidence, ConfidenceAssessments: assessments, InputEntities: inputs, Partitions: []Partition{},
		SupportingEvidence: cloneSlice(mergeConfidence.SupportingEvidence), Counterevidence: cloneSlice(mergeConfidence.Counterevidence),
		Reason: "independent_corroboration", RequestedAt: "2026-08-27T03:00:00.000000000Z", Deadline: fixture.command.Deadline}
	merged, err := fixture.service.Execute(context.Background(), mergeCommand)
	if err != nil || merged.Status != Merged {
		t.Fatalf("receipt=%+v err=%v", merged, err)
	}
	mergedState := fixture.store.entities[outputEntityID]
	expectedParents := []string{first.entity.ProvenanceDigest, second.entity.ProvenanceDigest}
	slices.Sort(expectedParents)
	if len(fixture.store.commits) != 1 || len(fixture.store.commits[0].Entities) != 3 ||
		!slices.Equal(mergedState.entity.PreviousProvenanceDigests, expectedParents) {
		t.Fatalf("commits=%+v merged=%+v", fixture.store.commits, mergedState)
	}

	counter := validCounterevidence(t, 8, "explicit_separation", firstEvidence.Link)
	topConfidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{
		Evidence: []ConfidenceEvidenceInput{firstEvidence, secondEvidence}, Counterevidence: []Counterevidence{counter}})
	if err != nil {
		t.Fatal(err)
	}
	firstConfidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{
		Evidence: []ConfidenceEvidenceInput{firstEvidence}, Counterevidence: []Counterevidence{}})
	if err != nil {
		t.Fatal(err)
	}
	secondConfidence, _, _, err := ComposeConfidence(context.Background(), ConfidenceInput{
		Evidence: []ConfidenceEvidenceInput{secondEvidence}, Counterevidence: []Counterevidence{}})
	if err != nil {
		t.Fatal(err)
	}
	splitDecisionID, splitHistoryID := transitionUUID(61), transitionUUID(62)
	splitSequence := uint64(3)
	mergeHistoryDigest := *fixture.store.commits[0].Outcome.HistoryDigest
	partitions := []Partition{
		{PartitionID: "partition-a", OutputEntityID: transitionUUID(63), MemberObservations: []ObservationRef{firstRef},
			AliasProofDigests: []string{}, Confidence: firstConfidence,
			ConfidenceAssessments: []ConfidenceAssessment{confidenceAssessment(firstEvidence)}},
		{PartitionID: "partition-b", OutputEntityID: transitionUUID(64), MemberObservations: []ObservationRef{secondRef},
			AliasProofDigests: []string{}, Confidence: secondConfidence,
			ConfidenceAssessments: []ConfidenceAssessment{confidenceAssessment(secondEvidence)}},
	}
	splitCommand := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: transitionUUID(65), IdempotencyKey: testDigest("service-split-idempotency"), Operation: Split,
		Scope: firstEvidence.Observation.Scope, ActorID: fixture.command.ActorID, ActorRevision: fixture.command.ActorRevision,
		ReversesHistoryDigest: &mergeHistoryDigest, DecisionID: &splitDecisionID, HistoryID: &splitHistoryID,
		HistorySequence: &splitSequence, Confidence: &topConfidence, ConfidenceAssessments: assessments,
		InputEntities: []EntityRef{mergedState.reference}, Partitions: partitions,
		SupportingEvidence: cloneSlice(topConfidence.SupportingEvidence), Counterevidence: cloneSlice(topConfidence.Counterevidence),
		Reason: "counterevidence_split", RequestedAt: "2026-08-27T04:00:00.000000000Z", Deadline: fixture.command.Deadline}
	splitReceipt, err := fixture.service.Execute(context.Background(), splitCommand)
	if err != nil || splitReceipt.Status != SplitStatus {
		t.Fatalf("receipt=%+v err=%v", splitReceipt, err)
	}
	if len(fixture.store.commits) != 2 || len(fixture.store.commits[1].Entities) != 3 ||
		fixture.store.commits[1].Decision == nil || fixture.store.commits[1].Decision.ReversesHistoryDigest == nil ||
		*fixture.store.commits[1].Decision.ReversesHistoryDigest != mergeHistoryDigest ||
		fixture.store.commits[1].History == nil || fixture.store.commits[1].History.ReversesHistoryDigest == nil {
		t.Fatalf("commits=%+v", fixture.store.commits)
	}
	for _, entity := range fixture.store.commits[1].Entities {
		if !slices.Equal(entity.PreviousProvenanceDigests, []string{mergedState.entity.ProvenanceDigest}) {
			t.Fatalf("split provenance=%+v", entity.PreviousProvenanceDigests)
		}
	}
	mergeReplay, err := fixture.service.Execute(context.Background(), mergeCommand)
	if err != nil || mergeReplay != merged {
		t.Fatalf("merge replay=%+v err=%v", mergeReplay, err)
	}
	splitReplay, err := fixture.service.Execute(context.Background(), splitCommand)
	if err != nil || splitReplay != splitReceipt {
		t.Fatalf("split replay=%+v err=%v", splitReplay, err)
	}
}

func confidenceAssessment(value ConfidenceEvidenceInput) ConfidenceAssessment {
	return ConfidenceAssessment{Observation: ObservationRef{ObservationID: value.Observation.ObservationID,
		ObservationDigest: value.ObservationDigest}, EvidenceLink: value.Link,
		SourceQuality: value.SourceQuality, Recency: value.Recency}
}

func TestServiceRecoversLostResponseRestartAndIncompleteBegin(t *testing.T) {
	t.Run("lost response and restart", func(t *testing.T) {
		fixture := newEntityServiceFixture(t)
		fixture.store.failAfterCommit = true
		if receipt, err := fixture.service.Execute(context.Background(), fixture.command); Code(err) != UnavailableError || receipt != (Receipt{}) {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
		stored := fixture.store.receipts[fixture.command.IdempotencyKey]
		restarted, err := NewService(fixture.service.dependencies)
		if err != nil {
			t.Fatal(err)
		}
		replayed, err := restarted.Execute(context.Background(), fixture.command)
		if err != nil || replayed != stored || len(fixture.store.commits) != 1 {
			t.Fatalf("replayed=%+v stored=%+v err=%v commits=%d", replayed, stored, err, len(fixture.store.commits))
		}
	})
	t.Run("incomplete begin", func(t *testing.T) {
		fixture := newEntityServiceFixture(t)
		_, digest, err := CanonicalCommand(context.Background(), fixture.command)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.digests[fixture.command.IdempotencyKey] = digest
		fixture.store.active[fixture.command.IdempotencyKey] = false
		receipt, err := fixture.service.Execute(context.Background(), fixture.command)
		if err != nil || receipt.Status != Observed || len(fixture.store.commits) != 1 {
			t.Fatalf("receipt=%+v err=%v commits=%d", receipt, err, len(fixture.store.commits))
		}
	})
}

func TestServiceDurablyDeniesChangedAndTamperedReplay(t *testing.T) {
	t.Run("changed command", func(t *testing.T) {
		fixture := newEntityServiceFixture(t)
		original, err := fixture.service.Execute(context.Background(), fixture.command)
		if err != nil {
			t.Fatal(err)
		}
		changedID := transitionUUID(59)
		fixture.command.CandidateID = &changedID
		conflict, err := fixture.service.Execute(context.Background(), fixture.command)
		if Code(err) != ConflictError || ErrorReason(err) != IdempotencyConflict || conflict.Status != Denied ||
			conflict.ReasonCode != IdempotencyConflict || len(fixture.store.commits) != 1 || len(fixture.store.denials) != 1 ||
			fixture.store.receipts[fixture.command.IdempotencyKey] != original {
			t.Fatalf("conflict=%+v err=%v commits=%d denials=%d", conflict, err, len(fixture.store.commits), len(fixture.store.denials))
		}
	})
	t.Run("tampered outcome", func(t *testing.T) {
		fixture := newEntityServiceFixture(t)
		receipt, err := fixture.service.Execute(context.Background(), fixture.command)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.mu.Lock()
		outcome := fixture.store.outcomes[receipt.OutcomeDigest]
		outcome.CreatedAt = "2026-08-27T01:00:00.000000001Z"
		fixture.store.outcomes[receipt.OutcomeDigest] = outcome
		commit := fixture.store.results[fixture.command.IdempotencyKey]
		commit.Outcome = outcome
		fixture.store.results[fixture.command.IdempotencyKey] = commit
		fixture.store.mu.Unlock()
		if replay, err := fixture.service.Execute(context.Background(), fixture.command); Code(err) != ConflictError || replay != (Receipt{}) {
			t.Fatalf("replay=%+v err=%v", replay, err)
		}
	})
}

func TestServicePersistsCancellationTimeoutAndConcurrentSingleCommit(t *testing.T) {
	for _, test := range []struct {
		name   string
		cause  error
		code   ErrorCode
		status Status
	}{
		{"canceled", context.Canceled, CanceledError, Canceled},
		{"timeout", context.DeadlineExceeded, TimeoutError, Timeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEntityServiceFixture(t)
			fixture.evidence.err = test.cause
			receipt, err := fixture.service.Execute(context.Background(), fixture.command)
			if Code(err) != test.code || !errors.Is(err, test.cause) || receipt.Status != test.status {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
			fixture.evidence.err = nil
			replayed, err := fixture.service.Execute(context.Background(), fixture.command)
			if err != nil || !reflect.DeepEqual(replayed, receipt) || len(fixture.store.commits) != 1 {
				t.Fatalf("replayed=%+v err=%v commits=%d", replayed, err, len(fixture.store.commits))
			}
		})
	}
	t.Run("concurrent", func(t *testing.T) {
		fixture := newEntityServiceFixture(t)
		const workers = 16
		var wait sync.WaitGroup
		errorsSeen := make(chan error, workers)
		for range workers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := fixture.service.Execute(context.Background(), fixture.command)
				errorsSeen <- err
			}()
		}
		wait.Wait()
		close(errorsSeen)
		if len(fixture.store.commits) != 1 {
			t.Fatalf("commits=%d", len(fixture.store.commits))
		}
		for err := range errorsSeen {
			if err != nil && Code(err) != UnavailableError {
				t.Fatalf("err=%v", err)
			}
		}
	})
}
