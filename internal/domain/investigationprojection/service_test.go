package investigationprojection

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

type projectionMemory struct {
	mu                         sync.Mutex
	facts                      []Fact
	watermark                  Watermark
	projection                 Projection
	checkpoint                 Checkpoint
	found                      bool
	authorityCalls, factLoads  int
	checkpointLoads, commits   int
	evidenceBuilds             int
	authorityErr, factErr      error
	checkpointErr, evidenceErr error
	commitErr                  error
	returnDivergentCommit      bool
	failAfterCommit            bool
}

func (memory *projectionMemory) VerifyCurrent(_ context.Context, _ Scope, _ StateVersion) (Watermark, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.authorityCalls++
	return memory.watermark, memory.authorityErr
}

func (memory *projectionMemory) VerifyExact(_ context.Context, _ Scope, _ StateVersion, _ Watermark) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.authorityCalls++
	return memory.authorityErr
}

func (memory *projectionMemory) LoadFacts(_ context.Context, _ Scope, after, through uint64) ([]Fact, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.factLoads++
	if memory.factErr != nil {
		return nil, memory.factErr
	}
	result := make([]Fact, 0, through-after)
	for _, fact := range memory.facts {
		if fact.Sequence > after && fact.Sequence <= through {
			result = append(result, fact)
		}
	}
	return result, nil
}

func (memory *projectionMemory) LoadLatest(_ context.Context, _ Scope, _ Kind) (Projection, Checkpoint, bool, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.checkpointLoads++
	return memory.projection, memory.checkpoint, memory.found, memory.checkpointErr
}

func (memory *projectionMemory) Commit(_ context.Context, expected *string, projection Projection,
	checkpoint Checkpoint) (Projection, Checkpoint, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.commits++
	if memory.commitErr != nil {
		return Projection{}, Checkpoint{}, memory.commitErr
	}
	if memory.found && (expected == nil || *expected != memory.checkpoint.CheckpointDigest) || !memory.found && expected != nil {
		return Projection{}, Checkpoint{}, errors.New("optimistic checkpoint conflict")
	}
	if memory.returnDivergentCommit {
		projection.FactSetDigest = projectionDigest("divergent")
		return projection, checkpoint, nil
	}
	memory.projection, memory.checkpoint, memory.found = projection, checkpoint, true
	if memory.failAfterCommit {
		memory.failAfterCommit = false
		return Projection{}, Checkpoint{}, errors.New("commit response lost")
	}
	return projection, checkpoint, nil
}

func (memory *projectionMemory) BuildProjectionEvidence(_ context.Context, request EvidenceRequest) (EvidenceDigests, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.evidenceBuilds++
	return EvidenceDigests{AuditDigest: projectionDigest("audit:" + request.FactSetDigest),
		ProvenanceDigest: projectionDigest("provenance:" + request.FactSetDigest)}, memory.evidenceErr
}

func TestServiceFirstReadPersistsAndRepeatedCurrentReadIsZeroIO(t *testing.T) {
	memory, query := projectionServiceFixture(t, 3)
	service := newProjectionService(t, memory)
	first, err := service.Read(context.Background(), query)
	if err != nil || first.FactCount != 3 || len(first.Claims) != 1 || memory.commits != 1 {
		t.Fatalf("projection=%+v err=%v commits=%d", first, err, memory.commits)
	}
	counts := projectionCallCounts(memory)
	second, err := service.Read(context.Background(), query)
	if err != nil || second.ProjectionDigest != first.ProjectionDigest || projectionCallCounts(memory) != counts {
		t.Fatalf("second=%+v err=%v before=%v after=%v", second, err, counts, projectionCallCounts(memory))
	}
}

func TestServiceNotificationInvalidatesCacheAndReplaysOnlyTail(t *testing.T) {
	memory, query := projectionServiceFixture(t, 3)
	service := newProjectionService(t, memory)
	first, err := service.Read(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	memory.appendFact(t, "observation")
	if err := service.NotifyCurrent(query.Scope, query.StateVersion, memory.watermark); err != nil {
		t.Fatal(err)
	}
	second, err := service.Read(context.Background(), query)
	if err != nil || second.FactCount != 4 || second.ProjectionDigest == first.ProjectionDigest || memory.factLoads != 2 ||
		memory.commits != 2 {
		t.Fatalf("second=%+v err=%v facts=%d commits=%d", second, err, memory.factLoads, memory.commits)
	}
}

func TestServiceCachedProjectionIsImmutableToCallers(t *testing.T) {
	memory, query := projectionServiceFixture(t, 1)
	service := newProjectionService(t, memory)
	first, err := service.Read(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	first.Claims[0].ClaimDigest = projectionDigest("caller-mutation")
	first.Completeness.Status = "partial"
	second, err := service.Read(context.Background(), query)
	if err != nil || second.Claims[0].ClaimDigest == first.Claims[0].ClaimDigest || second.Completeness.Status != "complete" {
		t.Fatalf("first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestServiceConcurrentBuildersConvergeOnOneCanonicalCheckpoint(t *testing.T) {
	memory, query := projectionServiceFixture(t, 3)
	service := newProjectionService(t, memory)
	start := make(chan struct{})
	results := make(chan Projection, 2)
	errorsChannel := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			projection, err := service.Read(context.Background(), query)
			results <- projection
			errorsChannel <- err
		}()
	}
	close(start)
	first, second := <-results, <-results
	firstErr, secondErr := <-errorsChannel, <-errorsChannel
	if firstErr != nil || secondErr != nil || first.ProjectionDigest != second.ProjectionDigest ||
		first.ProjectionDigest != memory.projection.ProjectionDigest {
		t.Fatalf("first=%+v second=%+v errors=%v,%v", first, second, firstErr, secondErr)
	}
}

func TestServiceRestartLoadsVerifiedCheckpointAndReplaysTail(t *testing.T) {
	memory, query := projectionServiceFixture(t, 2)
	service := newProjectionService(t, memory)
	if _, err := service.Read(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	memory.appendFact(t, "observation")
	restarted := newProjectionService(t, memory)
	projection, err := restarted.Read(context.Background(), query)
	if err != nil || projection.FactCount != 3 || memory.factLoads != 2 || memory.commits != 2 {
		t.Fatalf("projection=%+v err=%v facts=%d commits=%d", projection, err, memory.factLoads, memory.commits)
	}
}

func TestServiceExactReadReusesVerifiedCheckpointWithoutCacheOrRewrite(t *testing.T) {
	memory, query := projectionServiceFixture(t, 2)
	service := newProjectionService(t, memory)
	current, err := service.Read(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	exact := query
	exact.Consistency = "exact"
	requested := memory.watermark
	exact.RequestedWatermark = &requested
	exact.QueryDigest = ""
	_, exact.QueryDigest, _ = canonicalValue(exact)
	counts := projectionCallCounts(memory)
	result, err := newProjectionService(t, memory).Read(context.Background(), exact)
	after := projectionCallCounts(memory)
	if err != nil || result.ProjectionDigest != current.ProjectionDigest || after[0] != counts[0]+1 ||
		after[2] != counts[2]+1 || after[1] != counts[1] || after[3] != counts[3] || after[4] != counts[4] {
		t.Fatalf("result=%+v err=%v before=%v after=%v", result, err, counts, after)
	}
}

func TestServiceHeadVersionNotificationInvalidatesStaleCache(t *testing.T) {
	memory, query := projectionServiceFixture(t, 1)
	service := newProjectionService(t, memory)
	if _, err := service.Read(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	service.mu.RLock()
	before := len(service.cache)
	service.mu.RUnlock()
	changed := query.StateVersion
	changed.EntityHeadDigest = projectionDigest("changed-entity-head")
	if err := service.NotifyCurrent(query.Scope, changed, memory.watermark); err != nil {
		t.Fatal(err)
	}
	service.mu.RLock()
	after := len(service.cache)
	service.mu.RUnlock()
	if before != 1 || after != 0 {
		t.Fatalf("cache before=%d after=%d", before, after)
	}
}

func TestServiceFailsClosedOnMissingTamperedAndDivergentState(t *testing.T) {
	t.Run("missing fact", func(t *testing.T) {
		memory, query := projectionServiceFixture(t, 3)
		memory.facts = memory.facts[:2]
		projection, err := newProjectionService(t, memory).Read(context.Background(), query)
		if Code(err) != ConflictError || ErrorReason(err) != IntegrityFailure || !reflect.DeepEqual(projection, Projection{}) {
			t.Fatalf("projection=%+v err=%v", projection, err)
		}
	})
	t.Run("tampered checkpoint", func(t *testing.T) {
		memory, query := projectionServiceFixture(t, 2)
		service := newProjectionService(t, memory)
		if _, err := service.Read(context.Background(), query); err != nil {
			t.Fatal(err)
		}
		memory.projection.Claims[0].ClaimDigest = projectionDigest("tampered")
		restarted := newProjectionService(t, memory)
		projection, err := restarted.Read(context.Background(), query)
		if Code(err) != ConflictError || ErrorReason(err) != IntegrityFailure || !reflect.DeepEqual(projection, Projection{}) {
			t.Fatalf("projection=%+v err=%v", projection, err)
		}
	})
	t.Run("log shrink", func(t *testing.T) {
		memory, query := projectionServiceFixture(t, 3)
		service := newProjectionService(t, memory)
		if _, err := service.Read(context.Background(), query); err != nil {
			t.Fatal(err)
		}
		memory.facts = memory.facts[:2]
		_, head, err := CanonicalFact(context.Background(), memory.facts[1])
		if err != nil {
			t.Fatal(err)
		}
		memory.watermark = Watermark{Sequence: 2, HeadFactDigest: &head, CommittedAt: memory.facts[1].CommittedAt,
			AuthoritativeStateDigest: query.StateVersion.AuthoritativeStateDigest}
		restarted := newProjectionService(t, memory)
		projection, err := restarted.Read(context.Background(), query)
		if Code(err) != ConflictError || ErrorReason(err) != IntegrityFailure || !reflect.DeepEqual(projection, Projection{}) {
			t.Fatalf("projection=%+v err=%v", projection, err)
		}
	})
	t.Run("divergent commit", func(t *testing.T) {
		memory, query := projectionServiceFixture(t, 2)
		memory.returnDivergentCommit = true
		projection, err := newProjectionService(t, memory).Read(context.Background(), query)
		if Code(err) != ConflictError || ErrorReason(err) != ProjectionDivergent || !reflect.DeepEqual(projection, Projection{}) {
			t.Fatalf("projection=%+v err=%v", projection, err)
		}
	})
}

func TestServiceMapsDependencyCancellationAndUnavailable(t *testing.T) {
	memory, query := projectionServiceFixture(t, 1)
	memory.authorityErr = errors.New("offline")
	if _, err := newProjectionService(t, memory).Read(context.Background(), query); Code(err) != UnavailableError ||
		ErrorReason(err) != DependencyUnavailable {
		t.Fatalf("err=%v", err)
	}
	memory.authorityErr = context.Canceled
	if _, err := newProjectionService(t, memory).Read(context.Background(), query); Code(err) != UnavailableError {
		t.Fatalf("unowned cancellation err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newProjectionService(t, memory).Read(canceled, query); Code(err) != CanceledError ||
		ErrorReason(err) != ContextCanceled {
		t.Fatalf("owned cancellation err=%v", err)
	}
}

func TestServiceHandlesDenialTimeoutAndLostCommitResponse(t *testing.T) {
	t.Run("denial", func(t *testing.T) {
		memory, query := projectionServiceFixture(t, 1)
		memory.authorityErr = newError(DeniedError, AuthorityDenied, nil)
		if _, err := newProjectionService(t, memory).Read(context.Background(), query); Code(err) != DeniedError ||
			ErrorReason(err) != AuthorityDenied {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		memory, query := projectionServiceFixture(t, 1)
		query.RequestedAt = "2020-01-01T00:00:00.000000000Z"
		query.Deadline = "2020-01-01T00:00:01.000000000Z"
		query.QueryDigest = ""
		_, query.QueryDigest, _ = canonicalValue(query)
		if _, err := newProjectionService(t, memory).Read(context.Background(), query); Code(err) != TimeoutError ||
			ErrorReason(err) != ContextDeadline {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("lost commit response", func(t *testing.T) {
		memory, query := projectionServiceFixture(t, 2)
		memory.failAfterCommit = true
		projection, err := newProjectionService(t, memory).Read(context.Background(), query)
		if err != nil || projection.ProjectionDigest == "" || memory.commits != 1 || memory.checkpointLoads != 2 {
			t.Fatalf("projection=%+v err=%v commits=%d loads=%d", projection, err, memory.commits, memory.checkpointLoads)
		}
	})
}

func projectionServiceFixture(t *testing.T, count int) (*projectionMemory, Query) {
	t.Helper()
	memory := &projectionMemory{facts: []Fact{}}
	for index := 0; index < count; index++ {
		factType := "observation"
		if index == 0 {
			factType = "claim"
		}
		memory.appendFact(t, factType)
	}
	query := Query{SchemaVersion: QuerySchemaVersion, ContractVersion: ContractVersion,
		QueryID: projectionUUID(500), IdempotencyKey: projectionDigest("query-idempotency"), Scope: validProjectionScope(),
		Kind: Correlation, Consistency: "current", StateVersion: fixtureStateVersion(), MaxFacts: MaximumFacts,
		MaxOutputs: MaximumOutputs, RequestedAt: "2026-08-27T01:00:00.000000000Z",
		Deadline: "2099-08-27T01:00:00.000000000Z", QueryDigest: projectionDigest("placeholder")}
	query.QueryDigest = ""
	_, query.QueryDigest, _ = canonicalValue(query)
	return memory, query
}

func (memory *projectionMemory) appendFact(t *testing.T, factType string) {
	t.Helper()
	sequence := uint64(len(memory.facts) + 1)
	var previous *string
	if len(memory.facts) != 0 {
		_, digest, err := CanonicalFact(context.Background(), memory.facts[len(memory.facts)-1])
		if err != nil {
			t.Fatal(err)
		}
		previous = &digest
	}
	fact := validProjectionFact(t, sequence, previous, factType)
	memory.facts = append(memory.facts, fact)
	_, head, err := CanonicalFact(context.Background(), fact)
	if err != nil {
		t.Fatal(err)
	}
	memory.watermark = Watermark{Sequence: sequence, HeadFactDigest: &head, CommittedAt: fact.CommittedAt,
		AuthoritativeStateDigest: fixtureStateVersion().AuthoritativeStateDigest}
}

func newProjectionService(t *testing.T, memory *projectionMemory) *Service {
	t.Helper()
	service, err := NewService(Dependencies{Authority: memory, Facts: memory, Checkpoints: memory, Evidence: memory})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func projectionCallCounts(memory *projectionMemory) [5]int {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	return [5]int{memory.authorityCalls, memory.factLoads, memory.checkpointLoads, memory.evidenceBuilds, memory.commits}
}
