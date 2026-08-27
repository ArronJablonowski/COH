package mappingregistry

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestServicePersistsAndExactlyReplaysApply(t *testing.T) {
	fixture := newServiceFixture(t)
	receipt, err := fixture.execute(context.Background())
	if err != nil || receipt.Status != Applied || receipt.ReasonCode != AppliedReason {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	commits := fixture.store.committed()
	if len(commits) != 1 || commits[0].NormalizedEnvelope == nil || commits[0].SignedMapping != nil || commits[0].Snapshot != nil {
		t.Fatalf("commits=%+v", commits)
	}
	assertCommitMatches(t, commits[0], fixture.command, receipt)
	if commits[0].Outcome.NormalizedEnvelopeDigest == nil ||
		*commits[0].Outcome.NormalizedEnvelopeDigest != commits[0].NormalizedEnvelope.Digest() {
		t.Fatalf("outcome=%+v envelope=%+v", commits[0].Outcome, commits[0].NormalizedEnvelope)
	}

	replayed, err := fixture.execute(context.Background())
	if err != nil || replayed != receipt || len(fixture.store.committed()) != 1 {
		t.Fatalf("replayed=%+v err=%v commits=%d", replayed, err, len(fixture.store.committed()))
	}
}

func TestServiceRecoversLostResponseAndIncompleteBegin(t *testing.T) {
	t.Run("lost response", func(t *testing.T) {
		fixture := newServiceFixture(t)
		fixture.store.failAfterCommit = true
		if receipt, err := fixture.execute(context.Background()); Code(err) != UnavailableError || receipt != (Receipt{}) {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
		stored := fixture.store.committed()[0].Receipt
		replayed, err := fixture.execute(context.Background())
		if err != nil || replayed != stored || len(fixture.store.committed()) != 1 {
			t.Fatalf("replayed=%+v stored=%+v err=%v", replayed, stored, err)
		}
	})

	t.Run("incomplete begin after restart", func(t *testing.T) {
		fixture := newServiceFixture(t)
		_, digest, err := CanonicalCommand(context.Background(), fixture.command)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.digests[fixture.command.IdempotencyKey] = digest
		fixture.store.active[fixture.command.IdempotencyKey] = false
		receipt, err := fixture.execute(context.Background())
		if err != nil || receipt.Status != Applied || len(fixture.store.committed()) != 1 {
			t.Fatalf("receipt=%+v err=%v commits=%d", receipt, err, len(fixture.store.committed()))
		}
	})
}

func TestServiceRejectsChangedAndTamperedReplayWithoutReexecution(t *testing.T) {
	t.Run("changed command", func(t *testing.T) {
		fixture := newServiceFixture(t)
		original, err := fixture.execute(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fixture.command.RequestedAt = "2026-08-27T00:00:00.000000001Z"
		conflict, err := fixture.execute(context.Background())
		if Code(err) != ConflictError || ErrorReason(err) != IdempotencyConflict ||
			conflict.Status != Denied || conflict.ReasonCode != IdempotencyConflict {
			t.Fatalf("conflict=%+v err=%v", conflict, err)
		}
		if len(fixture.store.committed()) != 1 || len(fixture.store.denials) != 1 || fixture.store.receipts[fixture.command.IdempotencyKey] != original {
			t.Fatalf("commits=%d denials=%d receipt=%+v", len(fixture.store.committed()), len(fixture.store.denials), fixture.store.receipts[fixture.command.IdempotencyKey])
		}
	})

	t.Run("tampered outcome", func(t *testing.T) {
		fixture := newServiceFixture(t)
		receipt, err := fixture.execute(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.mu.Lock()
		outcome := fixture.store.outcomes[receipt.OutcomeDigest]
		outcome.CreatedAt = "2026-08-27T01:00:00.000000001Z"
		fixture.store.outcomes[receipt.OutcomeDigest] = outcome
		fixture.store.mu.Unlock()
		if replay, err := fixture.execute(context.Background()); Code(err) != ConflictError || replay != (Receipt{}) {
			t.Fatalf("replay=%+v err=%v", replay, err)
		}
		if len(fixture.store.committed()) != 1 {
			t.Fatalf("commits=%d", len(fixture.store.committed()))
		}
	})
}

func TestServicePersistsCancellationAndTimeoutForExactReplay(t *testing.T) {
	tests := []struct {
		name   string
		cause  error
		code   ErrorCode
		status Status
		reason Reason
	}{
		{"canceled", context.Canceled, CanceledError, Canceled, ContextCanceled},
		{"timeout", context.DeadlineExceeded, TimeoutError, Timeout, ContextDeadline},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			fixture.store.evidenceErr = test.cause
			receipt, err := fixture.execute(context.Background())
			if Code(err) != test.code || !errors.Is(err, test.cause) || receipt.Status != test.status || receipt.ReasonCode != test.reason {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
			fixture.store.evidenceErr = nil
			replayed, err := fixture.execute(context.Background())
			if err != nil || !reflect.DeepEqual(replayed, receipt) || len(fixture.store.committed()) != 1 {
				t.Fatalf("replayed=%+v err=%v commits=%d", replayed, err, len(fixture.store.committed()))
			}
		})
	}
}

func TestServiceSerializesConcurrentIdenticalExecution(t *testing.T) {
	fixture := newServiceFixture(t)
	const workers = 16
	var wait sync.WaitGroup
	receipts := make(chan Receipt, workers)
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := fixture.execute(context.Background())
			receipts <- receipt
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(receipts)
	close(errorsSeen)
	if len(fixture.store.committed()) != 1 {
		t.Fatalf("commits=%d", len(fixture.store.committed()))
	}
	want := fixture.store.committed()[0].Receipt
	for receipt := range receipts {
		if receipt != (Receipt{}) && receipt != want {
			t.Fatalf("receipt=%+v want=%+v", receipt, want)
		}
	}
	for err := range errorsSeen {
		if err != nil && Code(err) != UnavailableError {
			t.Fatalf("err=%v", err)
		}
	}
}
