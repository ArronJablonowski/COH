package entityresolution

import (
	"context"
	"errors"
	"testing"
)

func TestServiceReplayRejectsTamperedAtomicCommitRecords(t *testing.T) {
	tests := map[string]func(*Commit){
		"command": func(value *Commit) { value.Command.ActorRevision++ },
		"candidate": func(value *Commit) {
			value.Candidate.Result = "ambiguous"
		},
		"audit": func(value *Commit) { value.Audit.Digest = testDigest("tampered-audit") },
		"provenance": func(value *Commit) {
			value.Provenance.OutcomeDigest = testDigest("tampered-outcome")
		},
		"receipt": func(value *Commit) { value.Receipt.ProvenanceDigest = testDigest("tampered-provenance") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newEntityServiceFixture(t)
			if _, err := fixture.service.Execute(context.Background(), fixture.command); err != nil {
				t.Fatal(err)
			}
			fixture.store.mu.Lock()
			commit := fixture.store.results[fixture.command.IdempotencyKey]
			mutate(&commit)
			fixture.store.results[fixture.command.IdempotencyKey] = commit
			fixture.store.mu.Unlock()
			receipt, err := fixture.service.Execute(context.Background(), fixture.command)
			if Code(err) != ConflictError || ErrorReason(err) != IdempotencyConflict || receipt != (Receipt{}) {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

func TestServicePersistsDependencyUnavailableTerminal(t *testing.T) {
	fixture := newEntityServiceFixture(t)
	fixture.evidence.err = errors.New("offline")
	receipt, err := fixture.service.Execute(context.Background(), fixture.command)
	if Code(err) != UnavailableError || ErrorReason(err) != DependencyUnavailableReason ||
		receipt.Status != DependencyUnavailable || receipt.ReasonCode != DependencyUnavailableReason || len(fixture.store.commits) != 1 {
		t.Fatalf("receipt=%+v err=%v commits=%d", receipt, err, len(fixture.store.commits))
	}
	fixture.evidence.err = nil
	replayed, err := fixture.service.Execute(context.Background(), fixture.command)
	if err != nil || replayed != receipt || len(fixture.store.commits) != 1 {
		t.Fatalf("replayed=%+v err=%v commits=%d", replayed, err, len(fixture.store.commits))
	}
}

func TestServiceRejectsInvalidCommandBeforeDurableBegin(t *testing.T) {
	tests := map[string]func(*Command){
		"missing generated candidate identity": func(value *Command) { value.CandidateID = nil },
		"nil durable array":                    func(value *Command) { value.Counterevidence = nil },
		"scope drift": func(value *Command) {
			value.Observation.Scope.TenantID = transitionUUID(99)
		},
		"confidence assessment drift": func(value *Command) {
			value.ConfidenceAssessments[0].SourceQuality = "unknown"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newEntityServiceFixture(t)
			mutate(&fixture.command)
			receipt, err := fixture.service.Execute(context.Background(), fixture.command)
			if Code(err) != InvalidInputError || receipt != (Receipt{}) || len(fixture.store.digests) != 0 ||
				len(fixture.store.commits) != 0 {
				t.Fatalf("receipt=%+v err=%v digests=%d commits=%d", receipt, err, len(fixture.store.digests), len(fixture.store.commits))
			}
		})
	}
}
