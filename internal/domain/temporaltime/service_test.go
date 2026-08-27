package temporaltime

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestServicePersistsExactBundleAndRecoversExactReplay(t *testing.T) {
	service, store, command := testService(t, nil)
	receipt, err := service.Normalize(context.Background(), command)
	if err != nil || receipt.Outcome != Normalized || receipt.Record == nil {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	store.mu.Lock()
	if len(store.commits) != 1 || store.commits[0].Command != command || store.commits[0].Receipt != receipt ||
		store.commits[0].Record.OriginalTime.Text != command.OriginalTime.Text || store.commits[0].Audit.Digest != receipt.AuditDigest ||
		store.commits[0].Provenance.Digest != receipt.ProvenanceDigest {
		t.Fatalf("commits=%+v", store.commits)
	}
	store.mu.Unlock()

	replayed, err := service.Normalize(context.Background(), command)
	if err != nil || !reflect.DeepEqual(replayed, receipt) {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.commits) != 1 {
		t.Fatalf("exact replay committed %d times", len(store.commits))
	}
}

func TestServiceRecoversLostResponseWithoutDuplicateCommit(t *testing.T) {
	service, store, command := testService(t, nil)
	store.failAfterCommit = true
	if receipt, err := service.Normalize(context.Background(), command); Code(err) != Unavailable || receipt != (Receipt{}) {
		t.Fatalf("lost response receipt=%+v err=%v", receipt, err)
	}
	recovered, err := service.Normalize(context.Background(), command)
	if err != nil || recovered.Outcome != Normalized {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.commits) != 1 {
		t.Fatalf("lost-response recovery committed %d times", len(store.commits))
	}
}

func TestServiceResumesBegunCommandAfterRestart(t *testing.T) {
	service, store, command := testService(t, nil)
	_, commandDigest, err := CanonicalCommand(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.digests[command.IdempotencyKey] = commandDigest
	store.commands[command.IdempotencyKey] = command
	store.active[command.IdempotencyKey] = false
	store.mu.Unlock()
	receipt, err := service.Normalize(context.Background(), command)
	if err != nil || receipt.Outcome != Normalized {
		t.Fatalf("restart receipt=%+v err=%v", receipt, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.commits) != 1 || store.commands[command.IdempotencyKey] != command {
		t.Fatalf("restart commits=%d command=%+v", len(store.commits), store.commands[command.IdempotencyKey])
	}
}

func TestServiceDurablyDeniesChangedReplayWithoutReplacingReceipt(t *testing.T) {
	service, store, command := testService(t, nil)
	original, err := service.Normalize(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	changed := command
	changed.OriginalTime.Text = "2026-08-27T12:00:01"
	denial, err := service.Normalize(context.Background(), changed)
	if Code(err) != ConflictError || ErrorReason(err) != IdempotencyConflict || denial.Outcome != Denied || denial.ReasonCode != IdempotencyConflict {
		t.Fatalf("denial=%+v err=%v", denial, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !reflect.DeepEqual(store.receipts[command.IdempotencyKey], original) || len(store.denials) != 1 {
		t.Fatalf("original=%+v stored=%+v denials=%d", original, store.receipts[command.IdempotencyKey], len(store.denials))
	}
}

func TestServicePersistsCancellationTimeoutAndRecovery(t *testing.T) {
	for _, test := range []struct {
		name    string
		cause   error
		code    ErrorCode
		outcome Outcome
		reason  Reason
	}{
		{name: "canceled", cause: context.Canceled, code: Canceled, outcome: CanceledOutcome, reason: ContextCanceled},
		{name: "timeout", cause: context.DeadlineExceeded, code: Timeout, outcome: TimeoutOutcome, reason: ContextDeadline},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, store, command := testService(t, test.cause)
			receipt, err := service.Normalize(context.Background(), command)
			if Code(err) != test.code || receipt.Outcome != test.outcome || receipt.ReasonCode != test.reason || receipt.Record == nil {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
			store.mu.Lock()
			store.evidenceErr = nil
			store.mu.Unlock()
			replayed, replayErr := service.Normalize(context.Background(), command)
			if replayErr != nil || !reflect.DeepEqual(replayed, receipt) {
				t.Fatalf("terminal recovery=%+v err=%v", replayed, replayErr)
			}
		})
	}
}

func TestServiceConcurrentBoundaryCommitsAtMostOnce(t *testing.T) {
	service, store, command := testService(t, nil)
	const workers = 16
	var wait sync.WaitGroup
	wait.Add(workers)
	results := make(chan error, workers)
	for range workers {
		go func() {
			defer wait.Done()
			_, err := service.Normalize(context.Background(), command)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil && Code(err) != Unavailable {
			t.Fatalf("concurrent err=%v", err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.commits) != 1 || len(store.receipts) != 1 {
		t.Fatalf("commits=%d receipts=%d", len(store.commits), len(store.receipts))
	}
}

func TestServicePersistsComparisonAuditAndProvenance(t *testing.T) {
	service, store, _ := testService(t, nil)
	left := exactRecordFixture(t, "0199a401-1000-7000-8000-000000000081", digestOf('c'), "2026-08-27T19:00:00.000000000Z")
	right := exactRecordFixture(t, "0199a401-1000-7000-8000-000000000082", digestOf('d'), "2026-08-27T19:00:01.000000000Z")
	comparison, err := service.CompareAndPersist(context.Background(), "0199a401-1000-7000-8000-000000000083", left, right)
	if err != nil || comparison.Outcome != Before {
		t.Fatalf("comparison=%+v err=%v", comparison, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.comparisons) != 1 || store.comparisons[0].Comparison != comparison || !digestPattern.MatchString(store.comparisons[0].ComparisonDigest) ||
		!digestPattern.MatchString(store.comparisons[0].AuditDigest) || !digestPattern.MatchString(store.comparisons[0].ProvenanceDigest) {
		t.Fatalf("comparison commits=%+v", store.comparisons)
	}
}

func testService(t *testing.T, evidenceErr error) (*Service, *memoryTemporalStore, Command) {
	t.Helper()
	command := testCommand()
	command.OriginalTime = OriginalTime{Text: "2026-08-27T12:00:00", Format: "civil_second", Precision: Second}
	command.Timezone = offsetAssertion(-420)
	command.RequestedAt = "2098-08-27T19:00:00.000000000Z"
	command.Deadline = "2099-08-27T19:00:05.000000000Z"
	zero := int64(0)
	command.Calibration.EstimateNanoseconds, command.Calibration.RadiusNanoseconds = &zero, &zero
	registry, err := NewStrictParserRegistry([]ParserSpec{{Identity: command.Parser, Kind: BuiltinStrictParser}})
	if err != nil {
		t.Fatal(err)
	}
	timezones, err := NewPinnedTimezoneResolver("2026b", digestOf('b'), map[string]*time.Location{"Etc/UTC": time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryTemporalStore{
		digests: make(map[string]string), commands: make(map[string]Command), active: make(map[string]bool), receipts: make(map[string]Receipt), evidenceErr: evidenceErr,
	}
	dependencies := Dependencies{
		Evidence: store, Parsers: registry, Timezones: timezones, Calibrations: calibrationStub{}, Store: store,
		Audit: auditStub{}, Provenance: provenanceStub{}, Clock: fixedClock{value: testNow()},
	}
	service, err := NewService(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return service, store, command
}

type memoryTemporalStore struct {
	mu              sync.Mutex
	digests         map[string]string
	commands        map[string]Command
	active          map[string]bool
	receipts        map[string]Receipt
	commits         []Commit
	denials         []Commit
	comparisons     []ComparisonCommit
	failAfterCommit bool
	evidenceErr     error
}

func (store *memoryTemporalStore) VerifyBinding(context.Context, Case, SourceBinding) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.evidenceErr
}

func (store *memoryTemporalStore) LoadReceipt(_ context.Context, key string) (Receipt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.receipts[key]
	return value, exists, nil
}

func (store *memoryTemporalStore) LoadCommandDigest(_ context.Context, key string) (string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.digests[key]
	return value, exists, nil
}

func (store *memoryTemporalStore) Begin(_ context.Context, command Command, digest string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, exists := store.digests[command.IdempotencyKey]; exists {
		if existing != digest {
			return false, errors.New("changed digest")
		}
		if store.active[command.IdempotencyKey] || store.receipts[command.IdempotencyKey].SchemaVersion != "" {
			return false, nil
		}
	}
	store.digests[command.IdempotencyKey] = digest
	store.commands[command.IdempotencyKey] = command
	store.active[command.IdempotencyKey] = true
	return true, nil
}

func (store *memoryTemporalStore) Commit(_ context.Context, commit Commit) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := commit.Command.IdempotencyKey
	if commit.Receipt.ReasonCode == IdempotencyConflict {
		store.denials = append(store.denials, commit)
		return nil
	}
	if _, exists := store.receipts[key]; exists {
		return errors.New("duplicate commit")
	}
	store.commits = append(store.commits, commit)
	store.receipts[key] = commit.Receipt
	store.active[key] = false
	if store.failAfterCommit {
		store.failAfterCommit = false
		return errors.New("response lost")
	}
	return nil
}

func (store *memoryTemporalStore) CommitComparison(_ context.Context, commit ComparisonCommit) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.comparisons = append(store.comparisons, commit)
	return nil
}

type calibrationStub struct{}

func (calibrationStub) ResolveCalibration(_ context.Context, _ Case, value Calibration) (Calibration, error) {
	return value, nil
}

type auditStub struct{}

func (auditStub) BuildAudit(_ context.Context, operationID, commandDigest string, outcome Outcome, reason Reason) (AuditRecord, error) {
	return AuditRecord{OperationID: operationID, CommandDigest: commandDigest, Outcome: outcome, ReasonCode: reason, Digest: digestOf('e')}, nil
}

func (auditStub) BuildComparisonAudit(context.Context, Comparison) (string, error) {
	return digestOf('f'), nil
}

type provenanceStub struct{}

func (provenanceStub) BuildProvenance(_ context.Context, operationID, commandDigest, recordDigest string) (ProvenanceRecord, error) {
	return ProvenanceRecord{OperationID: operationID, CommandDigest: commandDigest, RecordDigest: recordDigest, PreviousDigest: digestOf('1'), Digest: digestOf('2')}, nil
}

func (provenanceStub) BuildComparisonProvenance(context.Context, Comparison, string) (string, string, error) {
	return digestOf('3'), digestOf('4'), nil
}

type fixedClock struct{ value time.Time }

func (clock fixedClock) Now() time.Time { return clock.value }
