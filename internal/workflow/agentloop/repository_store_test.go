package agentloop

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type repositoryDriver struct {
	records      map[string]workflowbase.MetadataRecord
	transactions []workflowbase.Transaction
	replays      map[string]workflowbase.CommitResult
	sequence     uint64
}

func newRepositoryDriver() *repositoryDriver {
	return &repositoryDriver{records: map[string]workflowbase.MetadataRecord{}, replays: map[string]workflowbase.CommitResult{}}
}

func (driver *repositoryDriver) Get(_ context.Context, key workflowbase.RecordKey) (workflowbase.MetadataRecord, error) {
	value, ok := driver.records[storageKey(key)]
	if !ok {
		return workflowbase.MetadataRecord{}, workflowbase.NewStorageError(workflowbase.StorageNotFound, "get", "key", "not found", nil)
	}
	value.Canonical = append([]byte(nil), value.Canonical...)
	return value, nil
}

func (driver *repositoryDriver) Transact(_ context.Context, transaction workflowbase.Transaction) (workflowbase.CommitResult, error) {
	if replay, ok := driver.replays[transaction.IdempotencyKey]; ok {
		replay.Replayed = true
		return replay, nil
	}
	if err := workflowbase.ValidateTransaction(transaction); err != nil {
		return workflowbase.CommitResult{}, err
	}
	for _, mutation := range transaction.Mutations {
		current := driver.records[storageKey(mutation.Key)]
		if current.Revision != mutation.ExpectedRevision {
			return workflowbase.CommitResult{}, workflowbase.NewStorageError(workflowbase.StorageConflict, "transact", "revision", "conflict", nil)
		}
	}
	driver.sequence++
	result := workflowbase.CommitResult{IdempotencyKey: transaction.IdempotencyKey, CommitSequence: driver.sequence, RecordVersions: map[string]uint64{}, OutboxIDs: []string{}}
	for _, mutation := range transaction.Mutations {
		value := *mutation.Record
		value.Canonical = append([]byte(nil), value.Canonical...)
		driver.records[storageKey(mutation.Key)] = value
		result.RecordVersions[storageKey(mutation.Key)] = value.Revision
	}
	for _, message := range transaction.Outbox {
		result.OutboxIDs = append(result.OutboxIDs, message.ID)
	}
	sort.Strings(result.OutboxIDs)
	driver.transactions = append(driver.transactions, transaction)
	driver.replays[transaction.IdempotencyKey] = result
	return result, nil
}

func (*repositoryDriver) ClaimOutbox(context.Context, workflowbase.OutboxClaim) ([]workflowbase.OutboxDelivery, error) {
	return []workflowbase.OutboxDelivery{}, nil
}
func (*repositoryDriver) SettleOutbox(context.Context, workflowbase.OutboxSettlement) error {
	return nil
}
func (*repositoryDriver) MigrationStatus(context.Context, string) (workflowbase.MigrationResult, error) {
	return workflowbase.MigrationResult{State: workflowbase.MigrationPending}, nil
}
func (*repositoryDriver) Migrate(context.Context, workflowbase.MigrationPlan) (workflowbase.MigrationResult, error) {
	return workflowbase.MigrationResult{}, workflowbase.NewStorageError(workflowbase.StorageDenied, "migrate", "plan", "not supported", nil)
}

func storageKey(key workflowbase.RecordKey) string {
	return key.Case.OrganizationID + "/" + key.Case.TenantID + "/" + key.Case.CaseID + "/" + key.Kind + "/" + key.ID
}

func TestRepositoryStorePersistsCanonicalStateAndOutboxAtomically(t *testing.T) {
	driver := newRepositoryDriver()
	guarded, err := workflowbase.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{value: mustTime(t, "2026-08-26T16:10:00.000000000Z")}
	loop, err := New(store, &modelStub{ref: domain.ArtifactRef{Digest: testDigestTwo, MediaType: "application/json", Classification: "internal", Length: 1}}, &actionStub{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	created := startPlan(t, loop)
	validator, err := domaincontract.LoadValidator(os.DirFS("../../../contracts/domain/v1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(driver.transactions) != 1 || len(driver.transactions[0].Mutations) != 2 || len(driver.transactions[0].Outbox) != 1 || driver.transactions[0].Outbox[0].PayloadDigest != created.Run.ProvenanceDigest {
		t.Fatalf("transaction=%+v", driver.transactions)
	}
	for _, record := range driver.records {
		text := string(record.Canonical)
		if strings.Contains(text, "prompt") || strings.Contains(text, "credential") || strings.Contains(text, "secret") || strings.Contains(text, "evidence bytes") {
			t.Fatalf("unsafe workflow record: %s", text)
		}
		if err := workflowbase.ValidateMetadataRecord(record); err != nil {
			t.Fatalf("invalid record: %v", err)
		}
		if _, err := validator.Validate(context.Background(), record.Canonical); err != nil {
			t.Fatalf("record violates domain payload contract: %v\n%s", err, record.Canonical)
		}
	}
	loaded, err := store.Load(context.Background(), testScope(), testRun)
	if err != nil || loaded.Run.ProvenanceDigest != created.Run.ProvenanceDigest || loaded.Step.StepID != testPlanStep {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	replayed, err := loop.Start(context.Background(), StartRequest{IdempotencyKey: "start-1", RunID: testRun, StepID: testPlanStep, Case: testScope(), ActorID: testActor, PolicyDigest: testDigestOne, ProviderRoute: "connected", Activity: PlanningActivity, InputRefs: []string{testDigestOne}, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")})
	if err != nil || !replayed.Replayed || len(driver.transactions) != 1 {
		t.Fatalf("replayed=%+v err=%v transactions=%d", replayed, err, len(driver.transactions))
	}
}

func TestRepositoryStoreRejectsIllegalStateTransitions(t *testing.T) {
	for name, mutate := range map[string]func(*Snapshot){
		"skip_running": func(next *Snapshot) {
			next.Run.Status = RunWaiting
			next.Step.Status = StepSucceeded
		},
		"change_actor": func(next *Snapshot) {
			next.Step.Status = StepRunning
			next.Run.ActorID = "0199a213-81c0-7800-8aa1-bbab2a035a79"
		},
		"schedule_while_active": func(next *Snapshot) {
			next.Run.CurrentStepID = testActionStep
			next.Step = Step{
				ContractVersion: ContractVersion, StepID: testActionStep, RunID: testRun, Case: testScope(),
				Kind: PlanningActivity, Status: StepPending, Attempt: 1,
				Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z"), InputRefs: []string{}, OutputRefs: []string{},
				ProvenanceDigest: testDigestThree, CreatedAt: next.Run.UpdatedAt, UpdatedAt: next.Run.UpdatedAt, Revision: 1,
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			driver := newRepositoryDriver()
			guarded, _ := workflowbase.GuardStorage(driver)
			store, _ := NewRepositoryStore(guarded)
			loop, _, _, _, _ := newTestLoop(t)
			prior := startPlan(t, loop)
			if _, err := store.Create(context.Background(), "create", prior); err != nil {
				t.Fatal(err)
			}
			next := cloneSnapshot(prior)
			next.Run.Revision++
			next.Run.Sequence++
			next.Step.Revision++
			next.Run.UpdatedAt = next.Run.UpdatedAt.Add(1)
			next.Step.UpdatedAt = next.Run.UpdatedAt
			next.Run.ProvenanceDigest = testDigestThree
			next.Step.ProvenanceDigest = testDigestThree
			mutate(&next)
			if _, err := store.Save(context.Background(), "illegal", prior, next); Code(err) != Denied {
				t.Fatalf("illegal transition accepted: %+v err=%v", next, err)
			}
		})
	}
}

func TestRepositoryStoreRejectsIllegalInitialState(t *testing.T) {
	driver := newRepositoryDriver()
	guarded, _ := workflowbase.GuardStorage(driver)
	store, _ := NewRepositoryStore(guarded)
	loop, _, _, _, _ := newTestLoop(t)
	initial := startPlan(t, loop)
	initial.Run.Status = RunWaiting
	initial.Step.Status = StepSucceeded
	if _, err := store.Create(context.Background(), "illegal-create", initial); Code(err) != InvalidInput || len(driver.transactions) != 0 {
		t.Fatalf("illegal initial state accepted: err=%v transactions=%d", err, len(driver.transactions))
	}
}

func TestRepositoryStoreRejectsCrossScopeAndRevisionConflict(t *testing.T) {
	driver := newRepositoryDriver()
	guarded, _ := workflowbase.GuardStorage(driver)
	store, _ := NewRepositoryStore(guarded)
	loop, _, _, _, _ := newTestLoop(t)
	snapshot := startPlan(t, loop)
	if _, err := store.Create(context.Background(), "create", snapshot); err != nil {
		t.Fatal(err)
	}
	other := testScope()
	other.TenantID = "0199a213-81c0-7800-8aa1-bbab2a035a79"
	if _, err := store.Load(context.Background(), other, testRun); Code(err) != NotFound {
		t.Fatalf("cross-scope err=%v", err)
	}
	next := cloneSnapshot(snapshot)
	next.Run.Revision += 2
	next.Run.Sequence++
	next.Step.Revision++
	if _, err := store.Save(context.Background(), "bad-revision", snapshot, next); Code(err) != Conflict {
		t.Fatalf("revision err=%v", err)
	}
}
