package subagentdag

import (
	"context"
	"testing"

	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

type repositoryDriver struct {
	records             map[string]workflowbase.MetadataRecord
	replays             map[string]workflowbase.CommitResult
	sequence            uint64
	failAfterCommitOnce bool
}

func newRepositoryDriver() *repositoryDriver {
	return &repositoryDriver{records: map[string]workflowbase.MetadataRecord{},
		replays: map[string]workflowbase.CommitResult{}}
}

func (driver *repositoryDriver) Get(_ context.Context, key workflowbase.RecordKey) (workflowbase.MetadataRecord, error) {
	value, found := driver.records[repositoryStorageKey(key)]
	if !found {
		return workflowbase.MetadataRecord{}, workflowbase.NewStorageError(
			workflowbase.StorageNotFound, "get", "key", "not found", nil)
	}
	value.Canonical = append([]byte{}, value.Canonical...)
	return value, nil
}

func (driver *repositoryDriver) Transact(_ context.Context, transaction workflowbase.Transaction) (workflowbase.CommitResult, error) {
	if replay, found := driver.replays[transaction.IdempotencyKey]; found {
		replay.Replayed = true
		return replay, nil
	}
	if err := workflowbase.ValidateTransaction(transaction); err != nil {
		return workflowbase.CommitResult{}, err
	}
	for _, mutation := range transaction.Mutations {
		if driver.records[repositoryStorageKey(mutation.Key)].Revision != mutation.ExpectedRevision {
			return workflowbase.CommitResult{}, workflowbase.NewStorageError(
				workflowbase.StorageConflict, "transact", "revision", "conflict", nil)
		}
	}
	driver.sequence++
	result := workflowbase.CommitResult{IdempotencyKey: transaction.IdempotencyKey,
		CommitSequence: driver.sequence, RecordVersions: map[string]uint64{}, OutboxIDs: []string{}}
	for _, mutation := range transaction.Mutations {
		value := *mutation.Record
		value.Canonical = append([]byte{}, value.Canonical...)
		key := repositoryStorageKey(mutation.Key)
		driver.records[key] = value
		result.RecordVersions[key] = value.Revision
	}
	driver.replays[transaction.IdempotencyKey] = result
	if driver.failAfterCommitOnce {
		driver.failAfterCommitOnce = false
		return workflowbase.CommitResult{}, workflowbase.NewStorageError(
			workflowbase.StorageUnavailable, "transact", "response", "lost response", nil)
	}
	return result, nil
}

func TestRepositoryStoreRecoversLostCommitResponseByExactReplay(t *testing.T) {
	driver := newRepositoryDriver()
	driver.failAfterCommitOnce = true
	store := guardedRepositoryStore(t, driver)
	clock := &testClock{testNow}
	authority := &authorityStub{clock: clock, allow: true}
	budgets := &budgetStub{reservations: map[string]runbudget.Reservation{}}
	controller, err := New(store, authority, runtimeStub{}, cancelerStub{}, budgets, clock)
	if err != nil {
		t.Fatal(err)
	}
	request := createRequest()
	if _, err = controller.Create(context.Background(), request); CodeOf(err) != Unavailable {
		t.Fatalf("lost response err=%v", err)
	}
	recovered, err := controller.Create(context.Background(), request)
	if err != nil || !recovered.Replayed || recovered.Task.TaskID != request.RootTaskID || len(driver.records) != 1 {
		t.Fatalf("recovered=%+v records=%d err=%v", recovered, len(driver.records), err)
	}
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
	return workflowbase.MigrationResult{}, workflowbase.NewStorageError(
		workflowbase.StorageDenied, "migrate", "plan", "unsupported", nil)
}

func repositoryStorageKey(key workflowbase.RecordKey) string {
	return key.Case.OrganizationID + "/" + key.Case.TenantID + "/" + key.Case.CaseID + "/" + key.Kind + "/" + key.ID
}

func TestRepositoryStorePersistsGraphAndRecoversCreateReplayAfterProgress(t *testing.T) {
	driver := newRepositoryDriver()
	store := guardedRepositoryStore(t, driver)
	clock := &testClock{testNow}
	authority := &authorityStub{clock: clock, allow: true}
	budgets := &budgetStub{reservations: map[string]runbudget.Reservation{}}
	controller, err := New(store, authority, runtimeStub{}, cancelerStub{}, budgets, clock)
	if err != nil {
		t.Fatal(err)
	}
	created, err := controller.Create(context.Background(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	child := delegateRequest("repository-child", AlertTriageRole, testRoot)
	delegated, err := controller.Delegate(context.Background(), child)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.Load(context.Background(), created.Graph.Case, testGraph)
	if err != nil || !found || loaded.ProvenanceDigest != delegated.Graph.ProvenanceDigest || len(loaded.Tasks) != 2 {
		t.Fatalf("loaded=%+v found=%v err=%v", loaded, found, err)
	}
	replayed, err := controller.Create(context.Background(), createRequest())
	if err != nil || !replayed.Replayed || replayed.Graph.ProvenanceDigest != delegated.Graph.ProvenanceDigest {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	changed := createRequest()
	changed.InputRefs = []string{testDigest("changed-input")}
	if _, err = controller.Create(context.Background(), changed); CodeOf(err) != Denied || Reason(err) != "changed_replay" {
		t.Fatalf("changed replay err=%v", err)
	}
	for _, record := range driver.records {
		if err = workflowbase.ValidateMetadataRecord(record); err != nil {
			t.Fatalf("invalid stored record: %v", err)
		}
	}
}

func TestRepositoryStoreRejectsStaleTransitionAndCrossScopeLoad(t *testing.T) {
	driver := newRepositoryDriver()
	store := guardedRepositoryStore(t, driver)
	controller, _, _, _, _ := newFixture(t)
	created, err := controller.Create(context.Background(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Begin(context.Background(), "repository-begin", created.Graph); err != nil {
		t.Fatal(err)
	}
	firstRequest := delegateRequest("repository-first", AlertTriageRole, testRoot)
	first, err := controller.Delegate(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Save(context.Background(), "repository-first", created.Graph, first.Graph); err != nil {
		t.Fatal(err)
	}
	secondRequest := delegateRequest("repository-second", SIEMQueryRole, testRoot)
	second, err := controller.Delegate(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Save(context.Background(), "repository-second", first.Graph, second.Graph); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Save(context.Background(), "stale-retry", created.Graph, first.Graph); CodeOf(err) != Conflict {
		t.Fatalf("stale save err=%v", err)
	}
	wrongScope := second.Graph.Case
	wrongScope.CaseID = testUUID("wrong-case")
	if _, found, loadErr := store.Load(context.Background(), wrongScope, testGraph); loadErr != nil || found {
		t.Fatalf("cross-scope found=%v err=%v", found, loadErr)
	}
}

func TestRepositoryStoreRejectsValidButDestructiveGraphRewrite(t *testing.T) {
	driver := newRepositoryDriver()
	store := guardedRepositoryStore(t, driver)
	controller, _, _, _, _ := newFixture(t)
	created, err := controller.Create(context.Background(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Begin(context.Background(), "destructive-begin", created.Graph); err != nil {
		t.Fatal(err)
	}
	delegate := delegateRequest("destructive-child", AlertTriageRole, testRoot)
	delegated, err := controller.Delegate(context.Background(), delegate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Save(context.Background(), "destructive-delegate", created.Graph, delegated.Graph); err != nil {
		t.Fatal(err)
	}
	rewrite := cloneGraph(delegated.Graph)
	rewrite.Tasks = []Task{cloneTask(created.Task)}
	rewrite.Edges = []Edge{}
	rewrite.Receipts = []Receipt{created.Graph.Receipts[0]}
	rewrite.PreviousProvenanceDigest = delegated.Graph.ProvenanceDigest
	rewrite.ProvenanceDigest = ""
	rewrite.Revision++
	rewrite.ProvenanceDigest, _ = graphProvenanceDigest(rewrite)
	if err = validateGraph(rewrite); err != nil {
		t.Fatalf("test rewrite must be internally valid: %v", err)
	}
	if _, _, err = store.Save(context.Background(), "destructive-rewrite", delegated.Graph, rewrite); CodeOf(err) != Denied || Reason(err) != "graph_transition_invalid" {
		t.Fatalf("destructive rewrite err=%v", err)
	}
}

func guardedRepositoryStore(t *testing.T, driver *repositoryDriver) *RepositoryStore {
	t.Helper()
	guarded, err := workflowbase.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
