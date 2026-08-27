package queryevidence

import (
	"context"
	"sync"
	"testing"

	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type metadataStub struct {
	mu           sync.Mutex
	records      map[string]workflowbase.MetadataRecord
	transactions map[string]workflowbase.CommitResult
}

func newMetadataStub() *metadataStub {
	return &metadataStub{records: map[string]workflowbase.MetadataRecord{}, transactions: map[string]workflowbase.CommitResult{}}
}

func metadataKey(key workflowbase.RecordKey) string {
	return key.Case.OrganizationID + "/" + key.Case.TenantID + "/" + key.Case.CaseID + "/" + key.Kind + "/" + key.ID
}

func (stub *metadataStub) Get(_ context.Context, key workflowbase.RecordKey) (workflowbase.MetadataRecord, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	value, found := stub.records[metadataKey(key)]
	if !found {
		return workflowbase.MetadataRecord{}, workflowbase.NewStorageError(workflowbase.StorageNotFound, "get", "key", "not found", nil)
	}
	value.Canonical = append([]byte(nil), value.Canonical...)
	return value, nil
}

func (stub *metadataStub) Transact(_ context.Context, transaction workflowbase.Transaction) (workflowbase.CommitResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if prior, found := stub.transactions[transaction.IdempotencyKey]; found {
		prior.Replayed = true
		return prior, nil
	}
	for _, mutation := range transaction.Mutations {
		current := stub.records[metadataKey(mutation.Key)]
		if current.Revision != mutation.ExpectedRevision {
			return workflowbase.CommitResult{}, workflowbase.NewStorageError(workflowbase.StorageConflict, "transact", "revision", "stale", nil)
		}
	}
	versions := map[string]uint64{}
	for _, mutation := range transaction.Mutations {
		copy := *mutation.Record
		copy.Canonical = append([]byte(nil), mutation.Record.Canonical...)
		stub.records[metadataKey(mutation.Key)] = copy
		versions[metadataKey(mutation.Key)] = copy.Revision
	}
	result := workflowbase.CommitResult{IdempotencyKey: transaction.IdempotencyKey, CommitSequence: uint64(len(stub.transactions) + 1), RecordVersions: versions}
	stub.transactions[transaction.IdempotencyKey] = result
	return result, nil
}

func TestRepositoryStorePersistsAndRecoversExactChain(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	_, ingest, _, audit, command := fixture(t, native)
	metadata := newMetadataStub()
	store, err := NewRepositoryStore(metadata)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := New(ingest, store, audit, testClock{evidenceNow})
	if err != nil {
		t.Fatal(err)
	}
	started, err := controller.Start(context.Background(), command, &sourceStub{data: native})
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := New(ingest, store, audit, testClock{evidenceNow})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.Start(context.Background(), command, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Record.RecordDigest != started.Record.RecordDigest || ingest.calls != 1 {
		t.Fatal("durable replay did not recover exact genesis")
	}

	head, found, err := store.LoadHead(context.Background(), started.Record.Stream)
	if err != nil || !found || head.RecordDigest != started.Record.RecordDigest {
		t.Fatal("durable head not recovered")
	}
}

func TestRepositoryStoreRejectsStaleHeadAndTampering(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	_, ingest, _, audit, command := fixture(t, native)
	metadata := newMetadataStub()
	store, _ := NewRepositoryStore(metadata)
	controller, _ := New(ingest, store, audit, testClock{evidenceNow})
	started, err := controller.Start(context.Background(), command, &sourceStub{data: native})
	if err != nil {
		t.Fatal(err)
	}

	changed := started.Record
	changed.RecordDigest = digest("substituted")
	if _, _, err = store.Append(context.Background(), ExpectedHead{}, "changed", changed.TransitionID, changed); Code(err) != InvalidInput {
		t.Fatal("invalid record reached storage")
	}

	key := metadataKey(headKey(started.Record.Stream))
	metadata.mu.Lock()
	value := metadata.records[key]
	value.Canonical[0] = '['
	metadata.records[key] = value
	metadata.mu.Unlock()
	if _, _, err = store.LoadHead(context.Background(), started.Record.Stream); Code(err) != Conflict {
		t.Fatal("tampered durable record was accepted")
	}
}

var _ workflowbase.MetadataStore = (*metadataStub)(nil)
