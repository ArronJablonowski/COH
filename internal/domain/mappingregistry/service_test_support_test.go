package mappingregistry

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type serviceFixture struct {
	service *Service
	store   *memoryMappingStore
	command Command
	input   applicationFixture
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	application := newApplicationFixture(t)
	signed := validSignedMapping(t)
	signed.Manifest = application.selected.Signed.Manifest
	signed.PublisherID = signed.Manifest.IssuerID
	_, digest, err := CanonicalManifest(context.Background(), signed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	signed.ManifestDigest = digest
	application.selected = verifiedMapping{Signed: signed, ManifestDigest: digest, RegistryRevision: 3}
	application.command.MappingDigest = digest
	application.command.ExpectedRegistryRevision = 3
	application.command.SchemaVersion = CommandSchemaVersion
	application.command.ContractVersion = ContractVersion
	application.command.IdempotencyKey = digestBytes([]byte("apply-idempotency"))
	application.command.RequestedAt = "2026-08-27T00:00:00.000000000Z"
	application.command.Deadline = "2099-08-27T00:00:00.000000000Z"
	store := &memoryMappingStore{
		digests: make(map[string]string), active: make(map[string]bool), receipts: make(map[string]Receipt),
		outcomes: make(map[string]Outcome), mappings: map[string]SignedMapping{digest: signed},
		snapshots: []RegistrySnapshot{{Source: signed.Manifest.Source, Revision: 3, CurrentManifestDigest: digest, Revocation: signed.Manifest.Revocation}},
	}
	dependencies := Dependencies{Evidence: store, Signatures: store, SourceSchemas: store, Store: store,
		Audit: mappingAuditStub{}, Provenance: mappingProvenanceStub{}, Clock: fixedMappingClock{now: time.Date(2026, 8, 27, 1, 0, 0, 0, time.UTC)}}
	service, err := NewService(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return &serviceFixture{service: service, store: store, command: application.command, input: *application}
}

func (fixture *serviceFixture) execute(ctx context.Context) (Receipt, error) {
	return fixture.service.Execute(ctx, fixture.command, &fixture.input.input)
}

type memoryMappingStore struct {
	mu               sync.Mutex
	digests          map[string]string
	active           map[string]bool
	receipts         map[string]Receipt
	outcomes         map[string]Outcome
	mappings         map[string]SignedMapping
	snapshots        []RegistrySnapshot
	commits          []Commit
	denials          []Commit
	failAfterCommit  bool
	evidenceErr      error
	schemaErr        error
	signatureErr     error
	signatureRevoked bool
}

func (store *memoryMappingStore) VerifyBinding(context.Context, Case, SourceBinding) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.evidenceErr
}

func (store *memoryMappingStore) VerifySourceSchema(context.Context, Case, SourceMatcher) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.schemaErr
}

func (store *memoryMappingStore) VerifySignature(_ context.Context, request SignatureRequest) (SignatureDecision, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.signatureErr != nil {
		return SignatureDecision{}, store.signatureErr
	}
	return SignatureDecision{Verified: true, Revoked: store.signatureRevoked, TrustRevision: request.KeyRevision, Revocation: request.Revocation}, nil
}

func (store *memoryMappingStore) LoadReceipt(_ context.Context, key string) (Receipt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.receipts[key]
	return value, exists, nil
}

func (store *memoryMappingStore) LoadOutcome(_ context.Context, digest string) (Outcome, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.outcomes[digest]
	return value, exists, nil
}

func (store *memoryMappingStore) LoadCommandDigest(_ context.Context, key string) (string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.digests[key]
	return value, exists, nil
}

func (store *memoryMappingStore) Begin(_ context.Context, command Command, digest string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, exists := store.digests[command.IdempotencyKey]; exists {
		if existing != digest {
			return false, errors.New("changed digest")
		}
		if store.active[command.IdempotencyKey] {
			return false, nil
		}
		if _, exists := store.receipts[command.IdempotencyKey]; exists {
			return false, nil
		}
	}
	store.digests[command.IdempotencyKey] = digest
	store.active[command.IdempotencyKey] = true
	return true, nil
}

func (store *memoryMappingStore) LoadSnapshots(context.Context, Case, SourceMatcher) ([]RegistrySnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]RegistrySnapshot(nil), store.snapshots...), nil
}

func (store *memoryMappingStore) LoadSignedMapping(_ context.Context, digest string) (SignedMapping, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.mappings[digest]
	return cloneSignedMapping(value), exists, nil
}

func (store *memoryMappingStore) Commit(ctx context.Context, commit Commit) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, _, err := CanonicalOutcome(ctx, commit.Outcome); err != nil {
		return err
	}
	if _, _, err := CanonicalReceipt(ctx, commit.Receipt); err != nil {
		return err
	}
	if commit.Receipt.ReasonCode == IdempotencyConflict {
		store.denials = append(store.denials, commit)
		store.outcomes[commit.Receipt.OutcomeDigest] = commit.Outcome
		return nil
	}
	key := commit.Command.IdempotencyKey
	if _, exists := store.receipts[key]; exists {
		return errors.New("duplicate commit")
	}
	if commit.SignedMapping != nil {
		if existing, exists := store.mappings[commit.SignedMapping.ManifestDigest]; exists {
			left, _, _ := CanonicalSignedMapping(context.Background(), existing)
			right, _, _ := CanonicalSignedMapping(context.Background(), *commit.SignedMapping)
			if !bytes.Equal(left, right) {
				return errors.New("manifest collision")
			}
		} else {
			store.mappings[commit.SignedMapping.ManifestDigest] = cloneSignedMapping(*commit.SignedMapping)
		}
	}
	if commit.Snapshot != nil {
		if len(store.snapshots) == 0 {
			if commit.Command.ExpectedRegistryRevision != 0 || commit.Snapshot.Revision != 1 {
				return errors.New("initial snapshot CAS")
			}
		} else if len(store.snapshots) != 1 || store.snapshots[0].Revision != commit.Command.ExpectedRegistryRevision ||
			commit.Snapshot.Revision != store.snapshots[0].Revision+1 {
			return errors.New("snapshot CAS")
		}
		store.snapshots = []RegistrySnapshot{*commit.Snapshot}
	}
	store.commits = append(store.commits, commit)
	store.outcomes[commit.Receipt.OutcomeDigest] = commit.Outcome
	store.receipts[key] = commit.Receipt
	store.active[key] = false
	if store.failAfterCommit {
		store.failAfterCommit = false
		return errors.New("response lost")
	}
	return nil
}

func (store *memoryMappingStore) committed() []Commit {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]Commit(nil), store.commits...)
}

type mappingAuditStub struct{}

func (mappingAuditStub) BuildAudit(_ context.Context, operationID, commandDigest string, status Status, reason Reason) (AuditRecord, error) {
	return AuditRecord{OperationID: operationID, CommandDigest: commandDigest, Status: status, Reason: reason,
		Digest: digestBytes([]byte("audit:" + operationID + ":" + string(status) + ":" + string(reason)))}, nil
}

type mappingProvenanceStub struct{}

func (mappingProvenanceStub) BuildProvenance(_ context.Context, operationID, commandDigest, outcomeDigest string) (ProvenanceRecord, error) {
	return ProvenanceRecord{OperationID: operationID, CommandDigest: commandDigest, OutcomeDigest: outcomeDigest,
		PreviousDigest: digestBytes([]byte("previous:" + operationID)), Digest: digestBytes([]byte("provenance:" + operationID + ":" + outcomeDigest))}, nil
}

func assertCommitMatches(t *testing.T, commit Commit, command Command, receipt Receipt) {
	t.Helper()
	if !reflect.DeepEqual(commit.Command, command) || commit.Receipt != receipt || commit.Outcome.CommandDigest != receipt.CommandDigest ||
		commit.Outcome.Status != receipt.Status || commit.Audit.Digest != receipt.AuditDigest || commit.Provenance.Digest != receipt.ProvenanceDigest {
		t.Fatalf("commit=%+v command=%+v receipt=%+v", commit, command, receipt)
	}
}
