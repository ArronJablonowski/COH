package skilldiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const repositoryRecordSchema = "coh.domain/v1"

type RepositoryStore struct{ repository workflowbase.MetadataStore }

type repositoryEnvelope struct {
	Schema         string     `json:"schema"`
	Kind           string     `json:"kind"`
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	TenantID       string     `json:"tenant_id"`
	CaseID         *string    `json:"case_id"`
	Revision       uint64     `json:"revision"`
	CreatedAt      string     `json:"created_at"`
	Data           recordWire `json:"data"`
}

func NewRepositoryStore(repository workflowbase.MetadataStore) (*RepositoryStore, error) {
	if repository == nil {
		return nil, newError(InvalidInput, "repository_required", false, nil)
	}
	return &RepositoryStore{repository: repository}, nil
}

func (store *RepositoryStore) Load(ctx context.Context, scope domain.CaseRef, taskID string,
	operation Phase, idempotency string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validCase(scope) || !uuidPattern.MatchString(taskID) ||
		(operation != CompactSearch && operation != DetailExpand && operation != ResourceFetch) ||
		!digestPattern.MatchString(idempotency) {
		return Record{}, false, newError(InvalidInput, "record_key_invalid", false, nil)
	}
	key := discoveryRecordKey(scope, taskID, operation, idempotency)
	record, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return Record{}, false, nil
		}
		return Record{}, false, mapStorageError("record_load", err)
	}
	var envelope repositoryEnvelope
	if err := decodeRepositoryRecord(record.Canonical, &envelope); err != nil {
		return Record{}, false, err
	}
	value, err := recordFromWire(envelope.Data)
	if err != nil {
		return Record{}, false, newError(Denied, "record_envelope_invalid", false, err)
	}
	if envelope.Schema != repositoryRecordSchema || envelope.Kind != "skill" ||
		envelope.ID != key.ID || envelope.OrganizationID != scope.OrganizationID ||
		envelope.TenantID != scope.TenantID || envelope.CaseID == nil || *envelope.CaseID != scope.CaseID ||
		envelope.Revision != record.Revision || envelope.CreatedAt != formatTime(value.CreatedAt) ||
		value.Case != scope || value.TaskID != taskID || value.Operation != operation ||
		value.IdempotencyDigest != idempotency || validateRecord(value) != nil {
		return Record{}, false, newError(Denied, "record_envelope_invalid", false, nil)
	}
	return cloneRecord(value), true, nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey string,
	value Record) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validOpaque(idempotencyKey, 1, MaximumIdempotencyBytes) || validateRecord(value) != nil {
		return Record{}, false, newError(InvalidInput, "record_commit_invalid", false, nil)
	}
	key := discoveryRecordKey(value.Case, value.TaskID, value.Operation, value.IdempotencyDigest)
	envelope := repositoryEnvelope{Schema: repositoryRecordSchema, Kind: "skill", ID: key.ID,
		OrganizationID: value.Case.OrganizationID, TenantID: value.Case.TenantID,
		CaseID: &value.Case.CaseID, Revision: value.Revision,
		CreatedAt: formatTime(value.CreatedAt), Data: recordToWire(value)}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return Record{}, false, err
	}
	metadata := workflowbase.MetadataRecord{Key: key, Schema: repositoryRecordSchema,
		Revision: value.Revision, Canonical: canonical, Digest: rawDigest(canonical)}
	transactionKey, _ := digest("COH-SKILL-DISCOVERY-TRANSACTION-V1\x00", struct {
		Case        domain.CaseRef `json:"case"`
		TaskID      string         `json:"task_id"`
		Operation   Phase          `json:"operation"`
		Idempotency string         `json:"idempotency_digest"`
	}{value.Case, value.TaskID, value.Operation, value.IdempotencyDigest})
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{
		ContractVersion: workflowbase.StorageContractVersion, IdempotencyKey: transactionKey,
		Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut, Key: key,
			ExpectedRevision: 0, Record: &metadata}},
	})
	if err != nil {
		return Record{}, false, mapStorageError("record_commit", err)
	}
	if result.Replayed {
		stored, found, loadErr := store.Load(ctx, value.Case, value.TaskID, value.Operation, value.IdempotencyDigest)
		if loadErr != nil {
			return Record{}, false, loadErr
		}
		if !found {
			return Record{}, false, newError(Denied, "replayed_record_missing", false, nil)
		}
		return stored, true, nil
	}
	return cloneRecord(value), false, nil
}

func discoveryRecordKey(scope domain.CaseRef, taskID string, operation Phase,
	idempotency string) workflowbase.RecordKey {
	id := deterministicUUID("COH-SKILL-DISCOVERY-RECORD-ID-V1\x00",
		scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+
			taskID+"\x00"+string(operation)+"\x00"+idempotency)
	return workflowbase.RecordKey{Case: scope, Kind: "skill", ID: id}
}

func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeRepositoryRecord(data []byte, output any) error {
	if len(data) == 0 || len(data) > 1<<20 || !json.Valid(data) {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "record_encoding_invalid", false, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	canonical, err := canonicalValue(output)
	if err != nil || string(canonical) != string(data) {
		return newError(Denied, "record_noncanonical", false, err)
	}
	return nil
}

func mapStorageError(operation string, err error) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return newError(InvalidInput, operation+"_invalid", false, err)
	case workflowbase.StorageDenied:
		return newError(Denied, operation+"_denied", false, err)
	case workflowbase.StorageNotFound:
		return newError(NotFound, operation+"_not_found", false, err)
	case workflowbase.StorageConflict:
		return newError(Conflict, operation+"_conflict", false, err)
	case workflowbase.StorageCanceled:
		return newError(Canceled, operation+"_canceled", false, err)
	case workflowbase.StorageTimeout:
		return newError(Timeout, operation+"_timeout", false, err)
	default:
		return newError(Unavailable, operation+"_unavailable", true, err)
	}
}

var _ Store = (*RepositoryStore)(nil)
