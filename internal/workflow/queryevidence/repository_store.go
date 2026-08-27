package queryevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	repositorySchema = "coh.domain/v1"
	repositoryKind   = "query_evidence"
)

type RepositoryStore struct{ repository workflowbase.MetadataStore }

type repositoryEnvelope struct {
	Schema         string          `json:"schema"`
	Kind           string          `json:"kind"`
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	TenantID       string          `json:"tenant_id"`
	CaseID         string          `json:"case_id"`
	Revision       uint64          `json:"revision"`
	CreatedAt      string          `json:"created_at"`
	EntryType      string          `json:"entry_type"`
	Data           json.RawMessage `json:"data"`
}

func NewRepositoryStore(repository workflowbase.MetadataStore) (*RepositoryStore, error) {
	if repository == nil {
		return nil, newError(InvalidInput, "repository_required", nil)
	}
	return &RepositoryStore{repository: repository}, nil
}

func (store *RepositoryStore) LoadHead(ctx context.Context, stream StreamRef) (Record, bool, error) {
	return store.load(ctx, headKey(stream), stream, "head", "")
}

func (store *RepositoryStore) Recover(ctx context.Context, stream StreamRef, idempotencyKey string) (Record, bool, error) {
	if !validIdempotency(idempotencyKey) {
		return Record{}, false, newError(InvalidInput, "idempotency_key_invalid", nil)
	}
	return store.load(ctx, replayKey(stream, idempotencyKey), stream, "replay", idempotencyKey)
}

func (store *RepositoryStore) load(ctx context.Context, key workflowbase.RecordKey, stream StreamRef,
	entryType, idempotencyKey string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validStream(stream) {
		return Record{}, false, newError(InvalidInput, "stream_invalid", nil)
	}
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return Record{}, false, nil
		}
		return Record{}, false, mapStorageError("record_load", err)
	}
	var envelope repositoryEnvelope
	if err = decodeExact(metadata.Canonical, &envelope); err != nil {
		return Record{}, false, err
	}
	record, canonical, err := DecodeRecord(ctx, envelope.Data)
	if err != nil {
		return Record{}, false, err
	}
	wantRevision := record.Revision
	if entryType == "replay" {
		wantRevision = 1
	}
	if metadata.Key != key || metadata.Schema != repositorySchema || metadata.Revision != wantRevision ||
		metadata.Digest != contentDigest(metadata.Canonical) || envelope.Schema != repositorySchema ||
		envelope.Kind != repositoryKind || envelope.ID != key.ID || envelope.OrganizationID != stream.OrganizationID ||
		envelope.TenantID != stream.TenantID || envelope.CaseID != stream.CaseID || envelope.Revision != wantRevision ||
		envelope.CreatedAt != record.OccurredAt || envelope.EntryType != entryType || !bytes.Equal(canonical, envelope.Data) ||
		record.Stream != stream || idempotencyKey != "" && key != replayKey(stream, idempotencyKey) {
		return Record{}, false, newError(Conflict, "repository_record_invalid", nil)
	}
	return record, true, nil
}

func (store *RepositoryStore) Append(ctx context.Context, expected ExpectedHead, idempotencyKey,
	transitionID string, record Record) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validIdempotency(idempotencyKey) || !validDigest(transitionID) || VerifyRecord(record) != nil ||
		record.TransitionID != transitionID || !validExpected(expected, record) {
		return Record{}, false, newError(InvalidInput, "append_invalid", nil)
	}
	if recovered, found, err := store.Recover(ctx, record.Stream, idempotencyKey); err != nil {
		return Record{}, false, err
	} else if found {
		if recovered.TransitionID != transitionID || recovered.RecordDigest != record.RecordDigest {
			return Record{}, false, newError(Conflict, "changed_replay", nil)
		}
		return recovered, true, nil
	}
	headRecord, err := repositoryRecord(headKey(record.Stream), "head", record, record.Revision)
	if err != nil {
		return Record{}, false, err
	}
	replayRecord, err := repositoryRecord(replayKey(record.Stream, idempotencyKey), "replay", record, 1)
	if err != nil {
		return Record{}, false, err
	}
	transaction := workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: repositoryIdempotency(record.Stream, idempotencyKey), Mutations: []workflowbase.Mutation{
			{Kind: workflowbase.MutationPut, Key: headRecord.Key, ExpectedRevision: expected.Revision, Record: &headRecord},
			{Kind: workflowbase.MutationPut, Key: replayRecord.Key, ExpectedRevision: 0, Record: &replayRecord},
		}}
	result, err := store.repository.Transact(ctx, transaction)
	if err != nil {
		return Record{}, false, mapStorageError("record_append", err)
	}
	if result.Replayed {
		recovered, found, recoverErr := store.Recover(ctx, record.Stream, idempotencyKey)
		if recoverErr != nil || !found {
			return Record{}, false, newError(Conflict, "replayed_record_missing", recoverErr)
		}
		if recovered.TransitionID != transitionID || recovered.RecordDigest != record.RecordDigest {
			return Record{}, false, newError(Conflict, "changed_replay", nil)
		}
		return recovered, true, nil
	}
	return record, false, nil
}

func validExpected(expected ExpectedHead, record Record) bool {
	if record.Revision == 1 {
		return expected == (ExpectedHead{}) && record.PreviousProvenanceDigest == ""
	}
	return expected.Revision == record.Revision-1 && validDigest(expected.ProvenanceDigest) &&
		record.PreviousProvenanceDigest == expected.ProvenanceDigest
}

func validIdempotency(value string) bool {
	return len(value) > 0 && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func repositoryRecord(key workflowbase.RecordKey, entryType string, record Record, revision uint64) (workflowbase.MetadataRecord, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return workflowbase.MetadataRecord{}, newError(Internal, "repository_encoding_failed", err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return workflowbase.MetadataRecord{}, newError(Internal, "repository_encoding_failed", err)
	}
	envelope := repositoryEnvelope{Schema: repositorySchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: key.Case.CaseID,
		Revision: revision, CreatedAt: record.OccurredAt, EntryType: entryType, Data: canonical}
	encoded, err = json.Marshal(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, newError(Internal, "repository_encoding_failed", err)
	}
	canonical, err = domaincontract.Canonicalize(encoded)
	if err != nil {
		return workflowbase.MetadataRecord{}, newError(Internal, "repository_encoding_failed", err)
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositorySchema, Revision: revision,
		Canonical: canonical, Digest: contentDigest(canonical)}, nil
}

func headKey(stream StreamRef) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: streamCase(stream), Kind: repositoryKind,
		ID: deterministicUUID("COH-QUERY-EVIDENCE-HEAD-ID-V1\x00", streamIdentity(stream))}
}

func replayKey(stream StreamRef, idempotencyKey string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: streamCase(stream), Kind: repositoryKind,
		ID: deterministicUUID("COH-QUERY-EVIDENCE-REPLAY-ID-V1\x00", streamIdentity(stream)+"\x00"+idempotencyKey)}
}

func streamCase(stream StreamRef) domain.CaseRef {
	return domain.CaseRef{OrganizationID: stream.OrganizationID, TenantID: stream.TenantID, CaseID: stream.CaseID}
}

func streamIdentity(stream StreamRef) string {
	return stream.OrganizationID + "\x00" + stream.TenantID + "\x00" + stream.CaseID + "\x00" + stream.QueryID + "\x00" + stream.AttemptID
}

func repositoryIdempotency(stream StreamRef, value string) string {
	return contentDigest([]byte("COH-QUERY-EVIDENCE-COMMIT-V1\x00" + streamIdentity(stream) + "\x00" + value))
}

func deterministicUUID(domainName, value string) string {
	sum := sha256.Sum256([]byte(domainName + value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func contentDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > MaximumDocumentBytes || !json.Valid(input) {
		return newError(Conflict, "repository_encoding_invalid", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Conflict, "repository_encoding_invalid", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Conflict, "repository_encoding_invalid", nil)
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return newError(Internal, "repository_encoding_failed", err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil || !bytes.Equal(canonical, input) {
		return newError(Conflict, "repository_encoding_invalid", err)
	}
	return nil
}

func mapStorageError(operation string, err error) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return newError(InvalidInput, operation+"_invalid", err)
	case workflowbase.StorageDenied:
		return newError(Denied, operation+"_denied", err)
	case workflowbase.StorageConflict:
		return newError(Conflict, operation+"_conflict", err)
	case workflowbase.StorageCanceled:
		return newError(Canceled, operation+"_canceled", err)
	case workflowbase.StorageTimeout:
		return newError(Timeout, operation+"_timeout", err)
	default:
		return newError(Unavailable, operation+"_unavailable", err)
	}
}

var _ EvidenceStore = (*RepositoryStore)(nil)
