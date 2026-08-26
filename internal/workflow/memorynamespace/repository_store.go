package memorynamespace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const repositoryRecordSchema = "coh.domain/v1"

type RepositoryStore struct {
	namespace  Namespace
	repository workflowbase.MetadataStore
}

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

func NewRepositoryStore(namespace Namespace, repository workflowbase.MetadataStore) (*RepositoryStore, error) {
	if !validNamespace(namespace) || repository == nil {
		return nil, newError(InvalidInput, "repository_store_invalid", false, nil)
	}
	return &RepositoryStore{namespace: namespace, repository: repository}, nil
}

func (store *RepositoryStore) Namespace() Namespace { return store.namespace }

func (store *RepositoryStore) Load(ctx context.Context, scope Scope, key string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if validateScope(store.namespace, scope) != nil || !tokenPattern.MatchString(key) {
		return Record{}, false, newError(InvalidInput, "record_key_invalid", false, nil)
	}
	return store.load(ctx, currentRecordKey(store.namespace, scope, key), scope, key, "current")
}

func (store *RepositoryStore) Recover(ctx context.Context, scope Scope, key, idempotency string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if validateScope(store.namespace, scope) != nil || !tokenPattern.MatchString(key) || !digestPattern.MatchString(idempotency) {
		return Record{}, false, newError(InvalidInput, "recovery_key_invalid", false, nil)
	}
	return store.load(ctx, receiptRecordKey(store.namespace, scope, key, idempotency), scope, key, "receipt")
}

func (store *RepositoryStore) load(ctx context.Context, recordKey workflowbase.RecordKey, scope Scope,
	key, kind string) (Record, bool, error) {
	metadata, err := store.repository.Get(ctx, recordKey)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return Record{}, false, nil
		}
		return Record{}, false, mapStorageError("record_load", err)
	}
	var envelope repositoryEnvelope
	if err := decodeRepositoryRecord(metadata.Canonical, &envelope); err != nil {
		return Record{}, false, err
	}
	value, err := recordFromWire(envelope.Data)
	if err != nil {
		return Record{}, false, err
	}
	wantCase := scopeCaseID(scope)
	if envelope.Schema != repositoryRecordSchema || envelope.Kind != "memory" || envelope.ID != recordKey.ID ||
		envelope.OrganizationID != scope.OrganizationID || envelope.TenantID != scope.TenantID ||
		!sameOptionalCase(envelope.CaseID, wantCase) || envelope.Revision != metadata.Revision ||
		envelope.CreatedAt != formatTime(value.CreatedAt) || value.Namespace != store.namespace ||
		value.Scope != scope || value.Key != key || validateRecord(value) != nil {
		return Record{}, false, newError(Denied, kind+"_record_invalid", false, nil)
	}
	if kind == "current" && envelope.Revision != value.Revision || kind == "receipt" && envelope.Revision != 1 {
		return Record{}, false, newError(Denied, kind+"_revision_invalid", false, nil)
	}
	return cloneRecord(value), true, nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey, intent string,
	expected uint64, value Record) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validOpaque(idempotencyKey, 1, 256) || !digestPattern.MatchString(intent) ||
		validateRecord(value) != nil || value.Namespace != store.namespace || value.IntentDigest != intent ||
		value.Revision != expected+1 {
		return Record{}, false, newError(InvalidInput, "record_commit_invalid", false, nil)
	}
	if recovered, found, err := store.Recover(ctx, value.Scope, value.Key, value.IdempotencyDigest); err != nil {
		return Record{}, false, err
	} else if found {
		if recovered.IntentDigest != intent {
			return Record{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return recovered, true, nil
	}
	currentKey := currentRecordKey(value.Namespace, value.Scope, value.Key)
	receiptKey := receiptRecordKey(value.Namespace, value.Scope, value.Key, value.IdempotencyDigest)
	currentMetadata, err := metadataFor(currentKey, value.Revision, value)
	if err != nil {
		return Record{}, false, err
	}
	receiptMetadata, err := metadataFor(receiptKey, 1, value)
	if err != nil {
		return Record{}, false, err
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: currentKey, ExpectedRevision: expected, Record: &currentMetadata},
		{Kind: workflowbase.MutationPut, Key: receiptKey, ExpectedRevision: 0, Record: &receiptMetadata},
	}
	sort.Slice(mutations, func(i, j int) bool { return mutations[i].Key.ID < mutations[j].Key.ID })
	txDigest := digest("COH-MEMORY-TRANSACTION-V1\x00", []byte(string(store.namespace)+"\x00"+value.Scope.OrganizationID+
		"\x00"+value.Scope.TenantID+"\x00"+value.Scope.CaseID+"\x00"+value.Scope.SessionID+"\x00"+
		value.Scope.SubjectActorID+"\x00"+value.Key+"\x00"+value.IdempotencyDigest))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: txDigest, Mutations: mutations})
	if err != nil {
		return Record{}, false, mapStorageError("record_commit", err)
	}
	if result.Replayed {
		recovered, found, recoverErr := store.Recover(ctx, value.Scope, value.Key, value.IdempotencyDigest)
		if recoverErr != nil {
			return Record{}, false, recoverErr
		}
		if !found || recovered.IntentDigest != intent {
			return Record{}, false, newError(Denied, "replayed_record_invalid", false, nil)
		}
		return recovered, true, nil
	}
	return cloneRecord(value), false, nil
}

func metadataFor(key workflowbase.RecordKey, revision uint64, value Record) (workflowbase.MetadataRecord, error) {
	caseID := scopeCaseID(value.Scope)
	envelope := repositoryEnvelope{Schema: repositoryRecordSchema, Kind: "memory", ID: key.ID,
		OrganizationID: value.Scope.OrganizationID, TenantID: value.Scope.TenantID, CaseID: caseID,
		Revision: revision, CreatedAt: formatTime(value.CreatedAt), Data: recordToWire(value)}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositoryRecordSchema, Revision: revision,
		Canonical: canonical, Digest: rawDigest(canonical)}, nil
}

func currentRecordKey(namespace Namespace, scope Scope, key string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scopeCase(scope), Kind: "memory", ID: deterministicUUID(
		"COH-MEMORY-CURRENT-ID-V1\x00", scopeIdentity(namespace, scope)+"\x00"+key)}
}

func receiptRecordKey(namespace Namespace, scope Scope, key, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scopeCase(scope), Kind: "memory", ID: deterministicUUID(
		"COH-MEMORY-RECEIPT-ID-V1\x00", scopeIdentity(namespace, scope)+"\x00"+key+"\x00"+idempotency)}
}

func scopeIdentity(namespace Namespace, scope Scope) string {
	return string(namespace) + "\x00" + scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID +
		"\x00" + scope.SessionID + "\x00" + scope.SubjectActorID
}

func scopeCase(scope Scope) domain.CaseRef {
	return domain.CaseRef{OrganizationID: scope.OrganizationID, TenantID: scope.TenantID, CaseID: scope.CaseID}
}
func scopeCaseID(scope Scope) *string {
	if scope.CaseID == "" {
		return nil
	}
	value := scope.CaseID
	return &value
}
func sameOptionalCase(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
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
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	canonical, err := canonicalValue(output)
	if err != nil || string(canonical) != string(data) {
		return newError(Denied, "record_noncanonical", false, nil)
	}
	return nil
}

func recordFromWire(value recordWire) (Record, error) {
	created, err := parseWireTime(value.CreatedAt)
	if err != nil {
		return Record{}, err
	}
	updated, err := parseWireTime(value.UpdatedAt)
	if err != nil {
		return Record{}, err
	}
	expires, err := parseWireTime(value.Retention.ExpiresAt)
	if err != nil {
		return Record{}, err
	}
	reviewed, err := parseOptionalWireTime(value.Review.ReviewedAt)
	if err != nil {
		return Record{}, err
	}
	validUntil, err := parseOptionalWireTime(value.Review.ValidUntil)
	if err != nil {
		return Record{}, err
	}
	return Record{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		Namespace: value.Namespace, Scope: value.Scope, Key: value.Key,
		Value: domain.ArtifactRef{Digest: value.Value.Digest, MediaType: value.Value.MediaType,
			Classification: value.Value.Classification, Length: value.Value.Length}, ValueType: value.ValueType,
		Retention: RetentionPolicy{Class: value.Retention.Class, PolicyDigest: value.Retention.PolicyDigest, ExpiresAt: expires},
		Review: Review{ReviewID: value.Review.ReviewID, ReviewerActorID: value.Review.ReviewerActorID,
			Revision: value.Review.Revision, AuthorityDigest: value.Review.AuthorityDigest,
			ReviewedAt: reviewed, ValidUntil: validUntil}, WriterActorID: value.WriterActorID,
		PolicyDigest: value.PolicyDigest, IntentDigest: value.IntentDigest, IdempotencyDigest: value.IdempotencyDigest,
		AccessDecisionDigest: value.AccessDecisionDigest, ReviewDecisionDigest: value.ReviewDecisionDigest,
		PreviousProvenanceDigest: value.PreviousProvenanceDigest, ProvenanceDigest: value.ProvenanceDigest,
		CreatedAt: created, UpdatedAt: updated, Revision: value.Revision}, nil
}

func parseWireTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(Denied, "record_time_invalid", false, nil)
	}
	return parsed, nil
}
func parseOptionalWireTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return parseWireTime(value)
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
