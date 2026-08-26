package retrievalguard

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

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
	return &RepositoryStore{repository}, nil
}

func (store *RepositoryStore) Load(ctx context.Context, scope domain.CaseRef, taskID, idempotency string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validCase(scope) || !uuidPattern.MatchString(taskID) || !digestPattern.MatchString(idempotency) {
		return Record{}, false, newError(InvalidInput, "record_key_invalid", false, nil)
	}
	key := retrievalRecordKey(scope, taskID, idempotency)
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return Record{}, false, nil
		}
		return Record{}, false, mapStorageError("record_load", err)
	}
	var envelope repositoryEnvelope
	if err = decodeRepositoryRecord(metadata.Canonical, &envelope); err != nil {
		return Record{}, false, err
	}
	value, err := recordFromWire(envelope.Data)
	if err != nil {
		return Record{}, false, err
	}
	if envelope.Schema != repositoryRecordSchema || envelope.Kind != "retrieval" || envelope.ID != key.ID || envelope.OrganizationID != scope.OrganizationID || envelope.TenantID != scope.TenantID ||
		envelope.CaseID == nil || *envelope.CaseID != scope.CaseID || envelope.Revision != 1 || metadata.Revision != 1 || envelope.CreatedAt != formatTime(value.CreatedAt) ||
		value.Request.Case != scope || value.Request.TaskID != taskID || value.IdempotencyDigest != idempotency || validateRecord(value) != nil {
		return Record{}, false, newError(Denied, "record_envelope_invalid", false, nil)
	}
	return cloneRecord(value), true, nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey string, value Record) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validOpaque(idempotencyKey, 1, 256) || validateRecord(value) != nil {
		return Record{}, false, newError(InvalidInput, "record_commit_invalid", false, nil)
	}
	if recovered, found, err := store.Load(ctx, value.Request.Case, value.Request.TaskID, value.IdempotencyDigest); err != nil {
		return Record{}, false, err
	} else if found {
		if recovered.IntentDigest != value.IntentDigest {
			return Record{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return recovered, true, nil
	}
	key := retrievalRecordKey(value.Request.Case, value.Request.TaskID, value.IdempotencyDigest)
	caseID := value.Request.Case.CaseID
	envelope := repositoryEnvelope{Schema: repositoryRecordSchema, Kind: "retrieval", ID: key.ID, OrganizationID: value.Request.Case.OrganizationID, TenantID: value.Request.Case.TenantID, CaseID: &caseID, Revision: 1, CreatedAt: formatTime(value.CreatedAt), Data: recordToWire(value)}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return Record{}, false, err
	}
	metadata := workflowbase.MetadataRecord{Key: key, Schema: repositoryRecordSchema, Revision: 1, Canonical: canonical, Digest: rawDigest(canonical)}
	transactionKey := digest("COH-RETRIEVAL-TRANSACTION-V1\x00", []byte(value.Request.Case.OrganizationID+"\x00"+value.Request.Case.TenantID+"\x00"+value.Request.Case.CaseID+"\x00"+value.Request.TaskID+"\x00"+value.IdempotencyDigest))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion, IdempotencyKey: transactionKey, Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut, Key: key, ExpectedRevision: 0, Record: &metadata}}})
	if err != nil {
		return Record{}, false, mapStorageError("record_commit", err)
	}
	if result.Replayed {
		recovered, found, loadErr := store.Load(ctx, value.Request.Case, value.Request.TaskID, value.IdempotencyDigest)
		if loadErr != nil {
			return Record{}, false, loadErr
		}
		if !found || recovered.IntentDigest != value.IntentDigest {
			return Record{}, false, newError(Denied, "replayed_record_invalid", false, nil)
		}
		return recovered, true, nil
	}
	return cloneRecord(value), false, nil
}

func retrievalRecordKey(scope domain.CaseRef, taskID, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: "retrieval", ID: deterministicUUID("COH-RETRIEVAL-RECORD-ID-V1\x00", scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+taskID+"\x00"+idempotency)}
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
	deadline, err := parseWireTime(value.Request.Deadline)
	if err != nil {
		return Record{}, err
	}
	created, err := parseWireTime(value.CreatedAt)
	if err != nil {
		return Record{}, err
	}
	request := Request{SchemaVersion: value.Request.SchemaVersion, ContractVersion: value.Request.ContractVersion, RequestID: value.Request.RequestID, IdempotencyKey: value.Request.IdempotencyKey,
		Case: domain.CaseRef{OrganizationID: value.Request.Case.OrganizationID, TenantID: value.Request.Case.TenantID, CaseID: value.Request.Case.CaseID}, TaskID: value.Request.TaskID, ActorID: value.Request.ActorID, ActorRevision: value.Request.ActorRevision,
		Source: Source{Kind: value.Request.Source.Kind, Artifact: artifactFromWire(value.Request.Source.Artifact), Trust: value.Request.Source.Trust, ProvenanceDigest: value.Request.Source.ProvenanceDigest},
		Profile: InspectionProfile{Name: value.Request.Profile.Name, Revision: value.Request.Profile.Revision, MaximumBytes: value.Request.Profile.MaximumBytes, AllowedMediaTypes: append([]string{}, value.Request.Profile.AllowedMediaTypes...),
			DenyActiveFormats: value.Request.Profile.DenyActiveFormats, RedactSecrets: value.Request.Profile.RedactSecrets, NeutralizeDirectives: value.Request.Profile.NeutralizeDirectives, ProfileDigest: value.Request.Profile.ProfileDigest}, PolicyDigest: value.Request.PolicyDigest, Deadline: deadline}
	inspection := InspectionResult{SourceDigest: value.Inspection.SourceDigest, SourceProvenanceDigest: value.Inspection.SourceProvenanceDigest, Sanitized: artifactFromWire(value.Inspection.Sanitized), Trust: value.Inspection.Trust,
		Findings: append([]Finding{}, value.Inspection.Findings...), FindingsDigest: value.Inspection.FindingsDigest, RedactionCount: value.Inspection.RedactionCount, Complete: value.Inspection.Complete, InspectorDigest: value.Inspection.InspectorDigest}
	return Record{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion, Request: request, IntentDigest: value.IntentDigest, IdempotencyDigest: value.IdempotencyDigest,
		DecisionDigest: value.DecisionDigest, RevocationDigest: value.RevocationDigest, Inspection: inspection, AuditEventDigest: value.AuditEventDigest, PreviousProvenanceDigest: value.PreviousProvenanceDigest,
		ProvenanceDigest: value.ProvenanceDigest, CreatedAt: created, Revision: value.Revision}, nil
}

func artifactFromWire(value artifactWire) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: value.Digest, MediaType: value.MediaType, Classification: value.Classification, Length: value.Length}
}
func parseWireTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(Denied, "record_time_invalid", false, nil)
	}
	return parsed, nil
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
