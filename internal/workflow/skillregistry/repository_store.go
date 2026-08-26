package skillregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const recordSchema = "coh.domain/v1"

type RepositoryStore struct{ repository workflowbase.Repository }

type recordEnvelope[T any] struct {
	Schema         string  `json:"schema"`
	Kind           string  `json:"kind"`
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	TenantID       string  `json:"tenant_id"`
	CaseID         *string `json:"case_id"`
	Revision       uint64  `json:"revision"`
	CreatedAt      string  `json:"created_at"`
	Data           T       `json:"data"`
}

type versionPayload struct {
	ContractVersion string          `json:"contract_version"`
	ManifestID      string          `json:"manifest_id"`
	ManifestDigest  string          `json:"manifest_digest"`
	Envelope        json.RawMessage `json:"signed_envelope"`
}

func NewRepositoryStore(repository workflowbase.Repository) (*RepositoryStore, error) {
	if repository == nil {
		return nil, newError(InvalidInput, "repository_required", false, nil)
	}
	return &RepositoryStore{repository: repository}, nil
}

func (store *RepositoryStore) LoadState(ctx context.Context, organizationID, tenantID,
	skillName string) (State, bool, error) {
	if err := contextError(ctx); err != nil {
		return State{}, false, err
	}
	if !validUUID(organizationID) || !validUUID(tenantID) || !tokenPattern.MatchString(skillName) {
		return State{}, false, newError(InvalidInput, "state_key_invalid", false, nil)
	}
	key := catalogKey(organizationID, tenantID, stateRecordID(organizationID, tenantID, skillName))
	record, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return State{}, false, nil
		}
		return State{}, false, mapStorageError("state_load", err)
	}
	var envelope recordEnvelope[State]
	if err := decodeExact(record.Canonical, &envelope); err != nil {
		return State{}, false, newError(Denied, "state_record_invalid", false, err)
	}
	if envelope.Schema != recordSchema || envelope.Kind != "skill" || envelope.ID != key.ID ||
		envelope.OrganizationID != organizationID || envelope.TenantID != tenantID ||
		envelope.CaseID != nil || envelope.Revision != record.Revision ||
		envelope.CreatedAt != formatTime(envelope.Data.CreatedAt) ||
		envelope.Data.OrganizationID != organizationID || envelope.Data.TenantID != tenantID ||
		envelope.Data.SkillName != skillName || validateState(envelope.Data) != nil {
		return State{}, false, newError(Denied, "state_record_invalid", false, nil)
	}
	return cloneState(envelope.Data), true, nil
}

func (store *RepositoryStore) LoadVersion(ctx context.Context, organizationID, tenantID,
	digest string) (Version, bool, error) {
	if err := contextError(ctx); err != nil {
		return Version{}, false, err
	}
	if !validUUID(organizationID) || !validUUID(tenantID) || !validDigest(digest) {
		return Version{}, false, newError(InvalidInput, "version_key_invalid", false, nil)
	}
	key := catalogKey(organizationID, tenantID, versionRecordID(organizationID, tenantID, digest))
	record, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return Version{}, false, nil
		}
		return Version{}, false, mapStorageError("version_load", err)
	}
	var envelope recordEnvelope[versionPayload]
	if err := decodeExact(record.Canonical, &envelope); err != nil {
		return Version{}, false, newError(Denied, "version_record_invalid", false, err)
	}
	created, err := timeFromString(envelope.CreatedAt)
	if err != nil {
		return Version{}, false, err
	}
	version := Version{OrganizationID: organizationID, TenantID: tenantID,
		ManifestID: envelope.Data.ManifestID, ManifestDigest: envelope.Data.ManifestDigest,
		Envelope: append([]byte(nil), envelope.Data.Envelope...), CreatedAt: created}
	if envelope.Schema != recordSchema || envelope.Kind != "skill" || envelope.ID != key.ID ||
		envelope.OrganizationID != organizationID || envelope.TenantID != tenantID ||
		envelope.CaseID != nil || envelope.Revision != 1 ||
		envelope.Data.ContractVersion != ContractVersion || envelope.Data.ManifestDigest != digest ||
		validateVersion(version) != nil {
		return Version{}, false, newError(Denied, "version_record_invalid", false, nil)
	}
	return cloneVersion(version), true, nil
}

func (store *RepositoryStore) LoadCatalog(ctx context.Context, organizationID,
	tenantID string) (CatalogSnapshot, error) {
	if err := contextError(ctx); err != nil {
		return CatalogSnapshot{}, err
	}
	if !validUUID(organizationID) || !validUUID(tenantID) {
		return CatalogSnapshot{}, newError(InvalidInput, "catalog_key_invalid", false, nil)
	}
	key := catalogKey(organizationID, tenantID, catalogRecordID(organizationID, tenantID))
	record, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			empty := CatalogSnapshot{SchemaVersion: CatalogSchemaVersion, ContractVersion: ContractVersion,
				OrganizationID: organizationID, TenantID: tenantID, Entries: []PromotedSkillRef{}}
			empty.SnapshotDigest, _ = catalogSnapshotDigest(empty)
			return empty, nil
		}
		return CatalogSnapshot{}, mapStorageError("catalog_load", err)
	}
	var envelope recordEnvelope[CatalogSnapshot]
	if err := decodeExact(record.Canonical, &envelope); err != nil {
		return CatalogSnapshot{}, newError(Denied, "catalog_record_invalid", false, err)
	}
	value := envelope.Data
	if envelope.Schema != recordSchema || envelope.Kind != "skill" || envelope.ID != key.ID ||
		envelope.OrganizationID != organizationID || envelope.TenantID != tenantID ||
		envelope.CaseID != nil || envelope.Revision != record.Revision ||
		envelope.CreatedAt != formatTime(value.UpdatedAt) ||
		validateCatalogSnapshot(value) != nil || value.Revision != record.Revision {
		return CatalogSnapshot{}, newError(Denied, "catalog_record_invalid", false, nil)
	}
	return cloneCatalogSnapshot(value), nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey string, expected *State,
	next State, version *Version) (State, bool, error) {
	if err := contextError(ctx); err != nil {
		return State{}, false, err
	}
	if !validOpaque(idempotencyKey, 1, 256) || validateState(next) != nil {
		return State{}, false, newError(InvalidInput, "commit_invalid", false, nil)
	}
	if err := validateExpectedTransition(expected, next); err != nil {
		return State{}, false, err
	}
	stateRecord, err := encodeStateRecord(next)
	if err != nil {
		return State{}, false, err
	}
	expectedRevision := uint64(0)
	if expected != nil {
		expectedRevision = expected.Revision
	}
	catalog, err := store.nextCatalog(ctx, next)
	if err != nil {
		return State{}, false, err
	}
	catalogRecord, err := encodeCatalogRecord(catalog)
	if err != nil {
		return State{}, false, err
	}
	mutations := []workflowbase.Mutation{{
		Kind: workflowbase.MutationPut, Key: stateRecord.Key,
		ExpectedRevision: expectedRevision, Record: &stateRecord,
	}, {
		Kind: workflowbase.MutationPut, Key: catalogRecord.Key,
		ExpectedRevision: catalog.Revision - 1, Record: &catalogRecord,
	}}
	if version != nil {
		if validateVersion(*version) != nil || version.OrganizationID != next.OrganizationID ||
			version.TenantID != next.TenantID || version.ManifestDigest != next.CurrentManifestDigest {
			return State{}, false, newError(InvalidInput, "version_commit_invalid", false, nil)
		}
		versionRecord, encodeErr := encodeVersionRecord(*version)
		if encodeErr != nil {
			return State{}, false, encodeErr
		}
		mutations = append(mutations, workflowbase.Mutation{Kind: workflowbase.MutationPut,
			Key: versionRecord.Key, ExpectedRevision: 0, Record: &versionRecord})
	}
	sort.Slice(mutations, func(left, right int) bool {
		return mutationKey(mutations[left].Key) < mutationKey(mutations[right].Key)
	})
	transaction := workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: idempotencyKey, Mutations: mutations}
	result, err := store.repository.Transact(ctx, transaction)
	if err != nil {
		return State{}, false, mapStorageError("commit", err)
	}
	if result.Replayed {
		stored, found, loadErr := store.LoadState(ctx, next.OrganizationID, next.TenantID, next.SkillName)
		if loadErr != nil {
			return State{}, false, loadErr
		}
		if !found {
			return State{}, false, newError(Denied, "replayed_state_missing", false, nil)
		}
		return stored, true, nil
	}
	return cloneState(next), false, nil
}

func (store *RepositoryStore) nextCatalog(ctx context.Context, next State) (CatalogSnapshot, error) {
	current, err := store.LoadCatalog(ctx, next.OrganizationID, next.TenantID)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	entries := append([]PromotedSkillRef(nil), current.Entries...)
	index := sort.Search(len(entries), func(index int) bool { return entries[index].SkillName >= next.SkillName })
	if index < len(entries) && entries[index].SkillName == next.SkillName {
		entries = append(entries[:index], entries[index+1:]...)
	}
	if next.Status == Promoted {
		entry := PromotedSkillRef{SkillName: next.SkillName, ManifestDigest: next.CurrentManifestDigest,
			StateRevision: next.Revision, ProvenanceDigest: next.ProvenanceDigest}
		entries = append(entries, PromotedSkillRef{})
		copy(entries[index+1:], entries[index:])
		entries[index] = entry
	}
	if len(entries) > MaximumCatalogEntries {
		return CatalogSnapshot{}, newError(Denied, "catalog_capacity_exceeded", false, nil)
	}
	value := CatalogSnapshot{SchemaVersion: CatalogSchemaVersion, ContractVersion: ContractVersion,
		OrganizationID: next.OrganizationID, TenantID: next.TenantID, Entries: entries,
		UpdatedAt: next.UpdatedAt, Revision: current.Revision + 1}
	value.SnapshotDigest, err = catalogSnapshotDigest(value)
	if err != nil || validateCatalogSnapshot(value) != nil {
		return CatalogSnapshot{}, newError(Denied, "catalog_next_invalid", false, err)
	}
	return value, nil
}

func encodeStateRecord(value State) (workflowbase.MetadataRecord, error) {
	id := stateRecordID(value.OrganizationID, value.TenantID, value.SkillName)
	envelope := recordEnvelope[State]{Schema: recordSchema, Kind: "skill", ID: id,
		OrganizationID: value.OrganizationID, TenantID: value.TenantID, Revision: value.Revision,
		CreatedAt: formatTime(value.CreatedAt), Data: value}
	return metadataRecord(catalogKey(value.OrganizationID, value.TenantID, id), value.Revision, envelope)
}

func encodeVersionRecord(value Version) (workflowbase.MetadataRecord, error) {
	id := versionRecordID(value.OrganizationID, value.TenantID, value.ManifestDigest)
	payload := versionPayload{ContractVersion: ContractVersion, ManifestID: value.ManifestID,
		ManifestDigest: value.ManifestDigest, Envelope: append(json.RawMessage(nil), value.Envelope...)}
	envelope := recordEnvelope[versionPayload]{Schema: recordSchema, Kind: "skill", ID: id,
		OrganizationID: value.OrganizationID, TenantID: value.TenantID, Revision: 1,
		CreatedAt: formatTime(value.CreatedAt), Data: payload}
	return metadataRecord(catalogKey(value.OrganizationID, value.TenantID, id), 1, envelope)
}

func encodeCatalogRecord(value CatalogSnapshot) (workflowbase.MetadataRecord, error) {
	if err := validateCatalogSnapshot(value); err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	id := catalogRecordID(value.OrganizationID, value.TenantID)
	envelope := recordEnvelope[CatalogSnapshot]{Schema: recordSchema, Kind: "skill", ID: id,
		OrganizationID: value.OrganizationID, TenantID: value.TenantID, Revision: value.Revision,
		CreatedAt: formatTime(value.UpdatedAt), Data: value}
	return metadataRecord(catalogKey(value.OrganizationID, value.TenantID, id), value.Revision, envelope)
}

func metadataRecord(key workflowbase.RecordKey, revision uint64, value any) (workflowbase.MetadataRecord, error) {
	canonical, err := canonicalValue(value)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: recordSchema, Revision: revision,
		Canonical: canonical, Digest: digestBytes(canonical)}, nil
}

func validateVersion(value Version) error {
	if !validUUID(value.OrganizationID) || !validUUID(value.TenantID) || !validUUID(value.ManifestID) ||
		!validDigest(value.ManifestDigest) || len(value.Envelope) == 0 || len(value.Envelope) > MaximumInputBytes ||
		!validTime(value.CreatedAt) {
		return newError(Denied, "version_invalid", false, nil)
	}
	decoded, err := decodeEnvelope(context.Background(), value.Envelope)
	if err != nil || decoded.envelope.ManifestDigest != value.ManifestDigest ||
		decoded.envelope.Manifest.ManifestID != value.ManifestID ||
		!bytes.Equal(decoded.canonical, value.Envelope) {
		return newError(Denied, "version_envelope_invalid", false, err)
	}
	return nil
}

func validateExpectedTransition(expected *State, next State) error {
	if expected == nil {
		if next.Revision != 1 || next.PreviousProvenanceDigest != "" {
			return newError(Conflict, "initial_revision_invalid", false, nil)
		}
		return nil
	}
	if validateState(*expected) != nil || expected.OrganizationID != next.OrganizationID ||
		expected.TenantID != next.TenantID || expected.SkillName != next.SkillName ||
		next.Revision != expected.Revision+1 || next.PreviousProvenanceDigest != expected.ProvenanceDigest ||
		next.CreatedAt != expected.CreatedAt || next.UpdatedAt.Before(expected.UpdatedAt) {
		return newError(Conflict, "state_transition_invalid", false, nil)
	}
	return nil
}

func catalogKey(organizationID, tenantID, id string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: domain.CaseRef{OrganizationID: organizationID, TenantID: tenantID},
		Kind: "skill", ID: id}
}

func stateRecordID(organizationID, tenantID, skillName string) string {
	return deterministicUUID("COH-SKILL-REGISTRY-STATE-ID-V1\x00", organizationID+"\x00"+tenantID+"\x00"+skillName)
}

func versionRecordID(organizationID, tenantID, digest string) string {
	return deterministicUUID("COH-SKILL-REGISTRY-VERSION-ID-V1\x00", organizationID+"\x00"+tenantID+"\x00"+digest)
}

func catalogRecordID(organizationID, tenantID string) string {
	return deterministicUUID("COH-SKILL-REGISTRY-CATALOG-ID-V1\x00", organizationID+"\x00"+tenantID)
}

func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func mutationKey(key workflowbase.RecordKey) string {
	return key.Case.OrganizationID + "/" + key.Case.TenantID + "/" + key.Kind + "/" + key.ID
}

func timeFromString(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		return time.Time{}, newError(Denied, "record_timestamp_invalid", false, err)
	}
	return parsed.UTC(), nil
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
var _ Catalog = (*RepositoryStore)(nil)
