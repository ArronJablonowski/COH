package lifecycledisposition

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func (adapter *Adapter) loadOperation(ctx context.Context, scope domain.CaseRef,
	operationID string) (storedOperation, bool, error) {
	return adapter.load(ctx, operationKey(scope, operationID), "operation", scope, operationID, "")
}

func (adapter *Adapter) loadDigest(ctx context.Context, scope domain.CaseRef,
	attestationDigest string) (storedOperation, bool, error) {
	return adapter.load(ctx, digestKey(scope, attestationDigest), "attestation", scope, "", attestationDigest)
}

func (adapter *Adapter) load(ctx context.Context, key workflowbase.RecordKey, entryType string,
	scope domain.CaseRef, operationID, attestationDigest string) (storedOperation, bool, error) {
	metadata, err := adapter.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return storedOperation{}, false, nil
		}
		return storedOperation{}, false, storageError("disposition_load", err)
	}
	var outer envelope
	if err = decodeCanonical(metadata.Canonical, &outer); err != nil || outer.Schema != repositorySchema ||
		outer.Kind != repositoryKind || outer.ID != key.ID || outer.OrganizationID != scope.OrganizationID ||
		outer.TenantID != scope.TenantID || outer.CaseID != scope.CaseID || outer.Revision != metadata.Revision ||
		outer.EntryType != entryType || metadata.Key != key || metadata.Schema != repositorySchema ||
		metadata.Digest != digest("", metadata.Canonical) {
		return storedOperation{}, false, lifecycleError(evidencelifecycle.Denied,
			"disposition_envelope_invalid", false)
	}
	var value storedOperation
	if err = decodeCanonical(outer.Data, &value); err != nil || !validateStored(value) || value.Case != scope ||
		operationID != "" && value.OperationID != operationID || attestationDigest != "" &&
		(value.Attestation == nil || value.Attestation.AttestationDigest != attestationDigest) {
		return storedOperation{}, false, lifecycleError(evidencelifecycle.Denied,
			"disposition_record_invalid", false)
	}
	expectedRevision := uint64(1)
	if entryType == "operation" && value.Attestation != nil {
		expectedRevision = 2
	}
	if metadata.Revision != expectedRevision || entryType == "attestation" && value.Attestation == nil {
		return storedOperation{}, false, lifecycleError(evidencelifecycle.Denied,
			"disposition_revision_invalid", false)
	}
	return value, true, nil
}

func (adapter *Adapter) savePlan(ctx context.Context, value storedOperation) (storedOperation, error) {
	record, err := metadata(operationKey(value.Case, value.OperationID), "operation", 1, value)
	if err != nil {
		return storedOperation{}, err
	}
	_, err = adapter.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: digest("COH-LIFECYCLE-DISPOSITION-PLAN-COMMIT-V1\x00", []byte(value.RequestDigest)),
		Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut, Key: record.Key,
			ExpectedRevision: 0, Record: &record}}})
	if err == nil {
		return value, nil
	}
	recovered, found, recoverErr := adapter.loadOperation(ctx, value.Case, value.OperationID)
	if recoverErr == nil && found && recovered.RequestDigest == value.RequestDigest {
		return recovered, nil
	}
	return storedOperation{}, storageError("disposition_plan_commit", err)
}

func (adapter *Adapter) saveAttestation(ctx context.Context,
	value storedOperation) (storedOperation, error) {
	operationRecord, err := metadata(operationKey(value.Case, value.OperationID), "operation", 2, value)
	if err != nil {
		return storedOperation{}, err
	}
	attestationRecord, err := metadata(digestKey(value.Case, value.Attestation.AttestationDigest),
		"attestation", 1, value)
	if err != nil {
		return storedOperation{}, err
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: operationRecord.Key, ExpectedRevision: 1, Record: &operationRecord},
		{Kind: workflowbase.MutationPut, Key: attestationRecord.Key, ExpectedRevision: 0, Record: &attestationRecord},
	}
	sort.Slice(mutations, func(left, right int) bool { return mutations[left].Key.ID < mutations[right].Key.ID })
	_, err = adapter.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: digest("COH-LIFECYCLE-DISPOSITION-ATTESTATION-COMMIT-V1\x00",
			[]byte(value.RequestDigest)), Mutations: mutations})
	if err == nil {
		return value, nil
	}
	recovered, found, recoverErr := adapter.loadOperation(ctx, value.Case, value.OperationID)
	if recoverErr == nil && found && recovered.RequestDigest == value.RequestDigest && recovered.Attestation != nil &&
		recovered.Attestation.AttestationDigest == value.Attestation.AttestationDigest {
		return recovered, nil
	}
	return storedOperation{}, storageError("disposition_attestation_commit", err)
}

func metadata(key workflowbase.RecordKey, entryType string, revision uint64,
	value storedOperation) (workflowbase.MetadataRecord, error) {
	data, err := canonicalValue(value)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	outer := envelope{Schema: repositorySchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: key.Case.CaseID,
		Revision: revision, EntryType: entryType, Data: json.RawMessage(data)}
	canonical, err := canonicalValue(outer)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositorySchema, Revision: revision,
		Canonical: canonical, Digest: digest("", canonical)}, nil
}

func operationKey(scope domain.CaseRef, operationID string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind, ID: operationID}
}

func digestKey(scope domain.CaseRef, value string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-LIFECYCLE-DISPOSITION-ATTESTATION-ID-V1\x00",
			scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+value)}
}

func storageError(operation string, err error) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return lifecycleError(evidencelifecycle.InvalidInput, operation+"_invalid", false)
	case workflowbase.StorageDenied:
		return lifecycleError(evidencelifecycle.Denied, operation+"_denied", false)
	case workflowbase.StorageNotFound:
		return lifecycleError(evidencelifecycle.NotFound, operation+"_not_found", false)
	case workflowbase.StorageConflict:
		return lifecycleError(evidencelifecycle.Conflict, operation+"_conflict", true)
	case workflowbase.StorageCanceled:
		return lifecycleError(evidencelifecycle.Canceled, operation+"_canceled", false)
	case workflowbase.StorageTimeout:
		return lifecycleError(evidencelifecycle.Timeout, operation+"_timeout", true)
	default:
		return lifecycleError(evidencelifecycle.Unavailable, operation+"_unavailable", true)
	}
}
