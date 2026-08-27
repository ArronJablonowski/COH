package lifecyclecustody

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func (adapter *Adapter) loadRequest(ctx context.Context, scope domain.CaseRef,
	requestDigest string) (storedSet, bool, error) {
	return adapter.loadStoredSet(ctx, requestKey(scope, requestDigest), "request", scope, requestDigest, "")
}

func (adapter *Adapter) loadDigest(ctx context.Context, scope domain.CaseRef,
	setDigest string) (storedSet, bool, error) {
	return adapter.loadStoredSet(ctx, setKey(scope, setDigest), "set", scope, "", setDigest)
}

func (adapter *Adapter) loadStoredSet(ctx context.Context, key workflowbase.RecordKey, entryType string,
	scope domain.CaseRef, requestDigest, setDigest string) (storedSet, bool, error) {
	if err := ctx.Err(); err != nil {
		return storedSet{}, false, contextError(err)
	}
	metadata, err := adapter.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return storedSet{}, false, nil
		}
		return storedSet{}, false, storageError("custody_set_load", err)
	}
	var outer envelope
	if err = decodeCanonical(metadata.Canonical, &outer); err != nil || outer.Schema != repositorySchema ||
		outer.Kind != repositoryKind || outer.ID != key.ID || outer.OrganizationID != scope.OrganizationID ||
		outer.TenantID != scope.TenantID || outer.CaseID != scope.CaseID || outer.EntryType != entryType ||
		outer.Revision != 1 ||
		metadata.Key != key || metadata.Schema != repositorySchema || metadata.Revision != 1 ||
		metadata.Digest != digest("", metadata.Canonical) {
		return storedSet{}, false, lifecycleError(evidencelifecycle.Denied, "custody_set_envelope_invalid", false)
	}
	var wire setWire
	if err = decodeCanonical(outer.Data, &wire); err != nil {
		return storedSet{}, false, err
	}
	value, err := setFromWire(wire)
	if err != nil || value.Case != scope || requestDigest != "" && value.RequestDigest != requestDigest ||
		setDigest != "" && value.SetDigest != setDigest {
		return storedSet{}, false, lifecycleError(evidencelifecycle.Denied, "custody_set_binding_invalid", false)
	}
	return value, true, nil
}

func (adapter *Adapter) commitSet(ctx context.Context, value storedSet) error {
	requestRecord, err := setMetadata(requestKey(value.Case, value.RequestDigest), "request", value)
	if err != nil {
		return err
	}
	setRecord, err := setMetadata(setKey(value.Case, value.SetDigest), "set", value)
	if err != nil {
		return err
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: requestRecord.Key, ExpectedRevision: 0, Record: &requestRecord},
		{Kind: workflowbase.MutationPut, Key: setRecord.Key, ExpectedRevision: 0, Record: &setRecord},
	}
	sort.Slice(mutations, func(left, right int) bool { return mutations[left].Key.ID < mutations[right].Key.ID })
	_, err = adapter.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: digest("COH-LIFECYCLE-CUSTODY-SET-COMMIT-V1\x00", []byte(value.Case.OrganizationID+"\x00"+
			value.Case.TenantID+"\x00"+value.Case.CaseID+"\x00"+value.RequestDigest)), Mutations: mutations})
	if err == nil {
		return nil
	}
	recovered, found, recoverErr := adapter.loadStoredSet(ctx, requestRecord.Key, "request",
		value.Case, value.RequestDigest, "")
	if recoverErr == nil && found && recovered.SetDigest == value.SetDigest {
		return nil
	}
	return storageError("custody_set_commit", err)
}

func setMetadata(key workflowbase.RecordKey, entryType string, value storedSet) (workflowbase.MetadataRecord, error) {
	data, err := canonicalValue(setToWire(value))
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	outer := envelope{Schema: repositorySchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: key.Case.CaseID,
		Revision: 1, EntryType: entryType, Data: json.RawMessage(data)}
	canonical, err := canonicalValue(outer)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositorySchema, Revision: 1,
		Canonical: canonical, Digest: digest("", canonical)}, nil
}

func requestKey(scope domain.CaseRef, requestDigest string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-LIFECYCLE-CUSTODY-REQUEST-ID-V1\x00", scope.OrganizationID+"\x00"+
			scope.TenantID+"\x00"+scope.CaseID+"\x00"+requestDigest)}
}

func setKey(scope domain.CaseRef, setDigest string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-LIFECYCLE-CUSTODY-SET-ID-V1\x00", scope.OrganizationID+"\x00"+
			scope.TenantID+"\x00"+scope.CaseID+"\x00"+setDigest)}
}

func contextError(err error) error {
	if err == context.DeadlineExceeded {
		return lifecycleError(evidencelifecycle.Timeout, "custody_request_timeout", false)
	}
	return lifecycleError(evidencelifecycle.Canceled, "custody_request_canceled", false)
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
