package evidencelifecycle

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const holdReleaseIndexSchema = "coh.evidence-hold-release-index/v1"

type holdReleaseState struct {
	SchemaVersion     string
	ContractVersion   string
	Case              domain.CaseRef
	OperationID       string
	IdempotencyDigest string
	IntentDigest      string
	Active            bool
	UpdatedAt         time.Time
	Revision          uint64
}

func (store *RepositoryStore) HasIncompleteHoldRelease(ctx context.Context,
	scope domain.CaseRef) (bool, error) {
	if err := lifecycleContextError(ctx); err != nil {
		return false, err
	}
	if !validCase(scope) {
		return false, newError(InvalidInput, "hold_release_scope_invalid", false, nil)
	}
	value, found, err := store.loadHoldRelease(ctx, scope)
	if err != nil || !found {
		return false, err
	}
	return value.Active, nil
}

func (store *RepositoryStore) loadHoldRelease(ctx context.Context,
	scope domain.CaseRef) (holdReleaseState, bool, error) {
	key := lifecycleHoldReleaseKey(scope)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return holdReleaseState{}, found, err
	}
	envelope, err := lifecycleDecodeEnvelope(metadata, key, "hold_release_index")
	if err != nil {
		return holdReleaseState{}, false, err
	}
	var value holdReleaseState
	if err = lifecycleDecode(envelope.Data, &value); err != nil || !validHoldReleaseState(value) ||
		value.Case != scope || value.Revision != metadata.Revision ||
		envelope.CreatedAt != formatTime(value.UpdatedAt) {
		return holdReleaseState{}, false, newError(Denied, "hold_release_index_invalid", false, err)
	}
	return value, true, nil
}

func (store *RepositoryStore) holdReleaseStartMutation(ctx context.Context, idempotency string,
	value Progress) (*workflowbase.Mutation, error) {
	current, found, err := store.loadHoldRelease(ctx, value.Case)
	if err != nil {
		return nil, err
	}
	if found && current.Active {
		return nil, newError(Conflict, "hold_release_already_incomplete", true, nil)
	}
	revision := uint64(1)
	if found {
		revision = current.Revision + 1
	}
	next := holdReleaseState{SchemaVersion: holdReleaseIndexSchema, ContractVersion: ContractVersion,
		Case: value.Case, OperationID: value.OperationID, IdempotencyDigest: idempotency,
		IntentDigest: value.IntentDigest, Active: true, UpdatedAt: value.UpdatedAt, Revision: revision}
	key := lifecycleHoldReleaseKey(value.Case)
	metadata, err := lifecycleMetadata(key, revision, "hold_release_index", value.UpdatedAt, next)
	if err != nil {
		return nil, err
	}
	expected := uint64(0)
	if found {
		expected = current.Revision
	}
	return &workflowbase.Mutation{Kind: workflowbase.MutationPut, Key: key,
		ExpectedRevision: expected, Record: &metadata}, nil
}

func (store *RepositoryStore) holdReleaseCompleteMutation(ctx context.Context, idempotency string,
	progress Progress) (*workflowbase.Mutation, error) {
	current, found, err := store.loadHoldRelease(ctx, progress.Case)
	if err != nil {
		return nil, err
	}
	if !found || !current.Active || current.OperationID != progress.OperationID ||
		current.IdempotencyDigest != idempotency || current.IntentDigest != progress.IntentDigest {
		return nil, newError(Denied, "hold_release_index_mismatch", false, nil)
	}
	next := current
	next.Active, next.UpdatedAt, next.Revision = false, progress.UpdatedAt, current.Revision+1
	key := lifecycleHoldReleaseKey(progress.Case)
	metadata, err := lifecycleMetadata(key, next.Revision, "hold_release_index", next.UpdatedAt, next)
	if err != nil {
		return nil, err
	}
	return &workflowbase.Mutation{Kind: workflowbase.MutationPut, Key: key,
		ExpectedRevision: current.Revision, Record: &metadata}, nil
}

func (store *RepositoryStore) verifyHoldReleaseState(ctx context.Context, scope domain.CaseRef,
	operationID, idempotency, intent string, active bool) error {
	value, found, err := store.loadHoldRelease(ctx, scope)
	if err != nil {
		return err
	}
	if !found || value.Active != active || value.OperationID != operationID ||
		value.IdempotencyDigest != idempotency || value.IntentDigest != intent {
		return newError(Denied, "hold_release_index_mismatch", false, nil)
	}
	return nil
}

func validHoldReleaseState(value holdReleaseState) bool {
	return value.SchemaVersion == holdReleaseIndexSchema && value.ContractVersion == ContractVersion &&
		validCase(value.Case) && uuidPattern.MatchString(value.OperationID) &&
		digestPattern.MatchString(value.IdempotencyDigest) && digestPattern.MatchString(value.IntentDigest) &&
		validTime(value.UpdatedAt) && validRevision(value.Revision)
}

func lifecycleHoldReleaseKey(scope domain.CaseRef) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: lifecycleRepositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-LIFECYCLE-HOLD-RELEASE-INDEX-ID-V1\x00",
			scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID)}
}
