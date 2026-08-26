package subagentdag

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	repositoryRecordSchema = "coh.domain/v1"
	repositoryRecordKind   = "subagent_dag"
	maximumRecordBytes     = 16 << 20
)

type RepositoryStore struct{ repository workflowbase.MetadataStore }

type repositoryEnvelope struct {
	Schema         string    `json:"schema"`
	Kind           string    `json:"kind"`
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	TenantID       string    `json:"tenant_id"`
	CaseID         string    `json:"case_id"`
	Revision       uint64    `json:"revision"`
	CreatedAt      string    `json:"created_at"`
	Data           graphWire `json:"data"`
}

func NewRepositoryStore(repository workflowbase.MetadataStore) (*RepositoryStore, error) {
	if repository == nil {
		return nil, newError(InvalidInput, "repository_required", false, nil)
	}
	return &RepositoryStore{repository: repository}, nil
}

func (store *RepositoryStore) Load(ctx context.Context, scope domain.CaseRef, graphID string) (Graph, bool, error) {
	if err := contextError(ctx); err != nil {
		return Graph{}, false, err
	}
	if !validCase(scope) || !uuidPattern.MatchString(graphID) {
		return Graph{}, false, newError(InvalidInput, "graph_key_invalid", false, nil)
	}
	key := graphRecordKey(scope, graphID)
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return Graph{}, false, nil
		}
		return Graph{}, false, mapRepositoryError("graph_load", err)
	}
	var envelope repositoryEnvelope
	if err = decodeRepositoryEnvelope(metadata.Canonical, &envelope); err != nil {
		return Graph{}, false, err
	}
	graph, err := graphFromWire(envelope.Data)
	if err != nil {
		return Graph{}, false, err
	}
	if envelope.Schema != repositoryRecordSchema || envelope.Kind != repositoryRecordKind ||
		envelope.ID != graphID || envelope.OrganizationID != scope.OrganizationID ||
		envelope.TenantID != scope.TenantID || envelope.CaseID != scope.CaseID ||
		envelope.Revision != graph.Revision || metadata.Revision != graph.Revision ||
		envelope.CreatedAt != formatTime(graph.CreatedAt) || graph.GraphID != graphID ||
		graph.Case != scope || validateGraph(graph) != nil {
		return Graph{}, false, newError(Denied, "graph_envelope_invalid", false, nil)
	}
	return cloneGraph(graph), true, nil
}

func (store *RepositoryStore) Begin(ctx context.Context, idempotencyKey string, next Graph) (Graph, bool, error) {
	if err := contextError(ctx); err != nil {
		return Graph{}, false, err
	}
	if !validOpaque(idempotencyKey) || validateGraph(next) != nil || next.Revision != 1 ||
		next.PreviousProvenanceDigest != "" {
		return Graph{}, false, newError(InvalidInput, "graph_begin_invalid", false, nil)
	}
	if current, found, err := store.Load(ctx, next.Case, next.GraphID); err != nil {
		return Graph{}, false, err
	} else if found {
		if !containsReceipt(current, next.Receipts[0]) {
			return Graph{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return current, true, nil
	}
	return store.transact(ctx, idempotencyKey, Graph{}, next)
}

func (store *RepositoryStore) Save(ctx context.Context, idempotencyKey string, prior, next Graph) (Graph, bool, error) {
	if err := contextError(ctx); err != nil {
		return Graph{}, false, err
	}
	if !validOpaque(idempotencyKey) || validateGraph(prior) != nil || validateGraph(next) != nil {
		return Graph{}, false, newError(InvalidInput, "graph_save_invalid", false, nil)
	}
	if err := validateGraphTransition(prior, next); err != nil {
		return Graph{}, false, err
	}
	current, found, err := store.Load(ctx, prior.Case, prior.GraphID)
	if err != nil {
		return Graph{}, false, err
	}
	if !found {
		return Graph{}, false, newError(NotFound, "graph_not_found", false, nil)
	}
	if current.Revision == next.Revision && current.ProvenanceDigest == next.ProvenanceDigest {
		return current, true, nil
	}
	if current.Revision != prior.Revision || current.ProvenanceDigest != prior.ProvenanceDigest {
		return Graph{}, false, newError(Conflict, "graph_revision_conflict", true, nil)
	}
	return store.transact(ctx, idempotencyKey, prior, next)
}

func (store *RepositoryStore) transact(ctx context.Context, idempotencyKey string, prior, next Graph) (Graph, bool, error) {
	metadata, err := encodeRepositoryGraph(next)
	if err != nil {
		return Graph{}, false, err
	}
	key := metadata.Key
	transactionKey := digest("COH-SUBAGENT-DAG-TRANSACTION-V1\x00",
		[]byte(next.Case.OrganizationID+"\x00"+next.Case.TenantID+"\x00"+next.Case.CaseID+"\x00"+
			next.GraphID+"\x00"+idempotencyKey))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{
		ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey:  transactionKey,
		Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut, Key: key,
			ExpectedRevision: prior.Revision, Record: &metadata}},
	})
	if err != nil {
		return Graph{}, false, mapRepositoryError("graph_commit", err)
	}
	if result.Replayed {
		stored, found, loadErr := store.Load(ctx, next.Case, next.GraphID)
		if loadErr != nil {
			return Graph{}, false, loadErr
		}
		if !found || stored.Revision != next.Revision || stored.ProvenanceDigest != next.ProvenanceDigest {
			return Graph{}, false, newError(Denied, "replayed_graph_invalid", false, nil)
		}
		return stored, true, nil
	}
	return cloneGraph(next), false, nil
}

func encodeRepositoryGraph(graph Graph) (workflowbase.MetadataRecord, error) {
	key := graphRecordKey(graph.Case, graph.GraphID)
	envelope := repositoryEnvelope{Schema: repositoryRecordSchema, Kind: repositoryRecordKind,
		ID: graph.GraphID, OrganizationID: graph.Case.OrganizationID, TenantID: graph.Case.TenantID,
		CaseID: graph.Case.CaseID, Revision: graph.Revision, CreatedAt: formatTime(graph.CreatedAt),
		Data: graphToWire(graph)}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	if len(canonical) > maximumRecordBytes {
		return workflowbase.MetadataRecord{}, newError(InvalidInput, "graph_record_too_large", false, nil)
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositoryRecordSchema,
		Revision: graph.Revision, Canonical: canonical, Digest: rawDigest(canonical)}, nil
}

func graphRecordKey(scope domain.CaseRef, graphID string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryRecordKind, ID: graphID}
}

func sameGraphIdentity(left, right Graph) bool {
	return left.SchemaVersion == right.SchemaVersion && left.ContractVersion == right.ContractVersion &&
		left.GraphID == right.GraphID && left.RunID == right.RunID && left.Case == right.Case &&
		left.ActorID == right.ActorID && left.ActorRevision == right.ActorRevision &&
		left.PolicyDigest == right.PolicyDigest && left.ProviderRoute == right.ProviderRoute &&
		left.Limits == right.Limits && left.BudgetPlanDigest == right.BudgetPlanDigest &&
		left.CreatedAt.Equal(right.CreatedAt) && left.Deadline.Equal(right.Deadline)
}

func containsReceipt(graph Graph, wanted Receipt) bool {
	for _, receipt := range graph.Receipts {
		if receipt.IdempotencyDigest == wanted.IdempotencyDigest {
			return receipt.Operation == wanted.Operation && receipt.IntentDigest == wanted.IntentDigest &&
				receipt.TaskID == wanted.TaskID
		}
	}
	return false
}

func decodeRepositoryEnvelope(data []byte, output any) error {
	if len(data) == 0 || len(data) > maximumRecordBytes || !json.Valid(data) {
		return newError(Denied, "graph_encoding_invalid", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "graph_encoding_invalid", false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "graph_encoding_invalid", false, nil)
	}
	canonical, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return newError(Denied, "graph_noncanonical", false, err)
	}
	return nil
}

func graphFromWire(value graphWire) (Graph, error) {
	createdAt, err := parseRepositoryTime(value.CreatedAt)
	if err != nil {
		return Graph{}, err
	}
	deadline, err := parseRepositoryTime(value.Deadline)
	if err != nil {
		return Graph{}, err
	}
	updatedAt, err := parseRepositoryTime(value.UpdatedAt)
	if err != nil {
		return Graph{}, err
	}
	tasks := make([]Task, len(value.Tasks))
	for index := range value.Tasks {
		tasks[index], err = taskFromWire(value.Tasks[index])
		if err != nil {
			return Graph{}, err
		}
	}
	cancellations := make([]CancellationRecord, len(value.Cancellations))
	for index, cancellation := range value.Cancellations {
		cancellations[index] = CancellationRecord{CancellationID: cancellation.CancellationID,
			RootTaskID: cancellation.RootTaskID, ReasonDigest: cancellation.ReasonDigest,
			TargetTaskIDs:   append([]string{}, cancellation.TargetTaskIDs...),
			Acknowledgments: append([]CancellationAck{}, cancellation.Acknowledgments...), Status: cancellation.Status,
			IntentDigest: cancellation.IntentDigest, IdempotencyDigest: cancellation.IdempotencyDigest,
			Revision: cancellation.Revision}
		cancellations[index].CreatedAt, err = parseRepositoryTime(cancellation.CreatedAt)
		if err != nil {
			return Graph{}, err
		}
		cancellations[index].UpdatedAt, err = parseRepositoryTime(cancellation.UpdatedAt)
		if err != nil {
			return Graph{}, err
		}
	}
	return Graph{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		GraphID: value.GraphID, RunID: value.RunID, Case: caseFromWire(value.Case), ActorID: value.ActorID,
		ActorRevision: value.ActorRevision, PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute,
		Limits: value.Limits, BudgetPlanDigest: value.BudgetPlanDigest, Tasks: tasks,
		Edges: append([]Edge{}, value.Edges...), Receipts: append([]Receipt{}, value.Receipts...),
		Cancellations: cancellations, PreviousProvenanceDigest: value.PreviousProvenanceDigest,
		ProvenanceDigest: value.ProvenanceDigest, CreatedAt: createdAt, Deadline: deadline,
		UpdatedAt: updatedAt, Revision: value.Revision}, nil
}

func taskFromWire(value taskWire) (Task, error) {
	createdAt, err := parseRepositoryTime(value.CreatedAt)
	if err != nil {
		return Task{}, err
	}
	deadline, err := parseRepositoryTime(value.Deadline)
	if err != nil {
		return Task{}, err
	}
	updatedAt, err := parseRepositoryTime(value.UpdatedAt)
	if err != nil {
		return Task{}, err
	}
	return Task{TaskID: value.TaskID, ParentTaskIDs: append([]string{}, value.ParentTaskIDs...),
		Role: value.Role, Status: value.Status, Depth: value.Depth, InputRefs: append([]string{}, value.InputRefs...),
		AssignmentDigest: value.AssignmentDigest, BudgetReservationDigest: value.BudgetReservationDigest,
		BudgetSettlementDigest: value.BudgetSettlementDigest, Result: resultPointerFromWire(value.Result),
		Cancellation: cloneCancellation(value.Cancellation), PreviousProvenanceDigest: value.PreviousProvenanceDigest,
		ProvenanceDigest: value.ProvenanceDigest, CreatedAt: createdAt, Deadline: deadline,
		UpdatedAt: updatedAt, Revision: value.Revision}, nil
}

func parseRepositoryTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(Denied, "graph_time_invalid", false, nil)
	}
	return parsed, nil
}

func mapRepositoryError(operation string, err error) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return newError(InvalidInput, operation+"_invalid", false, err)
	case workflowbase.StorageDenied:
		return newError(Denied, operation+"_denied", false, err)
	case workflowbase.StorageNotFound:
		return newError(NotFound, operation+"_not_found", false, err)
	case workflowbase.StorageConflict:
		return newError(Conflict, operation+"_conflict", true, err)
	case workflowbase.StorageCanceled:
		return newError(Canceled, operation+"_canceled", false, err)
	case workflowbase.StorageTimeout:
		return newError(Timeout, operation+"_timeout", true, err)
	default:
		return newError(Unavailable, operation+"_unavailable", true, err)
	}
}

var _ Store = (*RepositoryStore)(nil)
