package agentloop

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/memorynamespace"
	"github.com/ArronJablonowski/COH/internal/workflow/retrievalguard"
)

const MemoryLookupActivityName = "coh.agent-loop.memory-lookup.v1"

// BoundedMemoryLookup deliberately exposes read only. The memory controller
// retains namespace, policy, retention, review, and provenance enforcement.
type BoundedMemoryLookup interface {
	Get(context.Context, memorynamespace.GetRequest) (memorynamespace.Result, error)
}

type MemoryLookupRequest struct {
	Read                     memorynamespace.GetRequest
	Case                     domain.CaseRef
	TaskID                   string
	ActorRevision            uint64
	InspectionIdempotencyKey string
	InspectionProfile        retrievalguard.InspectionProfile
}

type MemoryLookupResult struct {
	Namespace              memorynamespace.Namespace
	Key                    string
	Revision               uint64
	SourceDigest           string
	SourceProvenanceDigest string
	Inspection             retrievalguard.InspectionResult
	AuditEventDigest       string
	ProvenanceDigest       string
	Replayed               bool
}

type MemoryLookupActivity struct {
	memory BoundedMemoryLookup
	guard  HostileContentGuard
}

func NewMemoryLookupActivity(memory BoundedMemoryLookup, guard HostileContentGuard) (*MemoryLookupActivity, error) {
	if memory == nil || guard == nil {
		return nil, newError(InvalidInput, "memory_lookup", "dependencies_required", false, nil)
	}
	return &MemoryLookupActivity{memory: memory, guard: guard}, nil
}

func (activity *MemoryLookupActivity) Lookup(ctx context.Context, request MemoryLookupRequest) (MemoryLookupResult, error) {
	if activity == nil || activity.memory == nil || activity.guard == nil {
		return MemoryLookupResult{}, newError(Unavailable, "memory_lookup", "activity_unavailable", true, nil)
	}
	result, err := activity.memory.Get(ctx, request.Read)
	if err != nil {
		return MemoryLookupResult{}, mapMemoryError(err)
	}
	guarded, err := activity.guard.Inspect(ctx, retrievalguard.Request{
		SchemaVersion: retrievalguard.RequestSchemaVersion, ContractVersion: retrievalguard.ContractVersion,
		RequestID: request.Read.RequestID, IdempotencyKey: request.InspectionIdempotencyKey,
		Case: request.Case, TaskID: request.TaskID, ActorID: request.Read.ActorID,
		ActorRevision: request.ActorRevision,
		Source: retrievalguard.Source{Kind: retrievalguard.MemorySource, Artifact: result.Record.Value,
			Trust: retrievalguard.UntrustedContent, ProvenanceDigest: result.Record.ProvenanceDigest},
		Profile: request.InspectionProfile, PolicyDigest: request.Read.PolicyDigest,
		Deadline: request.Read.Deadline,
	})
	if err != nil {
		return MemoryLookupResult{}, mapRetrievalError("memory_lookup", err)
	}
	return MemoryLookupResult{Namespace: result.Record.Namespace, Key: result.Record.Key,
		Revision: result.Record.Revision, SourceDigest: result.Record.Value.Digest,
		SourceProvenanceDigest: result.Record.ProvenanceDigest, Inspection: guarded.Inspection,
		AuditEventDigest: guarded.AuditEventDigest, ProvenanceDigest: guarded.ProvenanceDigest,
		Replayed: result.Replayed || guarded.Replayed}, nil
}

func mapMemoryError(err error) error {
	switch memorynamespace.CodeOf(err) {
	case memorynamespace.InvalidInput:
		return newError(InvalidInput, "memory_lookup", "request_invalid", false, err)
	case memorynamespace.Denied:
		return newError(Denied, "memory_lookup", "memory_denied", false, err)
	case memorynamespace.NotFound:
		return newError(NotFound, "memory_lookup", "memory_not_found", false, err)
	case memorynamespace.Conflict:
		return newError(Conflict, "memory_lookup", "memory_conflict", false, err)
	case memorynamespace.Canceled:
		return newError(Canceled, "memory_lookup", "memory_canceled", false, err)
	case memorynamespace.Timeout:
		return newError(Timeout, "memory_lookup", "memory_timeout", false, err)
	default:
		return newError(Unavailable, "memory_lookup", "memory_unavailable",
			memorynamespace.Retryable(err), err)
	}
}

func mapRetrievalError(operation string, err error) error {
	switch retrievalguard.CodeOf(err) {
	case retrievalguard.InvalidInput:
		return newError(InvalidInput, operation, "inspection_request_invalid", false, err)
	case retrievalguard.Denied:
		return newError(Denied, operation, "hostile_content_denied", false, err)
	case retrievalguard.NotFound:
		return newError(NotFound, operation, "source_not_found", false, err)
	case retrievalguard.Conflict:
		return newError(Conflict, operation, "inspection_conflict", false, err)
	case retrievalguard.Canceled:
		return newError(Canceled, operation, "inspection_canceled", false, err)
	case retrievalguard.Timeout:
		return newError(Timeout, operation, "inspection_timeout", false, err)
	default:
		return newError(Unavailable, operation, "inspection_unavailable", retrievalguard.Retryable(err), err)
	}
}
