package estop

import (
	"context"
	"reflect"
	"sort"
	"sync"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

type replayRecord struct {
	digest string
	record ActivationRecord
}

type controlRecord struct {
	ack     stopcontract.Acknowledgement
	auditID string
}

type MemoryStore struct {
	mu         sync.Mutex
	epoch      uint64
	states     map[string]stopcontract.State
	requests   map[string]replayRecord
	controls   map[string]controlRecord
	audits     map[string]stopcontract.AuditRecord
	auditOrder []string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{states: make(map[string]stopcontract.State), requests: make(map[string]replayRecord),
		controls: make(map[string]controlRecord), audits: make(map[string]stopcontract.AuditRecord)}
}

func (store *MemoryStore) Activate(ctx context.Context, candidate ActivationCandidate) (ActivationRecord, ActivationResult, error) {
	if err := ctx.Err(); err != nil {
		return ActivationRecord{}, "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	requestKey := candidate.Command.Scope.OrganizationID + "\x00" + candidate.Command.Scope.TenantID + "\x00" +
		candidate.Command.ActorID + "\x00" + candidate.Command.IdempotencyKey
	if previous, exists := store.requests[requestKey]; exists {
		if previous.digest == candidate.RequestDigest {
			return cloneActivation(previous.record), ActivationReplay, nil
		}
		return ActivationRecord{}, ActivationConflict, nil
	}
	key := scopeKey(candidate.Command.Scope)
	if current, exists := store.states[key]; exists && current.Active {
		return ActivationRecord{}, ActivationConflict, brokerError(stopcontract.Conflict, "stop_already_active")
	}
	store.epoch++
	state := stopcontract.State{SchemaVersion: stopcontract.StateSchemaVersion, ContractVersion: stopcontract.ContractVersion,
		Scope: candidate.Command.Scope, Epoch: store.epoch, Active: true, RequestID: candidate.Command.RequestID,
		RequestDigest: candidate.RequestDigest, ActorID: candidate.Command.ActorID, ActorRevision: candidate.Authority.ActorRevision,
		ReasonCode: candidate.Command.ReasonCode, AuthorizationDecisionDigest: candidate.Authority.AuthorizationDecisionDigest,
		PolicyDecisionDigest: candidate.Authority.PolicyDecisionDigest, ActivatedAt: candidate.ActivatedAt}
	decision := activationDecision(candidate.Command, candidate.Authority, state, nil, candidate.ActivatedAt)
	audit := newAuditRecord(decision)
	record := ActivationRecord{State: state, Decision: decision, AuditID: audit.ID}
	store.states[key] = state
	store.requests[requestKey] = replayRecord{digest: candidate.RequestDigest, record: cloneActivation(record)}
	store.putAudit(audit)
	return cloneActivation(record), ActivationNew, nil
}

func (store *MemoryStore) Effective(ctx context.Context, organizationID, tenantID, caseID string) (stopcontract.State, bool, error) {
	if err := ctx.Err(); err != nil {
		return stopcontract.State{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	global := stopcontract.Scope{Kind: "global", OrganizationID: organizationID, TenantID: tenantID}
	if state, exists := store.states[scopeKey(global)]; exists && state.Active {
		return state, true, nil
	}
	if caseID == "" {
		return stopcontract.State{}, false, nil
	}
	caseScope := stopcontract.Scope{Kind: "case", OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}
	state, exists := store.states[scopeKey(caseScope)]
	return state, exists && state.Active, nil
}

func (store *MemoryStore) ReserveAudit(ctx context.Context, decision stopcontract.Decision) (stopcontract.AuditRecord, error) {
	if err := ctx.Err(); err != nil {
		return stopcontract.AuditRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record := newAuditRecord(decision)
	store.putAudit(record)
	return record, nil
}

func (store *MemoryStore) RecordControl(ctx context.Context, state stopcontract.State, ack stopcontract.Acknowledgement, decision stopcontract.Decision) (stopcontract.AuditRecord, ControlRecordResult, error) {
	if err := ctx.Err(); err != nil {
		return stopcontract.AuditRecord{}, "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.states[scopeKey(state.Scope)]
	if !exists || !reflect.DeepEqual(current, state) {
		return stopcontract.AuditRecord{}, ControlConflict, brokerError(stopcontract.Conflict, "stop_state_stale")
	}
	key := scopeKey(state.Scope) + "\x00" + ack.ControlID
	if previous, exists := store.controls[key]; exists {
		if reflect.DeepEqual(previous.ack, ack) {
			return store.audits[previous.auditID], ControlReplay, nil
		}
		return stopcontract.AuditRecord{}, ControlConflict, nil
	}
	audit := newAuditRecord(decision)
	store.controls[key] = controlRecord{ack: ack, auditID: audit.ID}
	store.putAudit(audit)
	return audit, ControlNew, nil
}

func (store *MemoryStore) PendingAudits(ctx context.Context, limit int) ([]stopcontract.AuditRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if limit <= 0 || limit > 1024 {
		return nil, brokerError(stopcontract.InvalidInput, "audit_limit_invalid")
	}
	result := make([]stopcontract.AuditRecord, 0, limit)
	for _, id := range store.auditOrder {
		record := store.audits[id]
		if !record.Delivered {
			result = append(result, record)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (store *MemoryStore) MarkAuditDelivered(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.audits[id]
	if !exists {
		return brokerError(stopcontract.NotFound, "audit_record_not_found")
	}
	record.Delivered = true
	store.audits[id] = record
	return nil
}

func (store *MemoryStore) putAudit(record stopcontract.AuditRecord) {
	if _, exists := store.audits[record.ID]; exists {
		return
	}
	store.audits[record.ID] = record
	store.auditOrder = append(store.auditOrder, record.ID)
	sort.Strings(store.auditOrder)
}

func newAuditRecord(decision stopcontract.Decision) stopcontract.AuditRecord {
	return stopcontract.AuditRecord{ID: decision.DecisionDigest, Decision: decision}
}

func scopeKey(scope stopcontract.Scope) string {
	return scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.Kind + "\x00" + scope.CaseID
}

func cloneActivation(record ActivationRecord) ActivationRecord { return record }
