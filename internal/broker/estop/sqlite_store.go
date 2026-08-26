package estop

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sync"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

// SQLiteStore is the durable single-node E-stop store. The caller owns the
// database handle and must configure SQLite for FULL synchronous durability,
// WAL journaling, a busy timeout, and a single writer connection.
type SQLiteStore struct {
	mu sync.Mutex
	db *sql.DB
}

func NewSQLiteStore(ctx context.Context, db *sql.DB) (*SQLiteStore, error) {
	if ctx == nil || db == nil {
		return nil, brokerError(stopcontract.InvalidInput, "sqlite_store_configuration_invalid")
	}
	store := &SQLiteStore{db: db}
	if err := store.verifyDurability(ctx); err != nil {
		return nil, err
	}
	if err := store.initialize(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *SQLiteStore) verifyDurability(ctx context.Context) error {
	var journal string
	if err := store.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil {
		return storeError(ctx, err)
	}
	var synchronous, busyTimeout int
	if err := store.db.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		return storeError(ctx, err)
	}
	if err := store.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		return storeError(ctx, err)
	}
	if journal != "wal" || synchronous != 2 || busyTimeout < 1000 {
		return brokerError(stopcontract.Denied, "sqlite_durability_configuration_invalid")
	}
	return nil
}

func (store *SQLiteStore) initialize(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS coh_estop_meta (
singleton INTEGER PRIMARY KEY CHECK (singleton = 1), epoch INTEGER NOT NULL CHECK (epoch >= 0))`,
		`INSERT INTO coh_estop_meta(singleton, epoch) VALUES (1, 0) ON CONFLICT(singleton) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS coh_estop_states (
scope_key TEXT PRIMARY KEY, state_json BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS coh_estop_requests (
request_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL, state_json BLOB NOT NULL,
decision_json BLOB NOT NULL, audit_id TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS coh_estop_controls (
control_key TEXT PRIMARY KEY, acknowledgement_json BLOB NOT NULL, audit_id TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS coh_estop_audits (
id TEXT PRIMARY KEY, decision_json BLOB NOT NULL, delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1)))`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return storeError(ctx, err)
		}
	}
	return nil
}

func (store *SQLiteStore) Activate(ctx context.Context, candidate ActivationCandidate) (ActivationRecord, ActivationResult, error) {
	if err := contextStoreError(ctx); err != nil {
		return ActivationRecord{}, "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ActivationRecord{}, "", storeError(ctx, err)
	}
	defer tx.Rollback()
	requestKey := candidate.Command.Scope.OrganizationID + "\x00" + candidate.Command.Scope.TenantID + "\x00" +
		candidate.Command.ActorID + "\x00" + candidate.Command.IdempotencyKey
	previous, found, err := readActivation(ctx, tx, requestKey)
	if err != nil {
		return ActivationRecord{}, "", err
	}
	if found {
		if previous.digest == candidate.RequestDigest {
			return previous.record, ActivationReplay, nil
		}
		return ActivationRecord{}, ActivationConflict, nil
	}
	key := scopeKey(candidate.Command.Scope)
	if _, found, err := readState(ctx, tx, key); err != nil {
		return ActivationRecord{}, "", err
	} else if found {
		return ActivationRecord{}, ActivationConflict, brokerError(stopcontract.Conflict, "stop_already_active")
	}
	var epoch uint64
	if err := tx.QueryRowContext(ctx, `UPDATE coh_estop_meta SET epoch = epoch + 1 WHERE singleton = 1 RETURNING epoch`).Scan(&epoch); err != nil {
		return ActivationRecord{}, "", storeError(ctx, err)
	}
	state := stopcontract.State{SchemaVersion: stopcontract.StateSchemaVersion, ContractVersion: stopcontract.ContractVersion,
		Scope: candidate.Command.Scope, Epoch: epoch, Active: true, RequestID: candidate.Command.RequestID,
		RequestDigest: candidate.RequestDigest, ActorID: candidate.Command.ActorID, ActorRevision: candidate.Authority.ActorRevision,
		ReasonCode: candidate.Command.ReasonCode, AuthorizationDecisionDigest: candidate.Authority.AuthorizationDecisionDigest,
		PolicyDecisionDigest: candidate.Authority.PolicyDecisionDigest, ActivatedAt: candidate.ActivatedAt}
	decision := activationDecision(candidate.Command, candidate.Authority, state, nil, candidate.ActivatedAt)
	audit := newAuditRecord(decision)
	stateJSON, decisionJSON, err := encodeStateDecision(state, decision)
	if err != nil {
		return ActivationRecord{}, "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO coh_estop_states(scope_key, state_json) VALUES (?, ?)`, key, stateJSON); err != nil {
		return ActivationRecord{}, "", storeError(ctx, err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO coh_estop_requests
(request_key, request_digest, state_json, decision_json, audit_id) VALUES (?, ?, ?, ?, ?)`,
		requestKey, candidate.RequestDigest, stateJSON, decisionJSON, audit.ID); err != nil {
		return ActivationRecord{}, "", storeError(ctx, err)
	}
	if err = insertAudit(ctx, tx, audit, decisionJSON); err != nil {
		return ActivationRecord{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return ActivationRecord{}, "", storeError(ctx, err)
	}
	return ActivationRecord{State: state, Decision: decision, AuditID: audit.ID}, ActivationNew, nil
}

func (store *SQLiteStore) Effective(ctx context.Context, organizationID, tenantID, caseID string) (stopcontract.State, bool, error) {
	if err := contextStoreError(ctx); err != nil {
		return stopcontract.State{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	global := stopcontract.Scope{Kind: "global", OrganizationID: organizationID, TenantID: tenantID}
	if state, found, err := readState(ctx, store.db, scopeKey(global)); err != nil {
		return stopcontract.State{}, false, err
	} else if found {
		return state, true, nil
	}
	if caseID == "" {
		return stopcontract.State{}, false, nil
	}
	caseScope := stopcontract.Scope{Kind: "case", OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}
	state, found, err := readState(ctx, store.db, scopeKey(caseScope))
	return state, found, err
}

func (store *SQLiteStore) ReserveAudit(ctx context.Context, decision stopcontract.Decision) (stopcontract.AuditRecord, error) {
	if err := contextStoreError(ctx); err != nil {
		return stopcontract.AuditRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	audit := newAuditRecord(decision)
	encoded, err := json.Marshal(decision)
	if err != nil {
		return stopcontract.AuditRecord{}, brokerError(stopcontract.InvalidInput, "audit_encoding_invalid")
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO coh_estop_audits(id, decision_json, delivered)
VALUES (?, ?, 0) ON CONFLICT(id) DO NOTHING`, audit.ID, encoded); err != nil {
		return stopcontract.AuditRecord{}, storeError(ctx, err)
	}
	return audit, nil
}

func (store *SQLiteStore) RecordControl(ctx context.Context, state stopcontract.State, ack stopcontract.Acknowledgement,
	decision stopcontract.Decision) (stopcontract.AuditRecord, ControlRecordResult, error) {
	if err := contextStoreError(ctx); err != nil {
		return stopcontract.AuditRecord{}, "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return stopcontract.AuditRecord{}, "", storeError(ctx, err)
	}
	defer tx.Rollback()
	current, found, err := readState(ctx, tx, scopeKey(state.Scope))
	if err != nil {
		return stopcontract.AuditRecord{}, "", err
	}
	if !found || !reflect.DeepEqual(current, state) {
		return stopcontract.AuditRecord{}, ControlConflict, brokerError(stopcontract.Conflict, "stop_state_stale")
	}
	key := scopeKey(state.Scope) + "\x00" + ack.ControlID
	previousAck, previousAudit, found, err := readControl(ctx, tx, key)
	if err != nil {
		return stopcontract.AuditRecord{}, "", err
	}
	if found {
		if reflect.DeepEqual(previousAck, ack) {
			audit, auditFound, auditErr := readAudit(ctx, tx, previousAudit)
			if auditErr != nil || !auditFound {
				return stopcontract.AuditRecord{}, "", brokerError(stopcontract.Unavailable, "audit_record_corrupt")
			}
			return audit, ControlReplay, nil
		}
		return stopcontract.AuditRecord{}, ControlConflict, nil
	}
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return stopcontract.AuditRecord{}, "", brokerError(stopcontract.InvalidInput, "control_encoding_invalid")
	}
	audit := newAuditRecord(decision)
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		return stopcontract.AuditRecord{}, "", brokerError(stopcontract.InvalidInput, "audit_encoding_invalid")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO coh_estop_controls(control_key, acknowledgement_json, audit_id)
VALUES (?, ?, ?)`, key, ackJSON, audit.ID); err != nil {
		return stopcontract.AuditRecord{}, "", storeError(ctx, err)
	}
	if err = insertAudit(ctx, tx, audit, decisionJSON); err != nil {
		return stopcontract.AuditRecord{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return stopcontract.AuditRecord{}, "", storeError(ctx, err)
	}
	return audit, ControlNew, nil
}

func (store *SQLiteStore) PendingAudits(ctx context.Context, limit int) ([]stopcontract.AuditRecord, error) {
	if err := contextStoreError(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1024 {
		return nil, brokerError(stopcontract.InvalidInput, "audit_limit_invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	rows, err := store.db.QueryContext(ctx, `SELECT id, decision_json FROM coh_estop_audits
WHERE delivered = 0 ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, storeError(ctx, err)
	}
	defer rows.Close()
	result := make([]stopcontract.AuditRecord, 0, limit)
	for rows.Next() {
		var id string
		var encoded []byte
		if err = rows.Scan(&id, &encoded); err != nil {
			return nil, storeError(ctx, err)
		}
		var decision stopcontract.Decision
		if json.Unmarshal(encoded, &decision) != nil || decision.DecisionDigest != id {
			return nil, brokerError(stopcontract.Unavailable, "audit_record_corrupt")
		}
		result = append(result, stopcontract.AuditRecord{ID: id, Decision: decision})
	}
	if err = rows.Err(); err != nil {
		return nil, storeError(ctx, err)
	}
	return result, nil
}

func (store *SQLiteStore) MarkAuditDelivered(ctx context.Context, id string) error {
	if err := contextStoreError(ctx); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	result, err := store.db.ExecContext(ctx, `UPDATE coh_estop_audits SET delivered = 1 WHERE id = ?`, id)
	if err != nil {
		return storeError(ctx, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return storeError(ctx, err)
	}
	if changed != 1 {
		return brokerError(stopcontract.NotFound, "audit_record_not_found")
	}
	return nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readState(ctx context.Context, database queryer, key string) (stopcontract.State, bool, error) {
	var encoded []byte
	err := database.QueryRowContext(ctx, `SELECT state_json FROM coh_estop_states WHERE scope_key = ?`, key).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return stopcontract.State{}, false, nil
	}
	if err != nil {
		return stopcontract.State{}, false, storeError(ctx, err)
	}
	var state stopcontract.State
	if json.Unmarshal(encoded, &state) != nil || stopcontract.ValidateState(state) != nil {
		return stopcontract.State{}, false, brokerError(stopcontract.Unavailable, "stop_state_corrupt")
	}
	return state, true, nil
}

func readActivation(ctx context.Context, tx *sql.Tx, key string) (replayRecord, bool, error) {
	var digestValue, auditID string
	var stateJSON, decisionJSON []byte
	err := tx.QueryRowContext(ctx, `SELECT request_digest, state_json, decision_json, audit_id
FROM coh_estop_requests WHERE request_key = ?`, key).Scan(&digestValue, &stateJSON, &decisionJSON, &auditID)
	if errors.Is(err, sql.ErrNoRows) {
		return replayRecord{}, false, nil
	}
	if err != nil {
		return replayRecord{}, false, storeError(ctx, err)
	}
	var state stopcontract.State
	var decision stopcontract.Decision
	if json.Unmarshal(stateJSON, &state) != nil || json.Unmarshal(decisionJSON, &decision) != nil ||
		stopcontract.ValidateState(state) != nil || decision.DecisionDigest != auditID {
		return replayRecord{}, false, brokerError(stopcontract.Unavailable, "activation_record_corrupt")
	}
	return replayRecord{digest: digestValue, record: ActivationRecord{State: state, Decision: decision, AuditID: auditID}}, true, nil
}

func readControl(ctx context.Context, tx *sql.Tx, key string) (stopcontract.Acknowledgement, string, bool, error) {
	var encoded []byte
	var auditID string
	err := tx.QueryRowContext(ctx, `SELECT acknowledgement_json, audit_id FROM coh_estop_controls WHERE control_key = ?`, key).
		Scan(&encoded, &auditID)
	if errors.Is(err, sql.ErrNoRows) {
		return stopcontract.Acknowledgement{}, "", false, nil
	}
	if err != nil {
		return stopcontract.Acknowledgement{}, "", false, storeError(ctx, err)
	}
	var acknowledgement stopcontract.Acknowledgement
	if json.Unmarshal(encoded, &acknowledgement) != nil || stopcontract.ValidateAcknowledgement(acknowledgement) != nil {
		return stopcontract.Acknowledgement{}, "", false, brokerError(stopcontract.Unavailable, "control_record_corrupt")
	}
	return acknowledgement, auditID, true, nil
}

func readAudit(ctx context.Context, tx *sql.Tx, id string) (stopcontract.AuditRecord, bool, error) {
	var encoded []byte
	var delivered int
	err := tx.QueryRowContext(ctx, `SELECT decision_json, delivered FROM coh_estop_audits WHERE id = ?`, id).
		Scan(&encoded, &delivered)
	if errors.Is(err, sql.ErrNoRows) {
		return stopcontract.AuditRecord{}, false, nil
	}
	if err != nil {
		return stopcontract.AuditRecord{}, false, storeError(ctx, err)
	}
	var decision stopcontract.Decision
	if json.Unmarshal(encoded, &decision) != nil || decision.DecisionDigest != id || (delivered != 0 && delivered != 1) {
		return stopcontract.AuditRecord{}, false, brokerError(stopcontract.Unavailable, "audit_record_corrupt")
	}
	return stopcontract.AuditRecord{ID: id, Decision: decision, Delivered: delivered == 1}, true, nil
}

func encodeStateDecision(state stopcontract.State, decision stopcontract.Decision) ([]byte, []byte, error) {
	stateJSON, stateErr := json.Marshal(state)
	decisionJSON, decisionErr := json.Marshal(decision)
	if stateErr != nil || decisionErr != nil {
		return nil, nil, brokerError(stopcontract.InvalidInput, "activation_encoding_invalid")
	}
	return stateJSON, decisionJSON, nil
}

func insertAudit(ctx context.Context, tx *sql.Tx, audit stopcontract.AuditRecord, decisionJSON []byte) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO coh_estop_audits(id, decision_json, delivered) VALUES (?, ?, 0)`,
		audit.ID, decisionJSON); err != nil {
		return storeError(ctx, err)
	}
	return nil
}

func contextStoreError(ctx context.Context) error {
	if ctx == nil {
		return brokerError(stopcontract.InvalidInput, "context_required")
	}
	return stopcontract.ContextError(ctx)
}

func storeError(ctx context.Context, err error) error {
	if contextErr := contextStoreError(ctx); contextErr != nil {
		return contextErr
	}
	return brokerError(stopcontract.Unavailable, "estop_store_unavailable")
}

var _ Store = (*SQLiteStore)(nil)
