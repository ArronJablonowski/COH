package workflow

import (
	"context"
	"database/sql"
	"encoding/json"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

// SQLiteWorkflowIndex durably records active workflow targets. The caller
// owns and configures the database handle.
type SQLiteWorkflowIndex struct{ db *sql.DB }

func NewSQLiteWorkflowIndex(ctx context.Context, db *sql.DB) (*SQLiteWorkflowIndex, error) {
	if ctx == nil || db == nil {
		return nil, NewEngineError(EngineInvalidInput, "workflow_index", "configuration", "database and context required", nil)
	}
	index := &SQLiteWorkflowIndex{db: db}
	if err := index.verifyDurability(ctx); err != nil {
		return nil, err
	}
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS coh_active_workflows (
target_key TEXT PRIMARY KEY, organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
case_id TEXT NOT NULL, target_json BLOB NOT NULL)`)
	if err != nil {
		return nil, workflowIndexError(ctx)
	}
	return index, nil
}

func (index *SQLiteWorkflowIndex) verifyDurability(ctx context.Context) error {
	var journal string
	var synchronous, busyTimeout int
	if index.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal) != nil ||
		index.db.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous) != nil ||
		index.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout) != nil {
		return workflowIndexError(ctx)
	}
	if journal != "wal" || synchronous != 2 || busyTimeout < 1000 {
		return NewEngineError(EngineDenied, "workflow_index", "durability", "unsafe SQLite durability configuration", nil)
	}
	return nil
}

func (index *SQLiteWorkflowIndex) Add(ctx context.Context, target WorkflowTarget) error {
	if err := workflowIndexInput(ctx, target); err != nil {
		return err
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		return NewEngineError(EngineInvalidInput, "workflow_index", "target", "target encoding failed", nil)
	}
	_, err = index.db.ExecContext(ctx, `INSERT INTO coh_active_workflows
(target_key, organization_id, tenant_id, case_id, target_json) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(target_key) DO UPDATE SET target_json = excluded.target_json`, workflowTargetKey(target),
		target.Case.OrganizationID, target.Case.TenantID, target.Case.CaseID, encoded)
	if err != nil {
		return workflowIndexError(ctx)
	}
	return nil
}

func (index *SQLiteWorkflowIndex) Remove(ctx context.Context, target WorkflowTarget) error {
	if err := workflowIndexInput(ctx, target); err != nil {
		return err
	}
	if _, err := index.db.ExecContext(ctx, `DELETE FROM coh_active_workflows WHERE target_key = ?`,
		workflowTargetKey(target)); err != nil {
		return workflowIndexError(ctx)
	}
	return nil
}

func (index *SQLiteWorkflowIndex) List(ctx context.Context, scope stopcontract.Scope) ([]WorkflowTarget, error) {
	if ctx == nil || ctx.Err() != nil || stopcontract.ValidateScope(scope) != nil {
		return nil, NewEngineError(EngineInvalidInput, "workflow_index", "scope", "valid scope and context required", nil)
	}
	query := `SELECT target_json FROM coh_active_workflows WHERE organization_id = ? AND tenant_id = ?`
	arguments := []any{scope.OrganizationID, scope.TenantID}
	if scope.Kind == "case" {
		query += ` AND case_id = ?`
		arguments = append(arguments, scope.CaseID)
	}
	query += ` ORDER BY target_key`
	rows, err := index.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, workflowIndexError(ctx)
	}
	defer rows.Close()
	result := make([]WorkflowTarget, 0)
	for rows.Next() {
		var encoded []byte
		var target WorkflowTarget
		if rows.Scan(&encoded) != nil || json.Unmarshal(encoded, &target) != nil ||
			validateWorkflowTarget("workflow_index", target) != nil {
			return nil, NewEngineError(EngineUnavailable, "workflow_index", "record", "workflow index record is corrupt", nil)
		}
		result = append(result, target)
	}
	if rows.Err() != nil {
		return nil, workflowIndexError(ctx)
	}
	return result, nil
}

func workflowIndexError(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return validateEngineContext(ctx, "workflow_index")
	}
	return NewEngineError(EngineUnavailable, "workflow_index", "database", "workflow index unavailable", nil)
}

var _ WorkflowIndex = (*SQLiteWorkflowIndex)(nil)
