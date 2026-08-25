package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func (store *Store) beginScoped(ctx context.Context, organizationID, tenantID string) (pgx.Tx, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('coh.organization_id', $1, true), pg_catalog.set_config('coh.tenant_id', $2, true)`, organizationID, tenantID); err != nil {
		tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}
