package estop

import (
	"context"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

func (controller *Controller) Check(ctx context.Context, organizationID, tenantID, caseID string) (stopcontract.State, error) {
	if controller == nil || controller.store == nil {
		return stopcontract.State{}, brokerError(stopcontract.Unavailable, "controller_unavailable")
	}
	if err := normalizeContext(ctx); err != nil {
		return stopcontract.State{}, err
	}
	probe := stopcontract.Scope{Kind: "global", OrganizationID: organizationID, TenantID: tenantID}
	if err := stopcontract.ValidateScope(probe); err != nil {
		return stopcontract.State{}, err
	}
	if caseID != "" {
		probe.Kind, probe.CaseID = "case", caseID
		if err := stopcontract.ValidateScope(probe); err != nil {
			return stopcontract.State{}, err
		}
	}
	state, active, err := controller.store.Effective(ctx, organizationID, tenantID, caseID)
	if err != nil {
		return stopcontract.State{}, normalizeStoreError(ctx, err)
	}
	if active {
		return state, brokerError(stopcontract.Denied, "emergency_stop_active")
	}
	return stopcontract.State{}, nil
}

// Allow implements the narrow fail-closed guard consumed by capability
// brokers. A nil result proves that no effective global or case stop was
// active when the authoritative store was read.
func (controller *Controller) Allow(ctx context.Context, organizationID, tenantID, caseID string) error {
	_, err := controller.Check(ctx, organizationID, tenantID, caseID)
	return err
}

func (controller *Controller) RecoverAudit(ctx context.Context, limit int) (int, error) {
	if controller == nil || controller.store == nil || controller.audit == nil {
		return 0, brokerError(stopcontract.Unavailable, "controller_unavailable")
	}
	if err := normalizeContext(ctx); err != nil {
		return 0, err
	}
	records, err := controller.store.PendingAudits(ctx, limit)
	if err != nil {
		return 0, normalizeStoreError(ctx, err)
	}
	delivered := 0
	for _, record := range records {
		if err := controller.deliverAudit(ctx, record); err != nil {
			return delivered, brokerError(stopcontract.Unavailable, "audit_delivery_pending")
		}
		delivered++
	}
	return delivered, nil
}
