package auditlog

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

// AppendOutbox projects an atomically committed metadata outbox reference into
// the tenant audit chain. The returned chain hash is the settlement evidence
// digest; callers must not mark delivery successful when this method fails.
func (service *Service) AppendOutbox(ctx context.Context, delivery workflowbase.OutboxDelivery) (AppendResult, error) {
	message := delivery.Message
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: message.ID, OrganizationID: message.Case.OrganizationID, TenantID: message.Case.TenantID,
		CaseID: message.Case.CaseID, SourceSchema: "coh.storage-outbox/v1", Operation: message.Topic,
		Outcome: "allowed", ReasonCode: "outbox_delivered", SubjectDigest: message.PayloadDigest,
		EvidenceDigests: []string{message.PayloadDigest}}
	if delivery.LeaseID == "" || tamperaudit.ValidateEvent(event) != nil {
		return AppendResult{}, ErrInvalidInput
	}
	return service.Append(ctx, event)
}
