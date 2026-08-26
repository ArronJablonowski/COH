package broker

import (
	"context"
	"testing"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type auditCapture struct {
	event tamperaudit.Event
	err   error
}

func (capture *auditCapture) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	capture.event = event
	return capture.err
}

func TestDurableApprovalAuditProjection(t *testing.T) {
	capture := &auditCapture{}
	sink, err := newDurableApprovalAuditSink(capture)
	if err != nil {
		t.Fatal(err)
	}
	source := lifecycle.Event{SchemaVersion: lifecycle.SchemaVersion, ContractVersion: lifecycle.ContractVersion,
		EventID: "0198d6c4-1111-7111-8111-111111111111", Operation: "grant", Outcome: "allowed",
		ReasonCode: "approval_granted", ApprovalID: "0198d6c4-2222-7222-8222-222222222222",
		OrganizationID: "0198d6c4-3333-7333-8333-333333333333", TenantID: "0198d6c4-4444-7444-8444-444444444444",
		CaseID:            "0198d6c4-5555-7555-8555-555555555555",
		FingerprintDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ActorID:           "0198d6c4-6666-7666-8666-666666666666", ActorRevision: 3, RecordRevision: 2,
		OccurredAt: "2026-08-26T01:00:00.000000000Z"}
	if err := sink.AppendApprovalLifecycleEvent(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	if capture.event.SubjectID != source.ApprovalID || capture.event.SubjectDigest != source.FingerprintDigest ||
		capture.event.ActorID != source.ActorID || capture.event.OrganizationID != source.OrganizationID {
		t.Fatalf("projected event=%+v", capture.event)
	}
}
