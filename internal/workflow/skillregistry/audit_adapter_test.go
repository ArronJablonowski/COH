package skillregistry

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type durableAppenderStub struct {
	event tamperaudit.Event
	err   error
}

func (stub *durableAppenderStub) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	stub.event = event
	return stub.err
}

func TestDurableAuditorProjectsRedactedBoundEvent(t *testing.T) {
	fixture := newFixture(t)
	appender := &durableAppenderStub{}
	auditor, err := NewDurableAuditor(appender)
	if err != nil {
		t.Fatal(err)
	}
	source := AuditEvent{
		EventID: deterministicUUID("audit", "promotion"), OrganizationID: testOrganization,
		TenantID: testTenant, CaseID: testCase, TaskID: testTask, ActorID: testOwner,
		Action: AuditAction(Promote), SkillName: "timeline_builder",
		ManifestDigest: testDigest("2"), CommandDigest: testDigest("3"),
		PolicyDigest: testDigest("4"), ReviewDigest: testDigest("5"),
		Outcome: "allowed", OccurredAt: fixture.now,
	}
	receipt, err := auditor.Append(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := DigestAuditEvent(source)
	if receipt.EventID != source.EventID || receipt.EventDigest != expected ||
		!validDigest(receipt.ReceiptDigest) || appender.event.Operation != "skill_promote" ||
		appender.event.SubjectDigest != source.ManifestDigest ||
		appender.event.ActorID != "" || appender.event.SubjectID != "" ||
		!slices.IsSorted(appender.event.EvidenceDigests) ||
		!slices.Contains(appender.event.EvidenceDigests, expected) ||
		tamperaudit.ValidateEvent(appender.event) != nil {
		t.Fatalf("invalid durable audit projection: %#v %#v", receipt, appender.event)
	}

	appender.err = errors.New("audit store unavailable")
	if _, err := auditor.Append(context.Background(), source); CodeOf(err) != Unavailable {
		t.Fatalf("audit failure did not fail closed: %v", err)
	}
}
