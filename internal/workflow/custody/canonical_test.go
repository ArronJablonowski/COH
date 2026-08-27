package custody

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var custodyFixtureTime = time.Date(2026, 8, 27, 1, 0, 0, 0, time.UTC)

func TestEveryCustodyOperationHasOneStrictValidShape(t *testing.T) {
	for _, test := range []struct {
		operation Operation
		phase     Phase
	}{
		{Acquire, Completed}, {Access, Authorized}, {Transform, Completed}, {Redact, Completed},
		{Transfer, Authorized}, {Transfer, Completed}, {Export, Authorized}, {Export, Completed},
		{PlaceHold, Completed}, {ReleaseHold, Completed}, {Delete, Authorized}, {Delete, Completed},
	} {
		command := custodyCommandFixture(test.operation, test.phase)
		if err := validateCommand(command, custodyFixtureTime); err != nil {
			t.Fatalf("%s/%s: %v", test.operation, test.phase, err)
		}
		if _, err := CanonicalCommand(command); err != nil {
			t.Fatalf("canonical %s/%s: %v", test.operation, test.phase, err)
		}
	}
}

func TestCanonicalCommandBindsEveryCustodySecurityDimension(t *testing.T) {
	base := custodyCommandFixture(Export, Completed)
	baseDigest := mustCommandDigest(t, base)
	mutations := map[string]func(*Command){
		"organization":    func(value *Command) { value.Case.OrganizationID = custodyUUID(9); value.ExpectedHead.Case = value.Case },
		"tenant":          func(value *Command) { value.Case.TenantID = custodyUUID(9); value.ExpectedHead.Case = value.Case },
		"case":            func(value *Command) { value.Case.CaseID = custodyUUID(9); value.ExpectedHead.Case = value.Case },
		"actor":           func(value *Command) { value.ActorID = custodyUUID(9) },
		"actor revision":  func(value *Command) { value.ActorRevision++ },
		"artifact":        func(value *Command) { value.Subject.Artifact.Digest = fixtureDigest("artifact.changed") },
		"artifact length": func(value *Command) { value.Subject.Artifact.Length++ },
		"manifest":        func(value *Command) { value.Subject.Manifest.Digest = fixtureDigest("manifest.changed") },
		"manifest provenance": func(value *Command) {
			value.Subject.ManifestProvenanceDigest = fixtureDigest("manifest.provenance.changed")
		},
		"ingestion receipt": func(value *Command) {
			value.Subject.IngestionReceiptDigest = fixtureDigest("ingest.receipt.changed")
		},
		"purpose":     func(value *Command) { *value.PurposeDigest = fixtureDigest("purpose.changed") },
		"destination": func(value *Command) { *value.DestinationDigest = fixtureDigest("destination.changed") },
		"recipient":   func(value *Command) { *value.RecipientDigest = fixtureDigest("recipient.changed") },
		"external receipt": func(value *Command) {
			*value.ExternalReceiptDigest = fixtureDigest("external.receipt.changed")
		},
		"prior authorization": func(value *Command) {
			*value.PriorAuthorizationDigest = fixtureDigest("prior.authorization.changed")
		},
		"policy":        func(value *Command) { value.PolicyDigest = fixtureDigest("policy.changed") },
		"case revision": func(value *Command) { value.ExpectedCaseRevision++ },
		"head":          func(value *Command) { value.ExpectedHead.ChainHash = fixtureDigest("head.changed") },
		"deadline":      func(value *Command) { value.Deadline = value.Deadline.Add(time.Second) },
		"idempotency":   func(value *Command) { value.IdempotencyKey = "custody-key-changed" },
	}
	for name, mutate := range mutations {
		changed := cloneCommand(base)
		mutate(&changed)
		if got := mustCommandDigest(t, changed); got == baseDigest {
			t.Fatalf("%s mutation preserved command digest", name)
		}
	}

	transform := custodyCommandFixture(Transform, Completed)
	transformDigest := mustCommandDigest(t, transform)
	transform.Parents[0].Artifact.Digest = fixtureDigest("parent.changed")
	if got := mustCommandDigest(t, transform); got == transformDigest {
		t.Fatal("parent lineage mutation preserved command digest")
	}
	redact := custodyCommandFixture(Redact, Completed)
	redactDigest := mustCommandDigest(t, redact)
	*redact.GoverningDecisionDigest = fixtureDigest("governing.decision.changed")
	if got := mustCommandDigest(t, redact); got == redactDigest {
		t.Fatal("governing decision mutation preserved command digest")
	}
}

func TestCustodyValidationRejectsInvalidFieldCombinationsAndStaleBindings(t *testing.T) {
	tests := map[string]func() Command{
		"acquire extra purpose": func() Command {
			value := custodyCommandFixture(Acquire, Completed)
			value.PurposeDigest = digestPointer("purpose")
			return value
		},
		"access completed": func() Command {
			value := custodyCommandFixture(Access, Authorized)
			value.Phase = Completed
			return value
		},
		"transfer destination absent": func() Command {
			value := custodyCommandFixture(Transfer, Authorized)
			value.DestinationDigest = nil
			value.RecipientDigest = nil
			return value
		},
		"transform child parent": func() Command {
			value := custodyCommandFixture(Transform, Completed)
			value.Parents[0] = value.Subject
			return value
		},
		"delete completion authorization absent": func() Command {
			value := custodyCommandFixture(Delete, Completed)
			value.PriorAuthorizationDigest = nil
			return value
		},
		"redaction governing decision absent": func() Command {
			value := custodyCommandFixture(Redact, Completed)
			value.GoverningDecisionDigest = nil
			return value
		},
		"redaction prior custody authorization present": func() Command {
			value := custodyCommandFixture(Redact, Completed)
			value.PriorAuthorizationDigest = digestPointer("not-a-redaction-decision")
			return value
		},
	}
	for name, makeValue := range tests {
		if err := validateCommand(makeValue(), custodyFixtureTime); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	command := custodyCommandFixture(Access, Authorized)
	authorization := custodyAuthorizationFixture(t, command)
	authorization.CurrentHead.ChainHash = fixtureDigest("stale.head")
	if err := validateAuthorization(authorization); err == nil {
		t.Fatal("stale authorization head accepted")
	}
	decision := custodyDecisionFixture(t, custodyAuthorizationFixture(t, command))
	decision.ExpiresAt = decision.IssuedAt
	if err := validateDecision(decision); err == nil {
		t.Fatal("expired decision accepted")
	}
}

func TestCustodyRecordReceiptAndPrecommitBindingsDetectMutation(t *testing.T) {
	command := custodyCommandFixture(Acquire, Completed)
	authorization := custodyAuthorizationFixture(t, command)
	decision := custodyDecisionFixture(t, authorization)
	record := custodyRecordFixture(t, command, authorization, decision)
	if err := validateRecord(record); err != nil {
		t.Fatal(err)
	}
	receipt := custodyReceiptFixture(t, record)
	if err := validateReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	precommit, err := RecordPrecommitDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	changed := cloneRecord(record)
	changed.EvidenceVerifiedDigest = fixtureDigest("verified.changed")
	changedPrecommit, err := RecordPrecommitDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedPrecommit == precommit {
		t.Fatal("evidence mutation preserved precommit digest")
	}
	changed = cloneRecord(record)
	changed.AuditEventDigest = fixtureDigest("audit.changed")
	if err = validateRecord(changed); err == nil {
		t.Fatal("audit mutation preserved valid record")
	}
	changedReceipt := receipt
	changedReceipt.DecisionDigest = fixtureDigest("decision.changed")
	if err = validateReceipt(changedReceipt); err == nil {
		t.Fatal("decision mutation preserved valid receipt")
	}
}

func TestCanonicalWireUsesPublishedNamesAndExplicitNulls(t *testing.T) {
	canonical, err := CanonicalCommand(custodyCommandFixture(Acquire, Completed))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err = json.Unmarshal(canonical, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["schema_version"] != CommandSchemaVersion || wire["purpose_digest"] != nil ||
		wire["source_identity_digest"] == nil || wire["Subject"] != nil {
		t.Fatalf("unexpected canonical command: %s", canonical)
	}
}

func custodyCommandFixture(operation Operation, phase Phase) Command {
	scope := domain.CaseRef{OrganizationID: custodyUUID(1), TenantID: custodyUUID(2), CaseID: custodyUUID(3)}
	last := custodyFixtureTime.Add(-time.Minute)
	value := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		RequestID: custodyUUID(4), IdempotencyKey: "custody-key", Operation: operation, Phase: phase,
		Case: scope, ActorID: custodyUUID(5), ActorRevision: 3, Subject: custodyEvidenceFixture("subject"),
		PolicyDigest: fixtureDigest("policy"), ExpectedCaseRevision: 2,
		ExpectedHead: Head{Case: scope, Sequence: 7, ChainHash: fixtureDigest("head"), LastRecordAt: &last},
		Deadline:     custodyFixtureTime.Add(time.Minute)}
	switch operation {
	case Acquire:
		value.SourceIdentityDigest = digestPointer("source")
	case Access:
		value.PurposeDigest = digestPointer("purpose")
	case Transform:
		value.Parents = []EvidenceReference{custodyEvidenceFixture("parent")}
		value.TransformationDigest = digestPointer("transformation")
	case Redact:
		value.Parents = []EvidenceReference{custodyEvidenceFixture("parent")}
		value.RuleDigest, value.ReasonDigest = digestPointer("rule"), digestPointer("reason")
		value.MappingDigest, value.ApprovalDigest = digestPointer("mapping"), digestPointer("approval")
		value.GoverningDecisionDigest = digestPointer("redaction.decision")
	case Transfer, Export:
		value.PurposeDigest, value.DestinationDigest = digestPointer("purpose"), digestPointer("destination")
		value.RecipientDigest = digestPointer("recipient")
		if phase == Completed {
			value.ExternalReceiptDigest = digestPointer("external")
			value.PriorAuthorizationDigest = digestPointer("prior.authorization")
		}
	case PlaceHold, ReleaseHold:
		value.ReasonDigest, value.LifecycleReceiptDigest = digestPointer("reason"), digestPointer("lifecycle")
		value.ArtifactSetDigest = digestPointer("artifact.set")
	case Delete:
		value.ReasonDigest = digestPointer("reason")
		value.ArtifactSetDigest = digestPointer("artifact.set")
		if phase == Completed {
			value.LifecycleReceiptDigest = digestPointer("lifecycle")
			value.ExternalReceiptDigest = digestPointer("external")
			value.PriorAuthorizationDigest = digestPointer("prior.authorization")
		}
	}
	return value
}

func custodyAuthorizationFixture(t *testing.T, command Command) AuthorizationRequest {
	t.Helper()
	intent := mustCommandDigest(t, command)
	value := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: cloneCommand(command), CaseState: "open", CaseClassification: "restricted",
		CaseRevision: command.ExpectedCaseRevision, RetentionPolicyDigest: fixtureDigest("retention"),
		RetainUntil: custodyFixtureTime.Add(time.Hour), CaseProvenanceDigest: fixtureDigest("case.provenance"),
		EvidenceVerifiedDigest: fixtureDigest("evidence.verified"), CurrentHead: cloneHead(command.ExpectedHead)}
	var err error
	value.AuthorizationDigest, err = AuthorizationBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func custodyDecisionFixture(t *testing.T, authorization AuthorizationRequest) Decision {
	t.Helper()
	command := authorization.Command
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: custodyUUID(6), AuthorizationDigest: authorization.AuthorizationDigest,
		IntentDigest: authorization.IntentDigest, Operation: command.Operation, Phase: command.Phase,
		Case: command.Case, ActorID: command.ActorID, ActorRevision: command.ActorRevision,
		ExpectedCaseRevision: command.ExpectedCaseRevision, ExpectedHead: cloneHead(command.ExpectedHead),
		PolicyDigest: command.PolicyDigest, RevocationDigest: fixtureDigest("revocation"), Outcome: Allow,
		ReasonCode: ReasonAuthorized, IssuedAt: custodyFixtureTime, ExpiresAt: custodyFixtureTime.Add(time.Minute), Revision: 1}
	var err error
	value.DecisionDigest, err = DecisionBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func custodyRecordFixture(t *testing.T, command Command, authorization AuthorizationRequest, decision Decision) Record {
	t.Helper()
	previous := fixtureDigest("previous.provenance")
	value := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion, CustodyID: custodyUUID(7),
		Case: command.Case, Sequence: command.ExpectedHead.Sequence + 1,
		PreviousChainHash: command.ExpectedHead.ChainHash, Command: cloneCommand(command),
		IntentDigest: authorization.IntentDigest, AuthorizationDigest: authorization.AuthorizationDigest,
		DecisionDigest: decision.DecisionDigest, RevocationDigest: decision.RevocationDigest,
		EvidenceVerifiedDigest: authorization.EvidenceVerifiedDigest, PreviousProvenanceDigest: &previous,
		OccurredAt: custodyFixtureTime}
	var err error
	value.ProvenanceDigest, err = RecordProvenanceDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.AuditEventDigest = fixtureDigest("audit.event")
	value.RecordDigest, err = RecordBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.ChainHash, err = RecordChainHash(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func custodyReceiptFixture(t *testing.T, record Record) Receipt {
	t.Helper()
	value := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: record.Command.RequestID, Case: record.Case,
		IdempotencyDigest: IdempotencyBindingDigest(record.Command.IdempotencyKey), IntentDigest: record.IntentDigest,
		DecisionDigest: record.DecisionDigest, CustodyID: record.CustodyID, Sequence: record.Sequence,
		RecordDigest: record.RecordDigest, ChainHash: record.ChainHash, AuditEventDigest: record.AuditEventDigest,
		ProvenanceDigest: record.ProvenanceDigest, CreatedAt: record.OccurredAt}
	var err error
	value.ReceiptDigest, err = ReceiptBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func custodyEvidenceFixture(name string) EvidenceReference {
	return EvidenceReference{Artifact: domain.ArtifactRef{Digest: fixtureDigest(name + ".artifact"),
		MediaType: "application/octet-stream", Classification: "restricted", Length: 12},
		Manifest: domain.ArtifactRef{Digest: fixtureDigest(name + ".manifest"),
			MediaType: "application/vnd.coh.artifact-manifest+json", Classification: "restricted", Length: 24},
		ManifestProvenanceDigest: fixtureDigest(name + ".manifest.provenance"),
		IngestionReceiptDigest:   fixtureDigest(name + ".ingestion.receipt")}
}

func mustCommandDigest(t *testing.T, value Command) string {
	t.Helper()
	result, err := CommandBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func digestPointer(value string) *string {
	result := fixtureDigest(value)
	return &result
}

func fixtureDigest(value string) string { return digest("COH-CUSTODY-TEST-V1\x00", []byte(value)) }

func custodyUUID(suffix byte) string {
	return "018f0f9a-3c2d-7b1e-8a4f-00000000000" + string('0'+suffix)
}
