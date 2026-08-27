package redactioncustody

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

func TestAdapterBindsGoverningDecisionAndVerifiesExactDurableReceipt(t *testing.T) {
	request := custodyRequestFixture()
	receipt := custodyReceiptFixture(t, request.Command.Case)
	recorder := &recorderStub{result: custody.Result{Receipt: receipt, Replayed: true}}
	ledger := &ledgerStub{head: custody.Head{Case: request.Command.Case, ChainHash: custody.GenesisHash}, receipt: receipt, found: true}
	adapter, err := New(recorder, ledger)
	if err != nil {
		t.Fatal(err)
	}

	proof, replayed, err := adapter.RecordRedaction(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed || recorder.executed.Operation != custody.Redact || recorder.executed.Phase != custody.Completed ||
		recorder.executed.GoverningDecisionDigest == nil || *recorder.executed.GoverningDecisionDigest != request.DecisionDigest ||
		recorder.executed.PriorAuthorizationDigest != nil || len(recorder.executed.Parents) != 1 ||
		recorder.executed.Parents[0].Artifact != request.Command.Source.Artifact ||
		recorder.executed.Subject.Artifact != request.Derived.Artifact {
		t.Fatalf("custody command lost redaction lineage or authority: %+v", recorder.executed)
	}
	if recorder.executed.RuleDigest == nil || *recorder.executed.RuleDigest != request.Command.RuleDigest ||
		recorder.executed.ReasonDigest == nil || *recorder.executed.ReasonDigest != request.Command.ReasonDigest ||
		recorder.executed.MappingDigest == nil || *recorder.executed.MappingDigest != request.MappingDigest ||
		recorder.executed.ApprovalDigest == nil || *recorder.executed.ApprovalDigest != request.ApprovalDigest {
		t.Fatalf("custody command lost governed redaction facts: %+v", recorder.executed)
	}
	if proof.ReceiptDigest != receipt.ReceiptDigest || proof.RecordDigest != receipt.RecordDigest ||
		proof.ChainHash != receipt.ChainHash || proof.Sequence != receipt.Sequence || proof.AuditDigest != receipt.AuditEventDigest {
		t.Fatalf("proof=%+v", proof)
	}

	if err = adapter.VerifyRedaction(context.Background(), request, proof); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recorder.verifiedCommand, recorder.executed) || recorder.verifiedReceipt != receipt {
		t.Fatalf("verification did not use exact command and durable receipt")
	}
}

func TestAdapterRejectsNarrowProofThatDoesNotMatchDurableReceipt(t *testing.T) {
	request := custodyRequestFixture()
	receipt := custodyReceiptFixture(t, request.Command.Case)
	recorder := &recorderStub{}
	ledger := &ledgerStub{receipt: receipt, found: true}
	adapter, _ := New(recorder, ledger)
	proof := redaction.CustodyProof{ReceiptDigest: receipt.ReceiptDigest, RecordDigest: digest("changed"),
		ChainHash: receipt.ChainHash, Sequence: receipt.Sequence, AuditDigest: receipt.AuditEventDigest}
	if err := adapter.VerifyRedaction(context.Background(), request, proof); err == nil || recorder.verifyCalls != 0 {
		t.Fatalf("mismatched proof accepted: %v", err)
	}
}

type recorderStub struct {
	result          custody.Result
	executed        custody.Command
	verifiedCommand custody.Command
	verifiedReceipt custody.Receipt
	verifyCalls     int
}

func (stub *recorderStub) Execute(_ context.Context, command custody.Command) (custody.Result, error) {
	stub.executed = command
	return stub.result, nil
}

func (stub *recorderStub) VerifyReceipt(_ context.Context, command custody.Command, receipt custody.Receipt) error {
	stub.verifyCalls++
	stub.verifiedCommand, stub.verifiedReceipt = command, receipt
	return nil
}

type ledgerStub struct {
	head    custody.Head
	receipt custody.Receipt
	found   bool
}

func (stub *ledgerStub) LoadHead(_ context.Context, _ domain.CaseRef) (custody.Head, error) {
	return stub.head, nil
}

func (stub *ledgerStub) ResolveReceipt(_ context.Context, _ domain.CaseRef, _ string) (custody.Receipt, bool, error) {
	return stub.receipt, stub.found, nil
}

func custodyRequestFixture() redaction.CustodyRequest {
	at := time.Date(2026, 8, 27, 2, 0, 0, 0, time.UTC)
	scope := domain.CaseRef{OrganizationID: id(1), TenantID: id(2), CaseID: id(3)}
	source := evidence("a", "restricted", 100, "b", "c", "d")
	derived := evidence("e", "confidential", 80, "f", "1", "2")
	head := redaction.CustodyHead{Case: scope, ChainHash: custody.GenesisHash}
	command := redaction.Command{SchemaVersion: redaction.CommandSchemaVersion, ContractVersion: redaction.ContractVersion,
		RequestID: id(4), IdempotencyKey: "redaction-1", Case: scope, ActorID: id(5), ActorRevision: 2,
		Source: source, RuleDigest: digest("3"), PlanDigest: digest("4"), ReasonDigest: digest("5"),
		OutputMediaType: "text/plain", OutputClassification: "confidential", KeyProfile: "case-evidence",
		KeyProfileDigest: digest("6"), PolicyDigest: digest("7"), ExpectedCaseRevision: 3,
		ExpectedCustodyHead: head, Deadline: at.Add(time.Minute)}
	return redaction.CustodyRequest{Command: command, Derived: derived, MappingDigest: digest("8"),
		ApprovalDigest: digest("9"), DecisionDigest: digest("a"), ExpectedHead: head, Deadline: command.Deadline}
}

func custodyReceiptFixture(t *testing.T, scope domain.CaseRef) custody.Receipt {
	t.Helper()
	value := custody.Receipt{SchemaVersion: custody.ReceiptSchemaVersion, ContractVersion: custody.ContractVersion,
		RequestID: id(6), Case: scope, IdempotencyDigest: digest("b"), IntentDigest: digest("c"),
		DecisionDigest: digest("d"), CustodyID: id(7), Sequence: 1, RecordDigest: digest("e"),
		ChainHash: digest("f"), AuditEventDigest: digest("1"), ProvenanceDigest: digest("2"),
		CreatedAt: time.Date(2026, 8, 27, 2, 0, 1, 0, time.UTC)}
	var err error
	value.ReceiptDigest, err = custody.ReceiptBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func evidence(artifact, classification string, length int64, manifest, provenance, receipt string) redaction.EvidenceReference {
	return redaction.EvidenceReference{
		Artifact:                 domain.ArtifactRef{Digest: digest(artifact), MediaType: "text/plain", Classification: classification, Length: length},
		Manifest:                 domain.ArtifactRef{Digest: digest(manifest), MediaType: "application/vnd.coh.artifact-manifest+json", Classification: classification, Length: 256},
		ManifestProvenanceDigest: digest(provenance), IngestionReceiptDigest: digest(receipt)}
}

func id(suffix int) string {
	return "00000000-0000-7000-8000-" + strings.Repeat("0", 11) + string(rune('0'+suffix))
}
func digest(value string) string { return "sha256:" + strings.Repeat(value, 64) }
