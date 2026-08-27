package lifecycleredaction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

type repositoryStub struct {
	receipt redaction.Receipt
	record  redaction.Record
}

func (stub repositoryStub) ResolveReceipt(_ context.Context, _ domain.CaseRef,
	_ string) (redaction.Receipt, bool, error) {
	return stub.receipt, true, nil
}

func (stub repositoryStub) ResolveRecord(_ context.Context, _ domain.CaseRef,
	_ string) (redaction.Record, bool, error) {
	return stub.record, true, nil
}

type ingestionStub map[string]evidenceingest.Receipt

func (stub ingestionStub) ResolveReceipt(_ context.Context, _ domain.CaseRef,
	digest string) (evidenceingest.Receipt, bool, error) {
	value, found := stub[digest]
	return value, found, nil
}

type mappingStub struct {
	mapping redaction.Mapping
	err     error
}

func (stub mappingStub) ResolveRedactionMapping(context.Context,
	evidenceingest.Receipt) (redaction.Mapping, error) {
	return stub.mapping, stub.err
}

type custodyResolverStub struct{ receipt custody.Receipt }

func (stub custodyResolverStub) ResolveReceipt(context.Context, domain.CaseRef,
	string) (custody.Receipt, bool, error) {
	return stub.receipt, true, nil
}

type custodyVerifierStub struct {
	wantRequest redaction.CustodyRequest
	wantProof   redaction.CustodyProof
	err         error
	calls       int
}

func (stub *custodyVerifierStub) VerifyRedaction(_ context.Context,
	request redaction.CustodyRequest, proof redaction.CustodyProof) error {
	stub.calls++
	if request != stub.wantRequest || proof != stub.wantProof {
		return errors.New("custody request substitution")
	}
	return stub.err
}

type auditorStub struct {
	wantID     string
	wantDigest string
	proof      redaction.AuditProof
	err        error
}

func (stub auditorStub) VerifyRedactionEvent(_ context.Context, _ domain.CaseRef,
	eventID, digest string) (redaction.AuditProof, error) {
	if eventID != stub.wantID || digest != stub.wantDigest {
		return redaction.AuditProof{}, errors.New("audit request substitution")
	}
	return stub.proof, stub.err
}

type verifierFixture struct {
	scope      domain.CaseRef
	repository repositoryStub
	ingestion  ingestionStub
	mapping    redaction.Mapping
	custody    custody.Receipt
	request    redaction.CustodyRequest
	proof      redaction.CustodyProof
	audit      auditorStub
	evidence   evidencelifecycle.VerifiedEvidenceSet
}

func TestAdapterVerifiesCompleteRedactionAncestry(t *testing.T) {
	fixture := newVerifierFixture(t)
	custodyVerifier := &custodyVerifierStub{wantRequest: fixture.request, wantProof: fixture.proof}
	adapter, err := New(fixture.repository, fixture.ingestion, mappingStub{mapping: fixture.mapping},
		custodyResolverStub{fixture.custody}, custodyVerifier, fixture.audit)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := adapter.VerifyRedactionReceipts(t.Context(), fixture.scope, fixture.evidence)
	if err != nil || len(proofs) != 1 || proofs[0].ArtifactDigest != fixture.repository.record.Derived.Artifact.Digest ||
		proofs[0].ReceiptDigest != fixture.repository.receipt.ReceiptDigest ||
		proofs[0].MappingDigest != fixture.mapping.MappingDigest ||
		proofs[0].ProvenanceDigest != fixture.repository.record.ProvenanceDigest || custodyVerifier.calls != 1 {
		t.Fatalf("proofs=%+v custody calls=%d err=%v", proofs, custodyVerifier.calls, err)
	}
}

func TestAdapterRejectsBrokenLineageAndMappingSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*verifierFixture)
	}{
		{name: "source parent removed", mutate: func(value *verifierFixture) {
			value.evidence.Artifacts[1].ParentArtifactDigests = []string{digest("substituted-parent")}
		}},
		{name: "mapping digest changed", mutate: func(value *verifierFixture) {
			value.mapping.PlanDigest = digest("substituted-plan")
		}},
		{name: "mapping ingestion substituted", mutate: func(value *verifierFixture) {
			receipt := value.ingestion[value.repository.record.MappingIngestionReceiptDigest]
			receipt.ReceiptDigest = digest("substituted-receipt")
			value.ingestion[value.repository.record.MappingIngestionReceiptDigest] = receipt
		}},
		{name: "derived receipt digest changed", mutate: func(value *verifierFixture) {
			changed := digest("substituted-redaction-receipt")
			value.evidence.Artifacts[1].RedactionReceiptDigest = &changed
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerifierFixture(t)
			test.mutate(&fixture)
			custodyVerifier := &custodyVerifierStub{wantRequest: fixture.request, wantProof: fixture.proof}
			adapter, err := New(fixture.repository, fixture.ingestion, mappingStub{mapping: fixture.mapping},
				custodyResolverStub{fixture.custody}, custodyVerifier, fixture.audit)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = adapter.VerifyRedactionReceipts(t.Context(), fixture.scope,
				fixture.evidence); evidencelifecycle.CodeOf(err) != evidencelifecycle.Denied {
				t.Fatalf("code=%s err=%v", evidencelifecycle.CodeOf(err), err)
			}
		})
	}
}

func TestAdapterRejectsCustodyAndAuditVerificationFailure(t *testing.T) {
	fixture := newVerifierFixture(t)
	custodyVerifier := &custodyVerifierStub{wantRequest: fixture.request, wantProof: fixture.proof,
		err: errors.New("custody unavailable")}
	adapter, _ := New(fixture.repository, fixture.ingestion, mappingStub{mapping: fixture.mapping},
		custodyResolverStub{fixture.custody}, custodyVerifier, fixture.audit)
	if _, err := adapter.VerifyRedactionReceipts(t.Context(), fixture.scope,
		fixture.evidence); evidencelifecycle.CodeOf(err) != evidencelifecycle.Unavailable {
		t.Fatalf("custody code=%s err=%v", evidencelifecycle.CodeOf(err), err)
	}
	fixture = newVerifierFixture(t)
	fixture.audit.proof.EventDigest = digest("wrong-audit")
	custodyVerifier = &custodyVerifierStub{wantRequest: fixture.request, wantProof: fixture.proof}
	adapter, _ = New(fixture.repository, fixture.ingestion, mappingStub{mapping: fixture.mapping},
		custodyResolverStub{fixture.custody}, custodyVerifier, fixture.audit)
	if _, err := adapter.VerifyRedactionReceipts(t.Context(), fixture.scope,
		fixture.evidence); evidencelifecycle.CodeOf(err) != evidencelifecycle.Denied {
		t.Fatalf("audit code=%s err=%v", evidencelifecycle.CodeOf(err), err)
	}
}

func newVerifierFixture(t *testing.T) verifierFixture {
	t.Helper()
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	scope := domain.CaseRef{OrganizationID: uuid("org"), TenantID: uuid("tenant"), CaseID: uuid("case")}
	source := evidenceRef("source", "text/plain", "restricted", 10)
	derived := evidenceRef("derived", "text/plain", "confidential", 8)
	mapping := redaction.Mapping{SchemaVersion: redaction.MappingSchemaVersion,
		ContractVersion: redaction.ContractVersion, MappingID: uuid("mapping"), Case: scope,
		Source: source, DerivedArtifact: derived.Artifact, PlanDigest: digest("plan"), RuleDigest: digest("rule"),
		ReasonDigest: digest("reason"), ApprovalFingerprintDigest: digest("approval-fingerprint"),
		Entries: []redaction.MappingEntry{{Ordinal: 1, SourceStart: 0, SourceEnd: 2,
			SourceSegmentDigest: digest("source-segment"), OutputStart: 0, OutputEnd: 0,
			ReplacementMode: redaction.Remove, ReplacementDigest: digest("replacement")}},
		CreatedAt: now, PreviousProvenanceDigest: source.ManifestProvenanceDigest}
	mapping.ProvenanceDigest, _ = redaction.MappingProvenanceDigest(mapping)
	mapping.MappingDigest, _ = redaction.MappingBindingDigest(mapping)
	mappingCanonical, err := redaction.CanonicalMapping(mapping)
	if err != nil {
		t.Fatal(err)
	}
	mappingRef := evidenceRef("mapping", "application/vnd.coh.redaction-mapping+json", "restricted",
		int64(len(mappingCanonical)))
	mappingRef.Artifact.Digest = rawDigest(mappingCanonical)
	derivedReceipt := ingestionReceipt(derived, scope, now, "derived")
	derived.IngestionReceiptDigest = derivedReceipt.ReceiptDigest
	mappingReceipt := ingestionReceipt(mappingRef, scope, now, "mapping")
	mappingRef.IngestionReceiptDigest = mappingReceipt.ReceiptDigest
	command := redaction.Command{SchemaVersion: redaction.CommandSchemaVersion,
		ContractVersion: redaction.ContractVersion, RequestID: uuid("request"), IdempotencyKey: "redaction-fixture",
		Case: scope, ActorID: uuid("actor"), ActorRevision: 2, Source: source, RuleDigest: mapping.RuleDigest,
		PlanDigest: mapping.PlanDigest, ReasonDigest: mapping.ReasonDigest, OutputMediaType: derived.Artifact.MediaType,
		OutputClassification: derived.Artifact.Classification, KeyProfile: "operator_evidence",
		KeyProfileDigest: digest("key-profile"), PolicyDigest: digest("policy"), ExpectedCaseRevision: 3,
		ExpectedCustodyHead: redaction.CustodyHead{Case: scope, ChainHash: custody.GenesisHash},
		Deadline:            now.Add(time.Hour)}
	intent, _ := redaction.IntentBindingDigest(command)
	custodyReceipt := custody.Receipt{SchemaVersion: custody.ReceiptSchemaVersion,
		ContractVersion: custody.ContractVersion, RequestID: uuid("custody-request"), Case: scope,
		IdempotencyDigest: digest("custody-idempotency"), IntentDigest: digest("custody-intent"),
		DecisionDigest: digest("custody-decision"), CustodyID: uuid("custody"), Sequence: 1,
		RecordDigest: digest("custody-record"), ChainHash: digest("custody-chain"),
		AuditEventDigest: digest("custody-audit"), ProvenanceDigest: digest("custody-provenance"), CreatedAt: now}
	custodyReceipt.ReceiptDigest, _ = custody.ReceiptBindingDigest(custodyReceipt)
	record := redaction.Record{SchemaVersion: redaction.RecordSchemaVersion,
		ContractVersion: redaction.ContractVersion, RedactionID: uuid("redaction"), Case: scope, Command: command,
		IntentDigest: intent, PlanDigest: command.PlanDigest, DecisionDigest: digest("decision"),
		RevocationDigest: digest("revocation"), ApprovalUseDigest: digest("approval-use"),
		SourceVerificationDigest: digest("source-verification"), Derived: derived,
		DerivedIngestionReceiptDigest: derived.IngestionReceiptDigest, MappingReference: mappingRef,
		MappingDigest: mapping.MappingDigest, MappingIngestionReceiptDigest: mappingRef.IngestionReceiptDigest,
		CustodyReceiptDigest: custodyReceipt.ReceiptDigest, AuditEventDigest: digest("redaction-audit"),
		CreatedAt: now, PreviousProvenanceDigest: source.ManifestProvenanceDigest}
	record.ProvenanceDigest, _ = redaction.RecordProvenanceDigest(record)
	record.RecordDigest, _ = redaction.RecordBindingDigest(record)
	if redaction.ValidateRecord(record) != nil {
		t.Fatal("invalid record fixture")
	}
	redactionIdempotency, _ := redaction.IdempotencyBindingDigest(command.IdempotencyKey)
	receipt := redaction.Receipt{SchemaVersion: redaction.ReceiptSchemaVersion,
		ContractVersion: redaction.ContractVersion, RequestID: command.RequestID, Case: scope,
		IdempotencyDigest: redactionIdempotency, IntentDigest: intent, RedactionID: record.RedactionID,
		RecordDigest: record.RecordDigest, Derived: derived, MappingReference: mappingRef,
		MappingDigest: mapping.MappingDigest, CustodyReceiptDigest: record.CustodyReceiptDigest,
		AuditEventDigest: record.AuditEventDigest, ProvenanceDigest: record.ProvenanceDigest, CreatedAt: now}
	receipt.ReceiptDigest, _ = redaction.ReceiptBindingDigest(receipt)
	request := redaction.CustodyRequest{Command: command, Derived: derived, MappingDigest: mapping.MappingDigest,
		ApprovalDigest: record.ApprovalUseDigest, DecisionDigest: record.DecisionDigest,
		ExpectedHead: command.ExpectedCustodyHead, Deadline: command.Deadline}
	proof := redaction.CustodyProof{ReceiptDigest: custodyReceipt.ReceiptDigest,
		RecordDigest: custodyReceipt.RecordDigest, ChainHash: custodyReceipt.ChainHash,
		Sequence: custodyReceipt.Sequence, AuditDigest: custodyReceipt.AuditEventDigest}
	redactionReceiptDigest, mappingDigest := receipt.ReceiptDigest, mapping.MappingDigest
	evidence := evidencelifecycle.VerifiedEvidenceSet{Case: scope,
		Artifacts: []evidencelifecycle.ManifestArtifact{
			{Ordinal: 1, Role: evidencelifecycle.SourceArtifact, Reference: lifecycleRef(source)},
			{Ordinal: 2, Role: evidencelifecycle.DerivedArtifact, Reference: lifecycleRef(derived),
				ParentArtifactDigests:  []string{source.Artifact.Digest},
				ParentManifestDigests:  []string{source.Manifest.Digest},
				RedactionReceiptDigest: &redactionReceiptDigest, MappingDigest: &mappingDigest},
		}}
	return verifierFixture{scope: scope, repository: repositoryStub{receipt: receipt, record: record},
		ingestion: ingestionStub{derivedReceipt.ReceiptDigest: derivedReceipt,
			mappingReceipt.ReceiptDigest: mappingReceipt}, mapping: mapping, custody: custodyReceipt,
		request: request, proof: proof, audit: auditorStub{wantID: redaction.CompletedAuditEventID(record.RedactionID),
			wantDigest: record.AuditEventDigest, proof: redaction.AuditProof{EventDigest: record.AuditEventDigest,
				Sequence: 1, ChainHash: digest("audit-chain")}}, evidence: evidence}
}

func ingestionReceipt(reference redaction.EvidenceReference, scope domain.CaseRef,
	now time.Time, seed string) evidenceingest.Receipt {
	published := func(value domain.ArtifactRef, suffix string) evidenceingest.PublishedObject {
		return evidenceingest.PublishedObject{Case: scope, PlaintextDigest: value.Digest,
			PlaintextLength: value.Length, CiphertextDigest: digest(seed + "-cipher-" + suffix),
			CiphertextLength: value.Length + 64, EncryptionFormat: evidenceingest.EncryptionFormatVersion,
			EncryptionContextDigest: digest(seed + "-context-" + suffix),
			LocatorDigest:           digest(seed + "-locator-" + suffix)}
	}
	value := evidenceingest.Receipt{SchemaVersion: evidenceingest.ReceiptSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, RequestID: uuid(seed + "-request"), Case: scope,
		ActorID: uuid(seed + "-actor"), ActorRevision: 1, IntentDigest: digest(seed + "-intent"),
		IdempotencyDigest: digest(seed + "-idempotency"), AuthorizationDigest: digest(seed + "-authorization"),
		DecisionDigest: digest(seed + "-decision"), RevocationDigest: digest(seed + "-revocation"),
		TransportDigest: digest(seed + "-transport"), Artifact: reference.Artifact, Manifest: reference.Manifest,
		EncryptedArtifact:        published(reference.Artifact, "artifact"),
		EncryptedManifest:        published(reference.Manifest, "manifest"),
		ManifestProvenanceDigest: reference.ManifestProvenanceDigest,
		AuditEventDigest:         digest(seed + "-audit"), CreatedAt: now}
	value.ReceiptDigest, _ = evidenceingest.ReceiptBindingDigest(value)
	return value
}

func evidenceRef(seed, mediaType, classification string, length int64) redaction.EvidenceReference {
	return redaction.EvidenceReference{Artifact: domain.ArtifactRef{Digest: digest(seed + "-artifact"),
		MediaType: mediaType, Classification: classification, Length: length},
		Manifest: domain.ArtifactRef{Digest: digest(seed + "-manifest"),
			MediaType: "application/vnd.coh.artifact-manifest+json", Classification: classification, Length: 256},
		ManifestProvenanceDigest: digest(seed + "-provenance"),
		IngestionReceiptDigest:   digest(seed + "-receipt")}
}

func lifecycleRef(value redaction.EvidenceReference) evidencelifecycle.EvidenceReference {
	return evidencelifecycle.EvidenceReference{Artifact: value.Artifact, Manifest: value.Manifest,
		ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		IngestionReceiptDigest:   value.IngestionReceiptDigest}
}

func digest(value string) string { return rawDigest([]byte(value)) }

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func uuid(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
