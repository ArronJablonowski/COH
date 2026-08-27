package evidencelifecycle

import (
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var lifecycleTestNow = time.Date(2026, 8, 27, 3, 0, 0, 0, time.UTC)

func TestCommandValidationClosesOperationFieldsAndBounds(t *testing.T) {
	base := validLifecycleCommand(Export)
	if err := ValidateCommand(base, lifecycleTestNow); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []Operation{Import, PlaceHold, ReleaseHold, Delete} {
		command := validLifecycleCommand(operation)
		if err := ValidateCommand(command, lifecycleTestNow); err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	}
	for name, mutate := range map[string]func(*Command){
		"expired":       func(value *Command) { value.Deadline = lifecycleTestNow },
		"changed scope": func(value *Command) { value.ExpectedCustodyHead.Case.CaseID = lifecycleUUID("other") },
		"bad limit":     func(value *Command) { value.Limits.MaximumArtifacts = 0 },
		"raw package":   func(value *Command) { value.PackageDigest = pointerDigest("unexpected") },
		"missing actor": func(value *Command) { value.ActorID = "" },
	} {
		candidate := base
		mutate(&candidate)
		if err := ValidateCommand(candidate, lifecycleTestNow); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestManifestHeaderSignatureAndVerificationBindingsRejectMutation(t *testing.T) {
	manifest := validExportManifest(t)
	if err := ValidateExportManifest(manifest); err != nil {
		t.Fatal(err)
	}
	mutated := manifest
	mutated.DestinationDigest = lifecycleDigest("substituted")
	if err := ValidateExportManifest(mutated); CodeOf(err) != Denied {
		t.Fatalf("manifest mutation code=%s err=%v", CodeOf(err), err)
	}

	signature := validDetachedSignature(manifest.ManifestDigest)
	if err := ValidateDetachedSignature(signature); err != nil {
		t.Fatal(err)
	}
	signature.Algorithm = "rsa"
	if err := ValidateDetachedSignature(signature); err == nil {
		t.Fatal("unknown signature algorithm accepted")
	}

	header := validPackageHeader(t)
	if err := ValidatePackageHeader(header); err != nil {
		t.Fatal(err)
	}
	header.Compression = "gzip"
	if err := ValidatePackageHeader(header); err == nil {
		t.Fatal("compressed package accepted")
	}

	verification := validImportVerification(t)
	if err := ValidateImportVerification(verification); err != nil {
		t.Fatal(err)
	}
	verification.Outcome = VerificationIncomplete
	if err := ValidateImportVerification(verification); err == nil {
		t.Fatal("incomplete report with success reason accepted")
	}
}

func TestAuthorizationDecisionProgressAndFinalRecordsAreDigestBound(t *testing.T) {
	command := validLifecycleCommand(Export)
	intent, err := IntentBindingDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	authorization := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: command, CaseState: "open", CaseClassification: "restricted",
		CaseRevision: command.ExpectedCaseRevision, RetainUntil: lifecycleTestNow.Add(-time.Hour),
		CaseProvenanceDigest: lifecycleDigest("case-provenance"), ArtifactSetDigest: command.ArtifactSetDigest,
		CurrentCustodyHead: command.ExpectedCustodyHead}
	authorization.AuthorizationDigest, err = AuthorizationBindingDigest(authorization)
	if err != nil || ValidateAuthorization(authorization) != nil {
		t.Fatalf("authorization: digest=%v validate=%v", err, ValidateAuthorization(authorization))
	}

	decision := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: lifecycleUUID("decision"), AuthorizationDigest: authorization.AuthorizationDigest,
		IntentDigest: intent, Operation: Export, Case: command.Case, ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, ArtifactSetDigest: command.ArtifactSetDigest,
		PolicyDigest: command.PolicyDigest, ApprovalDigest: command.ApprovalDigest,
		RevocationDigest: lifecycleDigest("revocation"), ExpectedCaseRevision: command.ExpectedCaseRevision,
		ExpectedCustodyHead: command.ExpectedCustodyHead, Outcome: Allow, ReasonCode: ReasonAuthorized,
		IssuedAt: lifecycleTestNow, ExpiresAt: lifecycleTestNow.Add(time.Minute), Revision: 1}
	decision.DecisionDigest, err = DecisionBindingDigest(decision)
	if err != nil || ValidateDecision(decision) != nil {
		t.Fatalf("decision: digest=%v validate=%v", err, ValidateDecision(decision))
	}

	progress := Progress{SchemaVersion: ProgressSchemaVersion, ContractVersion: ContractVersion,
		OperationID: lifecycleUUID("operation"), Case: command.Case, Operation: Export, Phase: Planned,
		CommandDigest: lifecycleDigest("command"), IntentDigest: intent, UpdatedAt: lifecycleTestNow, Revision: 1}
	progress.ProgressDigest, err = ProgressBindingDigest(progress)
	if err != nil || ValidateProgress(progress) != nil {
		t.Fatalf("progress: digest=%v validate=%v", err, ValidateProgress(progress))
	}
	progress.Phase = Completed
	if err := ValidateProgress(progress); err == nil {
		t.Fatal("completed progress without required ancestry accepted")
	}

	record, receipt := validFinalExport(t, command, intent, decision.DecisionDigest)
	if err := ValidateRecord(record); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	receipt.RecordDigest = lifecycleDigest("other-record")
	if err := ValidateReceipt(receipt); CodeOf(err) != Denied {
		t.Fatalf("receipt mutation code=%s err=%v", CodeOf(err), err)
	}
}

func TestDispositionAttestationBindsOrderedVerifiedObjects(t *testing.T) {
	value := DispositionAttestation{SchemaVersion: DispositionAttestationSchemaVersion,
		ContractVersion: ContractVersion, AttestationID: lifecycleUUID("attestation"),
		Case: lifecycleCase(), OperationID: lifecycleUUID("operation"), ArtifactSetDigest: lifecycleDigest("set"),
		AuthorizationCustodyReceiptDigest: lifecycleDigest("authorize"),
		LifecycleReceiptDigest:            lifecycleDigest("lifecycle"), Mechanism: "encrypted_object_removal",
		Objects: []DispositionObject{{Ordinal: 1, ArtifactDigest: lifecycleDigest("artifact-a"),
			EncryptedObjectDigest: lifecycleDigest("encrypted-a"), KeyRevision: 2,
			Outcome: DispositionRemoved, OutcomeDigest: lifecycleDigest("outcome-a")}},
		AttemptedAt: lifecycleTestNow, CompletedAt: lifecycleTestNow.Add(time.Second)}
	var err error
	value.AttestationDigest, err = DispositionBindingDigest(value)
	if err != nil || ValidateDispositionAttestation(value) != nil {
		t.Fatalf("attestation: digest=%v validate=%v", err, ValidateDispositionAttestation(value))
	}
	value.Objects[0].KeyRevision++
	if err := ValidateDispositionAttestation(value); CodeOf(err) != Denied {
		t.Fatalf("attestation mutation code=%s err=%v", CodeOf(err), err)
	}
}

func validLifecycleCommand(operation Operation) Command {
	command := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		RequestID: lifecycleUUID("request-" + string(operation)), IdempotencyKey: "idempotency-" + string(operation),
		Operation: operation, Case: lifecycleCase(), ActorID: lifecycleUUID("actor"), ActorRevision: 3,
		PolicyDigest: lifecycleDigest("policy"), ExpectedCaseRevision: 7,
		ExpectedCustodyHead: CustodyHead{Case: lifecycleCase(), ChainHash: genesisHash},
		Limits: PackageLimits{MaximumManifestBytes: 1 << 20, MaximumSignatureBytes: 512,
			MaximumArtifacts: 16, MaximumArtifactBytes: 1 << 30, MaximumPackageBytes: 2 << 30},
		Deadline: lifecycleTestNow.Add(time.Hour)}
	switch operation {
	case Export:
		command.ArtifactSetDigest, command.PurposeDigest = pointerDigest("set"), pointerDigest("purpose")
		command.DestinationDigest, command.ApprovalDigest = pointerDigest("destination"), pointerDigest("approval")
	case Import:
		command.PackageDigest, command.SourceDigest = pointerDigest("package"), pointerDigest("source")
	case PlaceHold, ReleaseHold:
		command.ArtifactSetDigest, command.ReasonDigest = pointerDigest("set"), pointerDigest("reason")
	case Delete:
		command.ArtifactSetDigest, command.ReasonDigest = pointerDigest("set"), pointerDigest("reason")
		command.ApprovalDigest = pointerDigest("approval")
	}
	return command
}

func validExportManifest(t *testing.T) ExportManifest {
	t.Helper()
	artifact := domain.ArtifactRef{Digest: lifecycleDigest("artifact"), MediaType: "application/json",
		Classification: "restricted", Length: 128}
	manifestRef := domain.ArtifactRef{Digest: lifecycleDigest("artifact-manifest"),
		MediaType: "application/vnd.coh.artifact-manifest+json", Classification: "restricted", Length: 256}
	value := ExportManifest{SchemaVersion: ExportManifestSchemaVersion, ContractVersion: ContractVersion,
		ManifestID: lifecycleUUID("manifest"), PackageVersion: PackageVersion, Case: lifecycleCase(), CaseRevision: 7,
		Classification: "restricted", ActorID: lifecycleUUID("actor"), ActorRevision: 3,
		PurposeDigest: lifecycleDigest("purpose"), DestinationDigest: lifecycleDigest("destination"),
		Artifacts: []ManifestArtifact{{Ordinal: 1, Role: SourceArtifact,
			Reference: EvidenceReference{Artifact: artifact, Manifest: manifestRef,
				ManifestProvenanceDigest: lifecycleDigest("manifest-provenance"),
				IngestionReceiptDigest:   lifecycleDigest("ingestion")}, ParentArtifactDigests: []string{},
			ParentManifestDigests: []string{}}},
		Components:   []Component{{Kind: "policy", Name: "tenant.policy", Version: "1.0.0", Digest: lifecycleDigest("component")}},
		PolicyDigest: lifecycleDigest("policy"), DecisionDigest: lifecycleDigest("decision"),
		ApprovalDigest: lifecycleDigest("approval"), RevocationDigest: lifecycleDigest("revocation"),
		CustodyFromSequence: 1, CustodyToSequence: 2, CustodyReportDigest: lifecycleDigest("custody-report"),
		AuditCheckpointID: lifecycleUUID("checkpoint"), AuditCheckpointDigest: lifecycleDigest("checkpoint-digest"),
		AuditCheckpointSequence: 5, AuditSigningKeyRevision: 2, AuditProofDigest: lifecycleDigest("audit-proof"),
		SigningAlgorithm: SigningAlgorithm, SigningKeyID: "evidence.primary", SigningKeyRevision: 3,
		SigningTrustSnapshotDigest: lifecycleDigest("signing-trust"),
		SigningKeyRevocationDigest: lifecycleDigest("signing-revocation"),
		Compression:                NoCompression, Limits: validLifecycleCommand(Export).Limits, CreatedAt: lifecycleTestNow,
		ValidUntil: lifecycleTestNow.Add(time.Hour), IdempotencyDigest: lifecycleDigest("idempotency"),
		PreviousProvenanceDigest: lifecycleDigest("previous")}
	var err error
	value.ArtifactSetDigest, err = ArtifactSetBindingDigest(value.Artifacts)
	if err != nil {
		t.Fatal(err)
	}
	value.ManifestDigest, err = ManifestBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func validDetachedSignature(manifestDigest string) DetachedSignature {
	return DetachedSignature{SchemaVersion: DetachedSignatureSchemaVersion, ContractVersion: ContractVersion,
		Algorithm: SigningAlgorithm, KeyID: "evidence.primary", KeyRevision: 3,
		ManifestDigest: manifestDigest, Signature: strings.Repeat("A", 86)}
}

func validPackageHeader(t *testing.T) PackageHeader {
	t.Helper()
	value := PackageHeader{SchemaVersion: PackageHeaderSchemaVersion, ContractVersion: ContractVersion,
		Magic: PackageMagic, PackageVersion: PackageVersion, Compression: NoCompression,
		ManifestLength: 4096, SignatureLength: 256, ArtifactCount: 1, PackageLength: 8192}
	var err error
	value.HeaderDigest, err = HeaderBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func validImportVerification(t *testing.T) ImportVerification {
	t.Helper()
	value := ImportVerification{SchemaVersion: ImportVerificationSchemaVersion, ContractVersion: ContractVersion,
		VerificationID: lifecycleUUID("verification"), SourceDigest: lifecycleDigest("source"),
		PackageDigest: lifecycleDigest("package"), HeaderDigest: lifecycleDigest("header"),
		ManifestDigest: lifecycleDigest("manifest"), SignatureDigest: lifecycleDigest("signature"),
		SigningKeyID: "evidence.primary", SigningKeyRevision: 3, TrustSnapshotDigest: lifecycleDigest("trust"),
		RevocationDigest: lifecycleDigest("revocation"), ArtifactSetDigest: lifecycleDigest("set"),
		LineageDigest: lifecycleDigest("lineage"), ComponentSetDigest: lifecycleDigest("components"),
		CustodyReportDigest: lifecycleDigest("custody"), AuditCheckpointDigest: lifecycleDigest("checkpoint"),
		Outcome: VerificationValid, ReasonCode: VerifySuccess, VerifiedAt: lifecycleTestNow}
	var err error
	value.ReportDigest, err = VerificationBindingDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func validFinalExport(t *testing.T, command Command, intent, decision string) (Record, Receipt) {
	t.Helper()
	packageDigest, manifestDigest, signatureDigest := lifecycleDigest("package"), lifecycleDigest("manifest"), lifecycleDigest("signature")
	lifecycleReceipt, authorizedCustody := lifecycleDigest("lifecycle"), lifecycleDigest("authorized-custody")
	completedCustody := lifecycleDigest("completed-custody")
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		OperationID: lifecycleUUID("operation"), Case: command.Case, Operation: Export,
		CommandDigest: lifecycleDigest("command"), IntentDigest: intent, DecisionDigest: decision,
		RevocationDigest: lifecycleDigest("revocation"), ArtifactSetDigest: command.ArtifactSetDigest,
		PackageDigest: &packageDigest, ManifestDigest: &manifestDigest, SignatureDigest: &signatureDigest,
		LifecycleReceiptDigest: &lifecycleReceipt, AuthorizationCustodyReceiptDigest: &authorizedCustody,
		CompletionCustodyReceiptDigest: &completedCustody, AuditEventDigest: lifecycleDigest("audit"),
		CompletedAt: lifecycleTestNow, PreviousProvenanceDigest: lifecycleDigest("previous")}
	var err error
	record.ProvenanceDigest, err = RecordProvenanceDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordDigest, err = RecordBindingDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: command.RequestID, OperationID: record.OperationID, Case: command.Case, Operation: Export,
		IdempotencyDigest: lifecycleDigest("idempotency"), IntentDigest: intent, DecisionDigest: decision,
		RecordDigest: record.RecordDigest, ArtifactSetDigest: command.ArtifactSetDigest, PackageDigest: &packageDigest,
		ManifestDigest: &manifestDigest, SignatureDigest: &signatureDigest, LifecycleReceiptDigest: &lifecycleReceipt,
		CompletionCustodyReceiptDigest: &completedCustody, AuditEventDigest: record.AuditEventDigest,
		ProvenanceDigest: record.ProvenanceDigest, CreatedAt: lifecycleTestNow}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return record, receipt
}

func lifecycleCase() domain.CaseRef {
	return domain.CaseRef{OrganizationID: lifecycleUUID("organization"), TenantID: lifecycleUUID("tenant"),
		CaseID: lifecycleUUID("case")}
}

func pointerDigest(value string) *string {
	digestValue := lifecycleDigest(value)
	return &digestValue
}

func lifecycleDigest(value string) string { return digest("TEST\x00", []byte(value)) }

func lifecycleUUID(value string) string {
	hexValue := strings.TrimPrefix(lifecycleDigest(value), "sha256:")[:32]
	return hexValue[:8] + "-" + hexValue[8:12] + "-7" + hexValue[13:16] + "-8" + hexValue[17:20] + "-" + hexValue[20:32]
}
