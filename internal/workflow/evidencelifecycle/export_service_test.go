package evidencelifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func TestExportServiceWithholdsReleaseUntilEveryProofAndCommit(t *testing.T) {
	rig := newExportRig(t)
	result, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReleaseReference == nil || *result.ReleaseReference != "quarantine.export.1" || result.Replayed {
		t.Fatalf("unexpected result: %+v", result)
	}
	want := []string{"recover", "case.load", "case.hold", "evidence", "redaction", "custody.head",
		"custody.verify", "authority", "store.planned", "custody.authorized", "custody.verify", "store.authorized",
		"sign", "signature.verify", "package.build", "package.verify", "store.packaged",
		"custody.completed", "custody.verify", "store.custodied", "case.export", "case.resolve", "store.case_recorded",
		"audit.append", "audit.verify", "store.commit"}
	if !reflect.DeepEqual(rig.calls, want) {
		t.Fatalf("calls=%v\nwant=%v", rig.calls, want)
	}
	if ValidateReceipt(result.Receipt) != nil {
		t.Fatal("returned receipt is invalid")
	}
}

func TestExportServiceFailsClosedAtConsequentialBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*exportRig)
		absent string
	}{
		{"signer", func(rig *exportRig) { rig.signer.err = errors.New("signer unavailable") }, "package.build"},
		{"package verification", func(rig *exportRig) { rig.packages.verifyErr = errors.New("package invalid") }, "custody.completed"},
		{"custody completion", func(rig *exportRig) { rig.custody.failPhase = Completed }, "case.export"},
		{"case lifecycle", func(rig *exportRig) { rig.lifecycle.err = errors.New("case unavailable") }, "store.commit"},
		{"final audit", func(rig *exportRig) { rig.auditor.appendErr = errors.New("audit unavailable") }, "store.commit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newExportRig(t)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command)
			if err == nil || result.ReleaseReference != nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if containsCall(rig.calls, test.absent) {
				t.Fatalf("%s called after failure: %v", test.absent, rig.calls)
			}
		})
	}
}

type exportRig struct {
	service   *ExportService
	command   Command
	calls     []string
	signer    *exportSigner
	packages  *exportPackages
	custody   *exportCustody
	lifecycle *exportLifecycle
	auditor   *exportAuditor
}

func newExportRig(t *testing.T) *exportRig {
	t.Helper()
	rig := &exportRig{}
	now := lifecycleTestNow
	manifest := validExportManifest(t)
	command := validLifecycleCommand(Export)
	command.ArtifactSetDigest = &manifest.ArtifactSetDigest
	last := now.Add(-time.Minute)
	command.ExpectedCustodyHead = CustodyHead{Case: command.Case, Sequence: 5,
		ChainHash: lifecycleDigest("custody-head"), LastRecordAt: &last}
	evidence := VerifiedEvidenceSet{Case: command.Case, Artifacts: manifest.Artifacts, Components: manifest.Components,
		ArtifactSetDigest: manifest.ArtifactSetDigest, LineageDigest: lifecycleDigest("lineage")}
	evidence.ComponentSetDigest, _ = ComponentSetBindingDigest(evidence.Components)
	cases := &exportCases{calls: &rig.calls, snapshot: CaseSnapshot{Case: command.Case, State: "open",
		Classification: "restricted", Revision: command.ExpectedCaseRevision, RetainUntil: now.Add(-time.Hour),
		ProvenanceDigest: lifecycleDigest("case-provenance")}}
	authority := &exportAuthority{calls: &rig.calls, now: now}
	rig.custody = &exportCustody{calls: &rig.calls, head: command.ExpectedCustodyHead, now: now}
	rig.lifecycle = &exportLifecycle{calls: &rig.calls, cases: cases}
	rig.signer = &exportSigner{calls: &rig.calls}
	verifier := &exportSignatureVerifier{calls: &rig.calls}
	rig.packages = &exportPackages{calls: &rig.calls}
	store := &exportStore{calls: &rig.calls}
	rig.auditor = &exportAuditor{calls: &rig.calls}
	service, err := NewExportService(authority, cases, rig.lifecycle,
		exportEvidence{calls: &rig.calls, value: evidence}, exportRedactions{calls: &rig.calls},
		rig.custody, rig.signer, verifier, rig.packages, store, rig.auditor, exportClock{now},
		SigningProfile{KeyID: "evidence.primary", KeyRevision: 3,
			TrustSnapshotDigest: lifecycleDigest("signing-trust"),
			KeyRevocationDigest: lifecycleDigest("signing-revocation"), Validity: 20 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	rig.service, rig.command = service, command
	return rig
}

type exportClock struct{ now time.Time }

func (clock exportClock) Now() time.Time { return clock.now }

type exportAuthority struct {
	calls *[]string
	now   time.Time
}

func (stub *exportAuthority) AuthorizeEvidenceLifecycle(_ context.Context, request AuthorizationRequest) (Decision, error) {
	*stub.calls = append(*stub.calls, "authority")
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: lifecycleUUID("export-decision"), AuthorizationDigest: request.AuthorizationDigest,
		IntentDigest: request.IntentDigest, Operation: Export, Case: request.Command.Case,
		ActorID: request.Command.ActorID, ActorRevision: request.Command.ActorRevision,
		ArtifactSetDigest: request.ArtifactSetDigest, PolicyDigest: request.Command.PolicyDigest,
		ApprovalDigest: request.Command.ApprovalDigest, RevocationDigest: lifecycleDigest("revocation"),
		ExpectedCaseRevision: request.CaseRevision, ExpectedCustodyHead: request.CurrentCustodyHead,
		Outcome: Allow, ReasonCode: ReasonAuthorized, IssuedAt: stub.now,
		ExpiresAt: stub.now.Add(30 * time.Minute), Revision: 1}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

type exportCases struct {
	calls    *[]string
	snapshot CaseSnapshot
	proof    LifecycleProof
}

func (stub *exportCases) LoadCase(context.Context, domain.CaseRef) (CaseSnapshot, bool, error) {
	*stub.calls = append(*stub.calls, "case.load")
	return stub.snapshot, true, nil
}
func (stub *exportCases) ResolveLifecycleReceipt(context.Context, domain.CaseRef, string) (LifecycleProof, bool, error) {
	*stub.calls = append(*stub.calls, "case.resolve")
	return stub.proof, true, nil
}
func (stub *exportCases) HasIncompleteHoldRelease(context.Context, domain.CaseRef) (bool, error) {
	*stub.calls = append(*stub.calls, "case.hold")
	return false, nil
}

type exportLifecycle struct {
	calls *[]string
	err   error
	cases *exportCases
}

func (stub *exportLifecycle) ApplyCaseOperation(_ context.Context, request LifecycleRequest) (LifecycleProof, error) {
	*stub.calls = append(*stub.calls, "case.export")
	if stub.err != nil {
		return LifecycleProof{}, stub.err
	}
	proof := LifecycleProof{Operation: Export, Case: request.Case, Revision: request.ExpectedCaseRevision + 1,
		ReceiptDigest: lifecycleDigest("lifecycle-receipt"), ProvenanceDigest: lifecycleDigest("lifecycle-provenance")}
	stub.cases.proof = proof
	return proof, nil
}

type exportEvidence struct {
	calls *[]string
	value VerifiedEvidenceSet
}

func (stub exportEvidence) ResolveEvidenceSet(context.Context, domain.CaseRef, string) (VerifiedEvidenceSet, error) {
	*stub.calls = append(*stub.calls, "evidence")
	return stub.value, nil
}

type exportRedactions struct{ calls *[]string }

func (stub exportRedactions) VerifyRedactionReceipts(context.Context, domain.CaseRef, VerifiedEvidenceSet) ([]RedactionProof, error) {
	*stub.calls = append(*stub.calls, "redaction")
	return []RedactionProof{}, nil
}

type exportCustody struct {
	calls     *[]string
	head      CustodyHead
	now       time.Time
	failPhase Phase
}

func (stub *exportCustody) LoadCustodyHead(context.Context, domain.CaseRef) (CustodyHead, error) {
	*stub.calls = append(*stub.calls, "custody.head")
	return stub.head, nil
}
func (stub *exportCustody) VerifyLifecycle(_ context.Context, scope domain.CaseRef, from, to uint64) (CustodyVerification, error) {
	*stub.calls = append(*stub.calls, "custody.verify")
	return CustodyVerification{FromSequence: from, ToSequence: to, Head: stub.head,
		CheckpointID: lifecycleUUID("checkpoint"), CheckpointDigest: lifecycleDigest("checkpoint"),
		CheckpointSequence: to, CheckpointSigningKeyRevision: 2,
		CheckpointProofDigest: lifecycleDigest("checkpoint-proof"), ReportDigest: lifecycleDigest("custody-report")}, nil
}
func (stub *exportCustody) RecordLifecycle(_ context.Context, request CustodyRequest) (CustodyProof, error) {
	label := "custody." + string(request.Phase)
	*stub.calls = append(*stub.calls, label)
	if stub.failPhase == request.Phase {
		return CustodyProof{}, errors.New("custody unavailable")
	}
	last := stub.now
	head := CustodyHead{Case: request.Case, Sequence: request.ExpectedHead.Sequence + 1,
		ChainHash: lifecycleDigest(label + ".head"), LastRecordAt: &last}
	stub.head = head
	return CustodyProof{ReceiptDigest: lifecycleDigest(label + ".receipt"),
		RecordDigest: lifecycleDigest(label + ".record"), AuditDigest: lifecycleDigest(label + ".audit"), Head: head}, nil
}

type exportSigner struct {
	calls *[]string
	err   error
}

func (stub *exportSigner) SignManifest(_ context.Context, request SignRequest) (DetachedSignature, error) {
	*stub.calls = append(*stub.calls, "sign")
	if stub.err != nil {
		return DetachedSignature{}, stub.err
	}
	return validDetachedSignature(request.ManifestDigest), nil
}

type exportSignatureVerifier struct{ calls *[]string }

func (stub *exportSignatureVerifier) VerifyDetachedSignature(context.Context, VerifySignatureRequest) error {
	*stub.calls = append(*stub.calls, "signature.verify")
	return nil
}

type exportPackages struct {
	calls     *[]string
	verifyErr error
	value     QuarantinedPackage
}

func (stub *exportPackages) BuildPackage(_ context.Context, request PackageBuildRequest) (QuarantinedPackage, error) {
	*stub.calls = append(*stub.calls, "package.build")
	header := PackageHeader{SchemaVersion: PackageHeaderSchemaVersion, ContractVersion: ContractVersion,
		Magic: PackageMagic, PackageVersion: PackageVersion, Compression: NoCompression,
		ManifestLength: 4096, SignatureLength: 256, ArtifactCount: uint16(len(request.Manifest.Artifacts)), PackageLength: 8192}
	header.HeaderDigest, _ = HeaderBindingDigest(header)
	signatureDigest, _ := SignatureBindingDigest(request.Signature)
	stub.value = QuarantinedPackage{Reference: "quarantine.export.1", Header: header,
		HeaderDigest: header.HeaderDigest, PackageDigest: lifecycleDigest("export-package"), PackageLength: header.PackageLength,
		ManifestDigest: request.Manifest.ManifestDigest, SignatureDigest: signatureDigest}
	return stub.value, nil
}
func (stub *exportPackages) VerifyPackage(context.Context, QuarantinedPackage, PackageLimits) error {
	*stub.calls = append(*stub.calls, "package.verify")
	return stub.verifyErr
}
func (stub *exportPackages) RecoverPackage(context.Context, domain.CaseRef, string) (QuarantinedPackage, bool, error) {
	return stub.value, true, nil
}

type exportStore struct{ calls *[]string }

func (stub *exportStore) Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error) {
	*stub.calls = append(*stub.calls, "recover")
	return Receipt{}, false, nil
}
func (*exportStore) LoadProgress(context.Context, domain.CaseRef, string) (Progress, bool, error) {
	return Progress{}, false, nil
}
func (stub *exportStore) Advance(_ context.Context, _ string, _ string, value Progress) (Progress, bool, error) {
	*stub.calls = append(*stub.calls, "store."+string(value.Phase))
	return value, false, nil
}
func (stub *exportStore) Commit(_ context.Context, _, _ string, progress Progress, record Record,
	receipt Receipt) (Receipt, bool, error) {
	*stub.calls = append(*stub.calls, "store.commit")
	if ValidateProgress(progress) != nil || ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil {
		return Receipt{}, false, errors.New("invalid commit")
	}
	return receipt, false, nil
}

type exportAuditor struct {
	calls     *[]string
	appendErr error
}

func (stub *exportAuditor) AppendLifecycleEvent(context.Context, tamperaudit.Event) error {
	*stub.calls = append(*stub.calls, "audit.append")
	return stub.appendErr
}
func (stub *exportAuditor) VerifyLifecycleEvent(context.Context, domain.CaseRef, string, string) error {
	*stub.calls = append(*stub.calls, "audit.verify")
	return nil
}

func containsCall(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
