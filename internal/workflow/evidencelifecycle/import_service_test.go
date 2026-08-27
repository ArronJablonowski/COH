package evidencelifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestImportServiceWithholdsReferencesUntilCustodyAuditAndCommit(t *testing.T) {
	rig := newImportRig(t)
	result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 1 || result.Replayed || ValidateReceipt(result.Receipt) != nil {
		t.Fatalf("unexpected result: %+v", result)
	}
	want := []string{"recover", "package.verify", "progress.load", "store.quarantined", "store.verified", "case.load", "case.hold",
		"custody.head", "authority", "store.authorized", "publish", "store.published", "custody.completed",
		"custody.verify", "store.custodied", "audit.append", "audit.verify", "store.commit"}
	if !reflect.DeepEqual(rig.calls, want) {
		t.Fatalf("calls=%v\nwant=%v", rig.calls, want)
	}
}

func TestImportServiceFailsClosedAtEveryConsequentialBoundary(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*importRig)
		absent string
	}{
		{"verification", func(rig *importRig) { rig.reader.err = errors.New("verification unavailable") }, "store.quarantined"},
		{"authority", func(rig *importRig) { rig.authority.err = errors.New("authority unavailable") }, "publish"},
		{"publication", func(rig *importRig) { rig.publisher.err = errors.New("publication unavailable") }, "custody.completed"},
		{"custody", func(rig *importRig) { rig.custody.failPhase = Completed }, "store.commit"},
		{"audit", func(rig *importRig) { rig.auditor.appendErr = errors.New("audit unavailable") }, "store.commit"},
		{"commit", func(rig *importRig) { rig.store.commitErr = errors.New("commit unavailable") }, "result"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newImportRig(t)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
			if err == nil || len(result.Imported) != 0 {
				t.Fatalf("partial references escaped: result=%+v err=%v", result, err)
			}
			if test.absent != "result" && containsCall(rig.calls, test.absent) {
				t.Fatalf("%s called after failure: %v", test.absent, rig.calls)
			}
		})
	}
}

func TestImportServiceRejectsSubstitutedVerificationBeforeAuthorization(t *testing.T) {
	rig := newImportRig(t)
	rig.reader.value.Verification.PackageDigest = lifecycleDigest("substituted")
	result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
	if err == nil || len(result.Imported) != 0 || containsCall(rig.calls, "authority") ||
		containsCall(rig.calls, "store.quarantined") {
		t.Fatalf("substitution crossed boundary: calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}

func TestImportServiceExactReplayReturnsOnlyCommittedReferences(t *testing.T) {
	rig := newImportRig(t)
	first, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
	if err != nil {
		t.Fatal(err)
	}
	rig.calls = nil
	second, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || !sameEvidenceReferences(first.Imported, second.Imported) ||
		containsCall(rig.calls, "package.verify") || containsCall(rig.calls, "publish") ||
		containsCall(rig.calls, "custody.completed") {
		t.Fatalf("unexpected replay: calls=%v result=%+v", rig.calls, second)
	}
	want := []string{"recover", "case.load", "case.hold", "custody.head", "authority", "audit.verify"}
	if !reflect.DeepEqual(rig.calls, want) {
		t.Fatalf("calls=%v want=%v", rig.calls, want)
	}
}

func TestImportServiceResumesExactPublishedProgress(t *testing.T) {
	rig := newImportRig(t)
	rig.custody.failPhase = Completed
	if result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1"); err == nil || len(result.Imported) != 0 || rig.store.progress.Phase != Published {
		t.Fatalf("first result=%+v err=%v phase=%s", result, err, rig.store.progress.Phase)
	}
	rig.custody.failPhase, rig.calls = "", nil
	result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
	if err != nil || len(result.Imported) != 1 || !result.Replayed && result.Receipt.ReceiptDigest == "" {
		t.Fatalf("recovery result=%+v err=%v", result, err)
	}
	for _, forbidden := range []string{"store.quarantined", "store.verified", "store.authorized", "store.published"} {
		if containsCall(rig.calls, forbidden) {
			t.Fatalf("recovery repeated %s: %v", forbidden, rig.calls)
		}
	}
}

func TestImportServiceRecoversExactCustodyBeforeCommit(t *testing.T) {
	rig := newImportRig(t)
	rig.auditor.appendErr = errors.New("audit unavailable")
	if result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1"); err == nil || len(result.Imported) != 0 || rig.store.progress.Phase != Custodied {
		t.Fatalf("first result=%+v err=%v phase=%s", result, err, rig.store.progress.Phase)
	}
	rig.auditor.appendErr, rig.calls = nil, nil
	result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
	if err != nil || len(result.Imported) != 1 || !containsCall(rig.calls, "custody.recover") ||
		containsCall(rig.calls, "custody.completed") {
		t.Fatalf("recovery calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}

func TestImportServiceCancellationAndTimeoutReleaseNoReferences(t *testing.T) {
	for _, test := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		code ErrorCode
	}{
		{"canceled", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx, func() {}
		}, Canceled},
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		}, Timeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newImportRig(t)
			rig.reader.observeContext = true
			ctx, cancel := test.ctx()
			defer cancel()
			result, err := rig.service.Execute(ctx, rig.command, "quarantine.import.1")
			if CodeOf(err) != test.code || len(result.Imported) != 0 || containsCall(rig.calls, "publish") {
				t.Fatalf("code=%s calls=%v result=%+v err=%v", CodeOf(err), rig.calls, result, err)
			}
		})
	}
}

func TestImportServiceDeniesPendingHoldAndClassificationEscalation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*importRig)
	}{
		{"pending hold release", func(rig *importRig) { rig.cases.pending = true }},
		{"classification escalation", func(rig *importRig) { rig.cases.snapshot.Classification = "confidential" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newImportRig(t)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
			if err == nil || len(result.Imported) != 0 || containsCall(rig.calls, "authority") ||
				containsCall(rig.calls, "publish") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestImportServiceDeniesChangedCompletedReplay(t *testing.T) {
	rig := newImportRig(t)
	if _, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1"); err != nil {
		t.Fatal(err)
	}
	rig.calls = nil
	changed := rig.command
	changed.SourceDigest = pointerDigest("changed-source")
	result, err := rig.service.Execute(t.Context(), changed, "quarantine.import.1")
	if CodeOf(err) != Denied || Reason(err) != string(ReasonChangedReplay) || len(result.Imported) != 0 ||
		containsCall(rig.calls, "package.verify") || containsCall(rig.calls, "publish") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}

type importRig struct {
	service   *ImportService
	command   Command
	calls     []string
	reader    *importReader
	authority *importAuthority
	publisher *importPublisher
	custody   *exportCustody
	auditor   *exportAuditor
	store     *importStore
	cases     *exportCases
}

func newImportRig(t *testing.T) *importRig {
	t.Helper()
	rig := &importRig{}
	now := lifecycleTestNow
	command := validLifecycleCommand(Import)
	verified := validVerifiedImportFixture(t, command, "quarantine.import.1")
	cases := &exportCases{calls: &rig.calls, snapshot: CaseSnapshot{Case: command.Case, State: "open",
		Classification: "restricted", Revision: command.ExpectedCaseRevision, RetainUntil: now.Add(-time.Hour),
		ProvenanceDigest: lifecycleDigest("case-provenance")}}
	rig.cases = cases
	rig.reader = &importReader{calls: &rig.calls, value: verified}
	rig.authority = &importAuthority{calls: &rig.calls, now: now}
	rig.publisher = &importPublisher{calls: &rig.calls, value: validPublishedFixture(verified)}
	rig.custody = &exportCustody{calls: &rig.calls, head: command.ExpectedCustodyHead, now: now}
	rig.auditor = &exportAuditor{calls: &rig.calls}
	rig.store = &importStore{calls: &rig.calls}
	service, err := NewImportService(rig.authority, cases, rig.custody, rig.reader, rig.publisher,
		rig.store, rig.auditor, exportClock{now})
	if err != nil {
		t.Fatal(err)
	}
	rig.service, rig.command = service, command
	return rig
}

type importReader struct {
	calls          *[]string
	value          VerifiedImport
	err            error
	observeContext bool
}

func (stub *importReader) VerifyImport(ctx context.Context, _ ImportRequest) (VerifiedImport, error) {
	*stub.calls = append(*stub.calls, "package.verify")
	if stub.observeContext {
		if err := ctx.Err(); err != nil {
			return VerifiedImport{}, err
		}
	}
	return stub.value, stub.err
}

type importAuthority struct {
	calls  *[]string
	now    time.Time
	err    error
	mutate func(*Decision)
}

func (stub *importAuthority) AuthorizeEvidenceLifecycle(_ context.Context,
	request AuthorizationRequest) (Decision, error) {
	*stub.calls = append(*stub.calls, "authority")
	if stub.err != nil {
		return Decision{}, stub.err
	}
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID:          lifecycleUUID("import-decision-" + request.AuthorizationDigest),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: Import, Case: request.Command.Case, ActorID: request.Command.ActorID,
		ActorRevision: request.Command.ActorRevision, ArtifactSetDigest: request.ArtifactSetDigest,
		PackageDigest: request.Command.PackageDigest, PolicyDigest: request.Command.PolicyDigest,
		RevocationDigest: lifecycleDigest("import-revocation"), ExpectedCaseRevision: request.CaseRevision,
		ExpectedCustodyHead: request.CurrentCustodyHead, Outcome: Allow, ReasonCode: ReasonAuthorized,
		IssuedAt: stub.now, ExpiresAt: stub.now.Add(30 * time.Minute), Revision: 1}
	if stub.mutate != nil {
		stub.mutate(&value)
	}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

type importPublisher struct {
	calls *[]string
	value PublishedImport
	err   error
}

func (stub *importPublisher) PublishImport(context.Context, ImportPublicationRequest) (PublishedImport, error) {
	*stub.calls = append(*stub.calls, "publish")
	return stub.value, stub.err
}

type importStore struct {
	calls     *[]string
	receipt   Receipt
	progress  Progress
	commitErr error
}

func (stub *importStore) Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error) {
	*stub.calls = append(*stub.calls, "recover")
	return stub.receipt, stub.receipt.ReceiptDigest != "", nil
}
func (stub *importStore) LoadProgress(context.Context, domain.CaseRef, string) (Progress, bool, error) {
	*stub.calls = append(*stub.calls, "progress.load")
	return stub.progress, stub.progress.ProgressDigest != "", nil
}
func (stub *importStore) Advance(_ context.Context, _, _ string, value Progress) (Progress, bool, error) {
	*stub.calls = append(*stub.calls, "store."+string(value.Phase))
	if ValidateProgress(value) != nil {
		return Progress{}, false, errors.New("invalid progress")
	}
	stub.progress = value
	return value, false, nil
}
func (stub *importStore) Commit(_ context.Context, _, _ string, progress Progress, record Record,
	receipt Receipt) (Receipt, bool, error) {
	*stub.calls = append(*stub.calls, "store.commit")
	if stub.commitErr != nil {
		return Receipt{}, false, stub.commitErr
	}
	if ValidateProgress(progress) != nil || ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil {
		return Receipt{}, false, errors.New("invalid commit")
	}
	stub.receipt = receipt
	stub.progress = progress
	return receipt, false, nil
}

func validVerifiedImportFixture(t *testing.T, command Command, reference string) VerifiedImport {
	t.Helper()
	manifest := validExportManifest(t)
	signature := validDetachedSignature(manifest.ManifestDigest)
	signatureDigest, _ := SignatureBindingDigest(signature)
	header := validPackageHeader(t)
	packageDigest := *command.PackageDigest
	lineage, _ := LineageBindingDigest(manifest.Artifacts)
	components, _ := ComponentSetBindingDigest(manifest.Components)
	verification := ImportVerification{SchemaVersion: ImportVerificationSchemaVersion, ContractVersion: ContractVersion,
		VerificationID: lifecycleUUID("import-verification"), SourceDigest: *command.SourceDigest,
		PackageDigest: packageDigest, HeaderDigest: header.HeaderDigest, ManifestDigest: manifest.ManifestDigest,
		SignatureDigest: signatureDigest, SigningKeyID: signature.KeyID, SigningKeyRevision: signature.KeyRevision,
		TrustSnapshotDigest: lifecycleDigest("local-trust"), RevocationDigest: lifecycleDigest("local-revocation"),
		ArtifactSetDigest: manifest.ArtifactSetDigest, LineageDigest: lineage, ComponentSetDigest: components,
		CustodyReportDigest: manifest.CustodyReportDigest, AuditCheckpointDigest: manifest.AuditCheckpointDigest,
		Outcome: VerificationValid, ReasonCode: VerifySuccess, VerifiedAt: lifecycleTestNow}
	verification.ReportDigest, _ = VerificationBindingDigest(verification)
	return VerifiedImport{Package: QuarantinedPackage{Reference: reference, Header: header,
		HeaderDigest: header.HeaderDigest, PackageDigest: packageDigest, PackageLength: header.PackageLength,
		ManifestDigest: manifest.ManifestDigest, SignatureDigest: signatureDigest}, Manifest: manifest,
		Signature: signature, Verification: verification,
		Staged: []StagedImportArtifact{{Ordinal: 1, ArtifactDigest: manifest.Artifacts[0].Reference.Artifact.Digest,
			Reference: "quarantine.artifact.1", VerificationDigest: lifecycleDigest("staged-verification")}}}
}

func validPublishedFixture(verified VerifiedImport) PublishedImport {
	reference := verified.Manifest.Artifacts[0].Reference
	receipt := reference.IngestionReceiptDigest
	return PublishedImport{Artifacts: []EvidenceReference{reference}, Progress: []ArtifactProgress{{Ordinal: 1,
		ArtifactDigest: reference.Artifact.Digest, IngestionReceiptDigest: &receipt}}}
}
