package sqlite_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencecatalog"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencepackage"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencesigning"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencesource"
	"github.com/ArronJablonowski/COH/internal/workflow/lifecyclecustody"
)

func TestCOHE10ComposedExportUsesImmutableEncryptedEvidenceAndDurableStores(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	backup, casRoot := filepath.Join(root, "backups"), filepath.Join(root, "encrypted-cas")
	for _, directory := range []string{backup, casRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	driver := openCaseSQLite(t, filepath.Join(root, "coh.sqlite3"), backup, now)
	defer driver.Close()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}

	caseController, caseRepository := composeCaseController(t, driver, now, &caseAuditor{})
	create := caseCreateCommand(now)
	if _, err = caseController.Execute(t.Context(), create); err != nil {
		t.Fatal(err)
	}
	lifecycleCases := composeLifecycleCaseAdapter(t, driver, caseController, caseRepository)

	wrappingKey := sha256.Sum256([]byte("coh-e10-integration-wrapping-key"))
	ingestion, _ := composeEvidenceController(t, driver, caseRepository, casRoot, wrappingKey[:], now)
	payload := []byte("COH-E10 exact encrypted evidence export\n")
	ingestCommand := evidenceCommand(create, payload, now)
	ingested, err := ingestion.Execute(t.Context(), ingestCommand, &evidenceSource{value: payload})
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := evidenceingest.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	nativeCAS := openEvidenceCAS(t, casRoot, wrappingKey[:], now)
	catalog, err := evidencecatalog.New(guarded, receipts, nativeCAS)
	if err != nil {
		t.Fatal(err)
	}
	entry := evidencelifecycle.ManifestArtifact{Ordinal: 1, Role: evidencelifecycle.SourceArtifact,
		Reference: evidencelifecycle.EvidenceReference{Artifact: ingested.Artifact, Manifest: ingested.Manifest,
			ManifestProvenanceDigest: ingested.Receipt.ManifestProvenanceDigest,
			IngestionReceiptDigest:   ingested.Receipt.ReceiptDigest},
		ParentArtifactDigests: []string{}, ParentManifestDigests: []string{}}
	evidenceSet, replayed, err := catalog.Register(t.Context(), evidencecatalog.Registration{
		Case: create.Case, Artifacts: []evidencelifecycle.ManifestArtifact{entry}})
	if err != nil || replayed {
		t.Fatalf("catalog registration replayed=%v err=%v", replayed, err)
	}

	checkpointID, checkpointDigest := caseUUID("e10-checkpoint"), caseDigest("e10-checkpoint")
	custodyAuditor := &custodySQLiteAuditor{proofs: make(map[string]custody.AuditProof),
		checkpointID: &checkpointID, checkpointDigest: &checkpointDigest}
	caseSnapshot, found, err := lifecycleCases.LoadCase(t.Context(), create.Case)
	if err != nil || !found {
		t.Fatalf("case snapshot found=%v err=%v", found, err)
	}
	custodyReference := toCustodyReference(entry.Reference)
	verified := custody.VerifiedEvidence{Reference: custodyReference,
		SourceIdentityDigest: ingestCommand.Source.IdentityDigest,
		VerificationDigest:   caseDigest("e10-custody-evidence-verification")}
	custodyEvidence := lifecycleCustodyEvidence{verified: map[custody.EvidenceReference]custody.VerifiedEvidence{
		custodyReference: verified}}
	custodyCase := custody.CaseSnapshot{Case: create.Case, State: caseSnapshot.State,
		Classification: caseSnapshot.Classification, Revision: caseSnapshot.Revision,
		RetentionPolicyDigest: caseDigest("e10-retention-policy"), RetainUntil: caseSnapshot.RetainUntil,
		LegalHold: caseSnapshot.LegalHold, ProvenanceDigest: caseSnapshot.ProvenanceDigest}
	ledger, err := custody.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	custodyController, err := custody.New(custodySQLiteAuthority{now: now},
		custodySQLiteCases{current: custodyCase}, custodyEvidence, ledger, custodyAuditor, custodySQLiteClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	custodyVerifier, err := custody.NewVerifier(ledger, custodyEvidence, custodyAuditor, custodySQLiteClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := lifecycleCustodyCheckpoint{scope: create.Case, proof: auditlog.CheckpointProof{
		CheckpointID: checkpointID, CheckpointDigest: checkpointDigest, Sequence: 100,
		SigningKeyRevision: 3, ProofDigest: caseDigest("e10-checkpoint-proof")}}
	lifecycleCustody, err := lifecyclecustody.New(custodyController, ledger, custodyVerifier, checkpoint, guarded)
	if err != nil {
		t.Fatal(err)
	}
	initial := evidencelifecycle.CustodyRequest{Operation: evidencelifecycle.Import,
		Phase: evidencelifecycle.Completed, Case: create.Case, ActorID: create.ActorID,
		ActorRevision: create.ActorRevision, ArtifactSetDigest: evidenceSet.ArtifactSetDigest,
		Subjects: []evidencelifecycle.EvidenceReference{entry.Reference}, SourceDigest: &ingestCommand.Source.IdentityDigest,
		PolicyDigest: ingestCommand.PolicyDigest, ExpectedCaseRevision: caseSnapshot.Revision,
		ExpectedHead: evidencelifecycle.CustodyHead{Case: create.Case, ChainHash: custody.GenesisHash},
		Deadline:     now.Add(time.Hour)}
	initialCustody, err := lifecycleCustody.RecordLifecycle(t.Context(), initial)
	if err != nil {
		t.Fatal(err)
	}

	derivedPayload := append([]byte(nil), payload...)
	copy(derivedPayload[:6], []byte("******"))
	derivedEntry, redactions, redactionHead := composeE10DerivedRedaction(t, now, ingestCommand, ingestion,
		receipts, nativeCAS, guarded, custodyController, ledger, custodyEvidence, entry, initialCustody.Head,
		payload, derivedPayload)
	evidenceSet, replayed, err = catalog.Register(t.Context(), evidencecatalog.Registration{
		Case: create.Case, Artifacts: []evidencelifecycle.ManifestArtifact{entry, derivedEntry}})
	if err != nil || replayed {
		t.Fatalf("lineage catalog registration replayed=%v err=%v", replayed, err)
	}
	keys := newE10SigningKeys(now)
	signing, err := evidencesigning.New(keys)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := evidencesource.New(receipts, nativeCAS)
	if err != nil {
		t.Fatal(err)
	}
	quarantine := &e10Quarantine{objects: make(map[string][]byte),
		packages: make(map[string]evidencelifecycle.QuarantinedPackage)}
	packages, err := evidencepackage.New(quarantine, sources)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleStore, err := evidencelifecycle.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	service, err := evidencelifecycle.NewExportService(e10LifecycleAuthority{now: now}, lifecycleCases,
		lifecycleCases, catalog, redactions, lifecycleCustody, signing, signing, packages, lifecycleStore,
		&e10LifecycleAuditor{}, evidenceClock{now: now}, evidencelifecycle.SigningProfile{
			KeyID: "evidence.primary", KeyRevision: 1, TrustSnapshotDigest: keys.trust,
			KeyRevocationDigest: keys.revocation, Validity: 20 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	purpose, destination, approval := caseDigest("e10-purpose"), caseDigest("e10-destination"), caseDigest("e10-approval")
	command := evidencelifecycle.Command{SchemaVersion: evidencelifecycle.CommandSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, RequestID: caseUUID("e10-export-request"),
		IdempotencyKey: "coh-e10-composed-export", Operation: evidencelifecycle.Export, Case: create.Case,
		ActorID: create.ActorID, ActorRevision: create.ActorRevision, ArtifactSetDigest: &evidenceSet.ArtifactSetDigest,
		PurposeDigest: &purpose, DestinationDigest: &destination, ApprovalDigest: &approval,
		PolicyDigest: caseDigest("e10-export-policy"), ExpectedCaseRevision: caseSnapshot.Revision,
		ExpectedCustodyHead: redactionHead, Limits: evidencelifecycle.PackageLimits{
			MaximumManifestBytes: 1 << 20, MaximumSignatureBytes: 1 << 12, MaximumArtifacts: 8,
			MaximumArtifactBytes: 1 << 20, MaximumPackageBytes: 2 << 20}, Deadline: now.Add(time.Hour)}
	result, err := service.Execute(t.Context(), command)
	if err != nil || result.ReleaseReference == nil || result.Replayed {
		t.Fatalf("export=%+v err=%v", result, err)
	}
	packageBytes := quarantine.objects[*result.ReleaseReference]
	if len(packageBytes) == 0 || !bytes.Contains(packageBytes, payload) || !bytes.Contains(packageBytes, derivedPayload) {
		t.Fatalf("released package did not contain original and derived artifacts: bytes=%d", len(packageBytes))
	}
	if result.Receipt.PackageDigest == nil || result.Receipt.ManifestDigest == nil ||
		result.Receipt.AuthorizationCustodyReceiptDigest == nil || result.Receipt.CompletionCustodyReceiptDigest == nil ||
		result.Receipt.LifecycleReceiptDigest == nil {
		t.Fatalf("export receipt omitted required proofs: %+v", result.Receipt)
	}
	quarantined, found := quarantine.packages[*result.Receipt.PackageDigest]
	manifest, signature, err := packages.RecoverPackageProof(t.Context(), quarantined, command.Limits)
	if err != nil || len(manifest.Artifacts) != 2 || manifest.Artifacts[0].Role != evidencelifecycle.SourceArtifact ||
		manifest.Artifacts[1].Role != evidencelifecycle.DerivedArtifact ||
		manifest.Artifacts[1].RedactionReceiptDigest == nil || manifest.Artifacts[1].MappingDigest == nil ||
		len(manifest.Artifacts[1].ParentArtifactDigests) != 1 ||
		manifest.Artifacts[1].ParentArtifactDigests[0] != manifest.Artifacts[0].Reference.Artifact.Digest ||
		manifest.CustodyToSequence != redactionHead.Sequence || manifest.AuditCheckpointID != checkpointID ||
		manifest.AuditCheckpointDigest != checkpointDigest || signature.ManifestDigest != manifest.ManifestDigest {
		t.Fatalf("recovered export proof manifest=%+v signature=%+v found=%v err=%v", manifest, signature, found, err)
	}
	idempotencyDigest, err := evidencelifecycle.IdempotencyBindingDigest(command.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	recovered, found, err := lifecycleStore.Recover(t.Context(), create.Case, idempotencyDigest)
	if err != nil || !found || recovered.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatalf("durable recovery=%+v found=%v err=%v", recovered, found, err)
	}
	replayedResult, err := service.Execute(t.Context(), command)
	if err != nil || !replayedResult.Replayed || replayedResult.Receipt.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatalf("replay=%+v err=%v", replayedResult, err)
	}
	assertSensitiveBytesAbsent(t, filepath.Join(root, "coh.sqlite3"), casRoot, payload, derivedPayload)
}

func toCustodyReference(reference evidencelifecycle.EvidenceReference) custody.EvidenceReference {
	return custody.EvidenceReference{Artifact: reference.Artifact, Manifest: reference.Manifest,
		ManifestProvenanceDigest: reference.ManifestProvenanceDigest,
		IngestionReceiptDigest:   reference.IngestionReceiptDigest}
}

type e10LifecycleAuthority struct{ now time.Time }

func (authority e10LifecycleAuthority) AuthorizeEvidenceLifecycle(_ context.Context,
	request evidencelifecycle.AuthorizationRequest) (evidencelifecycle.Decision, error) {
	value := evidencelifecycle.Decision{SchemaVersion: evidencelifecycle.DecisionSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, DecisionID: caseUUID("e10-export-decision"),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: request.Command.Operation, Case: request.Command.Case, ActorID: request.Command.ActorID,
		ActorRevision: request.Command.ActorRevision, ArtifactSetDigest: request.ArtifactSetDigest,
		PolicyDigest: request.Command.PolicyDigest, ApprovalDigest: request.Command.ApprovalDigest,
		RevocationDigest: caseDigest("e10-export-revocation"), ExpectedCaseRevision: request.CaseRevision,
		ExpectedCustodyHead: request.CurrentCustodyHead, Outcome: evidencelifecycle.Allow,
		ReasonCode: evidencelifecycle.ReasonAuthorized, IssuedAt: authority.now,
		ExpiresAt: request.Command.Deadline, Revision: 1}
	value.DecisionDigest, _ = evidencelifecycle.DecisionBindingDigest(value)
	return value, nil
}

type e10LifecycleAuditor struct{ events map[string]string }

func (auditor *e10LifecycleAuditor) AppendLifecycleEvent(_ context.Context, event tamperaudit.Event) error {
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return err
	}
	if auditor.events == nil {
		auditor.events = make(map[string]string)
	}
	sum := sha256.Sum256(append([]byte("COH-EVIDENCE-LIFECYCLE-AUDIT-EVENT-V1\x00"), canonical...))
	auditor.events[event.EventID] = "sha256:" + fmtHex(sum[:])
	return nil
}

func (auditor *e10LifecycleAuditor) VerifyLifecycleEvent(_ context.Context, _ domain.CaseRef,
	eventID, digest string) error {
	if auditor.events[eventID] != digest {
		return errors.New("lifecycle audit proof mismatch")
	}
	return nil
}

type e10SigningKeys struct {
	private    ed25519.PrivateKey
	public     ed25519.PublicKey
	trust      string
	revocation string
	now        time.Time
}

func newE10SigningKeys(now time.Time) *e10SigningKeys {
	seed := sha256.Sum256([]byte("coh-e10-signing-key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	return &e10SigningKeys{private: private, public: private.Public().(ed25519.PublicKey),
		trust: caseDigest("e10-signing-trust"), revocation: caseDigest("e10-signing-revocation"), now: now}
}

func (keys *e10SigningKeys) ResolveSigningKey(context.Context, string, uint64,
	string) (evidencesigning.SigningKey, error) {
	return evidencesigning.SigningKey{KeyID: "evidence.primary", KeyRevision: 1,
		PrivateKey: append([]byte(nil), keys.private...)}, nil
}

func (keys *e10SigningKeys) ResolveVerificationKey(context.Context, string, uint64, string, string,
	time.Time) (evidencesigning.VerificationKey, error) {
	return evidencesigning.VerificationKey{KeyID: "evidence.primary", KeyRevision: 1,
		PublicKey: append([]byte(nil), keys.public...), TrustSnapshotDigest: keys.trust,
		RevocationDigest: keys.revocation, ValidFrom: keys.now.Add(-time.Hour),
		ValidUntil: keys.now.Add(time.Hour)}, nil
}

type e10Quarantine struct {
	objects  map[string][]byte
	packages map[string]evidencelifecycle.QuarantinedPackage
}

func (store *e10Quarantine) Create(context.Context, domain.CaseRef,
	string) (evidencepackage.QuarantineObject, error) {
	return &e10QuarantineObject{store: store}, nil
}
func (store *e10Quarantine) Open(_ context.Context, reference string) (io.ReadCloser, error) {
	value, found := store.objects[reference]
	if !found {
		return nil, errors.New("quarantine object not found")
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}
func (store *e10Quarantine) Recover(_ context.Context, _ domain.CaseRef,
	digest string) (evidencelifecycle.QuarantinedPackage, bool, error) {
	value, found := store.packages[digest]
	return value, found, nil
}

type e10QuarantineObject struct {
	bytes.Buffer
	store *e10Quarantine
}

func (object *e10QuarantineObject) Commit(_ context.Context, report evidencepackage.EncodingReport,
	manifestDigest, signatureDigest string) (string, error) {
	reference := "quarantine.coh-e10.export"
	object.store.objects[reference] = append([]byte(nil), object.Bytes()...)
	object.store.packages[report.PackageDigest] = evidencelifecycle.QuarantinedPackage{Reference: reference,
		Header: report.Header, HeaderDigest: report.Header.HeaderDigest, PackageDigest: report.PackageDigest,
		PackageLength: report.PackageLength, ManifestDigest: manifestDigest, SignatureDigest: signatureDigest}
	return reference, nil
}
func (*e10QuarantineObject) Abandon(context.Context) error { return nil }

func fmtHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2], result[index*2+1] = digits[item>>4], digits[item&15]
	}
	return string(result)
}
