package importingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func TestAdapterPublishesTopologicalImportThroughImmutableIngestion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := importArtifact("root", 1, nil)
	child := importArtifact("child", 2, []evidencelifecycle.ManifestArtifact{root})
	request := importRequest(now, []evidencelifecycle.ManifestArtifact{root, child})
	staged := &stagedStore{values: map[string][]byte{"stage.1": []byte("root"), "stage.2": []byte("child")}}
	ingestor := &ingestor{now: now}
	adapter, err := New(ingestor, staged, importProfile())
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.PublishImport(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Artifacts) != 2 || len(result.Progress) != 2 || staged.opened != 2 || staged.closed != 2 ||
		len(ingestor.commands) != 2 || result.Artifacts[1].Artifact != child.Reference.Artifact {
		t.Fatalf("result=%+v opened=%d closed=%d commands=%d", result, staged.opened, staged.closed, len(ingestor.commands))
	}
	second := ingestor.commands[1]
	if second.Source.Kind != evidenceingest.ImportSource || len(second.ParentArtifacts) != 1 ||
		second.ParentArtifacts[0] != result.Artifacts[0].Artifact ||
		second.ParentManifestDigests[0] != result.Artifacts[0].Manifest.Digest ||
		second.ExpectedDigest != child.Reference.Artifact.Digest ||
		second.Source.IdentityDigest != evidenceingest.SourceIdentityDigest(second.Source.Identity) {
		t.Fatalf("import lineage or source binding lost: %+v", second)
	}
}

func TestAdapterWithholdsAllReferencesWhenAnyIngestionFails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := importArtifact("root", 1, nil)
	child := importArtifact("child", 2, []evidencelifecycle.ManifestArtifact{root})
	request := importRequest(now, []evidencelifecycle.ManifestArtifact{root, child})
	staged := &stagedStore{values: map[string][]byte{"stage.1": []byte("root"), "stage.2": []byte("child")}}
	ingestor := &ingestor{now: now, failAt: 2}
	adapter, _ := New(ingestor, staged, importProfile())
	result, err := adapter.PublishImport(t.Context(), request)
	if err == nil || len(result.Artifacts) != 0 || len(result.Progress) != 0 {
		t.Fatalf("partial references escaped: result=%+v err=%v", result, err)
	}
}

func TestAdapterRejectsSubstitutedImmutableIngestionResult(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request := importRequest(now, []evidencelifecycle.ManifestArtifact{importArtifact("root", 1, nil)})
	staged := &stagedStore{values: map[string][]byte{"stage.1": []byte("root")}}
	ingestor := &ingestor{now: now, substitute: true}
	adapter, _ := New(ingestor, staged, importProfile())
	if _, err := adapter.PublishImport(t.Context(), request); err == nil {
		t.Fatal("substituted ingestion result accepted")
	}
}

type stagedStore struct {
	values         map[string][]byte
	opened, closed int
}

func (store *stagedStore) OpenStaged(_ context.Context,
	value evidencelifecycle.StagedImportArtifact) (StagedSource, error) {
	data, found := store.values[value.Reference]
	if !found {
		return nil, errors.New("missing staged artifact")
	}
	store.opened++
	return &stagedSource{value: data, close: func() { store.closed++ }}, nil
}

type stagedSource struct {
	value  []byte
	offset int
	close  func()
}

func (source *stagedSource) ReadContext(ctx context.Context, destination []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if source.offset == len(source.value) {
		return 0, io.EOF
	}
	count := copy(destination, source.value[source.offset:])
	source.offset += count
	return count, nil
}
func (source *stagedSource) Close() error { source.close(); return nil }

type ingestor struct {
	now        time.Time
	commands   []evidenceingest.Command
	failAt     int
	substitute bool
}

func (stub *ingestor) Execute(_ context.Context, command evidenceingest.Command,
	_ evidenceingest.Source) (evidenceingest.Result, error) {
	stub.commands = append(stub.commands, command)
	if stub.failAt == len(stub.commands) {
		return evidenceingest.Result{}, errors.New("ingestion unavailable")
	}
	artifact := domain.ArtifactRef{Digest: command.ExpectedDigest, MediaType: command.MediaType,
		Classification: command.Classification, Length: command.ExpectedLength}
	if stub.substitute {
		artifact.Digest = importDigest("substitute")
	}
	manifest := domain.ArtifactRef{Digest: importDigest("manifest-" + command.ExpectedDigest),
		MediaType: "application/vnd.coh.artifact-manifest+json", Classification: command.Classification, Length: 512}
	contextDigest := func(reference domain.ArtifactRef) string {
		value, _ := evidenceingest.EncryptionContextBindingDigest(evidenceingest.StageRequest{Case: command.Case,
			ExpectedDigest: reference.Digest, ExpectedLength: reference.Length, MediaType: reference.MediaType,
			Classification: reference.Classification, KeyProfile: command.KeyProfile,
			KeyProfileDigest: command.KeyProfileDigest, Deadline: command.Deadline})
		return value
	}
	published := func(reference domain.ArtifactRef) evidenceingest.PublishedObject {
		return evidenceingest.PublishedObject{Case: command.Case, PlaintextDigest: reference.Digest,
			PlaintextLength: reference.Length, CiphertextDigest: importDigest("cipher-" + reference.Digest),
			CiphertextLength: reference.Length + 128, EncryptionFormat: evidenceingest.EncryptionFormatVersion,
			EncryptionContextDigest: contextDigest(reference), LocatorDigest: importDigest("locator-" + reference.Digest)}
	}
	intent, _ := evidenceingest.CommandBindingDigest(command)
	transport, _ := evidenceingest.TransportBindingDigest(command.Transport)
	receipt := evidenceingest.Receipt{SchemaVersion: evidenceingest.ReceiptSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, RequestID: command.RequestID, Case: command.Case,
		ActorID: command.ActorID, ActorRevision: command.ActorRevision, IntentDigest: intent,
		IdempotencyDigest:   evidenceingest.IdempotencyBindingDigest(command.IdempotencyKey),
		AuthorizationDigest: importDigest("authorization"), DecisionDigest: importDigest("decision"),
		RevocationDigest: importDigest("revocation"), TransportDigest: transport, Artifact: artifact, Manifest: manifest,
		EncryptedArtifact: published(artifact), EncryptedManifest: published(manifest),
		ManifestProvenanceDigest: importDigest("provenance-" + artifact.Digest),
		AuditEventDigest:         importDigest("audit-" + artifact.Digest), CreatedAt: stub.now}
	receipt.ReceiptDigest, _ = evidenceingest.ReceiptBindingDigest(receipt)
	return evidenceingest.Result{Artifact: artifact, Manifest: manifest, Receipt: receipt}, nil
}

func importRequest(now time.Time,
	artifacts []evidencelifecycle.ManifestArtifact) evidencelifecycle.ImportPublicationRequest {
	staged := make([]evidencelifecycle.StagedImportArtifact, len(artifacts))
	for index, artifact := range artifacts {
		staged[index] = evidencelifecycle.StagedImportArtifact{Ordinal: artifact.Ordinal,
			ArtifactDigest: artifact.Reference.Artifact.Digest, Reference: "stage." + string(rune('1'+index)),
			VerificationDigest: importDigest("verification")}
	}
	return evidencelifecycle.ImportPublicationRequest{RequestID: importID("request"), IdempotencyKey: "import-1",
		Case: importCase(), ActorID: importID("actor"), ActorRevision: 2,
		Verified: evidencelifecycle.VerifiedImport{Package: evidencelifecycle.QuarantinedPackage{
			PackageDigest: importDigest("package")}, Manifest: evidencelifecycle.ExportManifest{
			Artifacts: artifacts, Components: []evidencelifecycle.Component{{Kind: "tool", Name: "collector",
				Version: "1.0.0", Digest: importDigest("component")}}, CreatedAt: now},
			Verification: evidencelifecycle.ImportVerification{SourceDigest: importDigest("source"),
				ReportDigest: importDigest("report")}, Staged: staged},
		PolicyDigest: importDigest("policy"), Deadline: now.Add(time.Hour)}
}

func importArtifact(seed string, ordinal uint16,
	parents []evidencelifecycle.ManifestArtifact) evidencelifecycle.ManifestArtifact {
	artifact := domain.ArtifactRef{Digest: importDigest(seed), MediaType: "application/json",
		Classification: "restricted", Length: int64(len(seed))}
	manifest := domain.ArtifactRef{Digest: importDigest(seed + "-manifest"),
		MediaType: "application/vnd.coh.artifact-manifest+json", Classification: "restricted", Length: 512}
	value := evidencelifecycle.ManifestArtifact{Ordinal: ordinal, Role: evidencelifecycle.ImportedArtifact,
		Reference: evidencelifecycle.EvidenceReference{Artifact: artifact, Manifest: manifest,
			ManifestProvenanceDigest: importDigest(seed + "-provenance"),
			IngestionReceiptDigest:   importDigest(seed + "-receipt")}, ParentArtifactDigests: []string{},
		ParentManifestDigests: []string{}}
	for _, parent := range parents {
		value.ParentArtifactDigests = append(value.ParentArtifactDigests, parent.Reference.Artifact.Digest)
		value.ParentManifestDigests = append(value.ParentManifestDigests, parent.Reference.Manifest.Digest)
	}
	return value
}

func importProfile() Profile {
	return Profile{KeyProfile: "imported_evidence", KeyProfileDigest: importDigest("key-profile"),
		Transport: evidenceingest.TransportContext{Mode: evidenceingest.InProcess,
			PeerIdentityDigest: importDigest("peer"), ChannelBindingDigest: importDigest("channel")}}
}
func importCase() domain.CaseRef {
	return domain.CaseRef{OrganizationID: importID("org"), TenantID: importID("tenant"), CaseID: importID("case")}
}
func importDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func importID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
