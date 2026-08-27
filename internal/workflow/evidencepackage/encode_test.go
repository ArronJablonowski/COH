package evidencepackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func TestEncodeIsDeterministicPathlessAndDigestVerified(t *testing.T) {
	payload := []byte(`{"event":"verified"}`)
	manifest, signature := packageFixture(t, payload)
	opener := packageSources{manifest.Artifacts[0].Reference.Artifact.Digest: payload}
	var first, second bytes.Buffer
	firstReport, err := Encode(t.Context(), &first, manifest, signature, opener)
	if err != nil {
		t.Fatal(err)
	}
	secondReport, err := Encode(t.Context(), &second, manifest, signature, opener)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) || firstReport != secondReport ||
		int64(first.Len()) != firstReport.PackageLength || strings.Contains(first.String(), "../") {
		t.Fatal("package is not deterministic, exact length, or pathless")
	}
	if firstReport.Header.Compression != evidencelifecycle.NoCompression ||
		firstReport.Header.Magic != evidencelifecycle.PackageMagic || firstReport.Header.ArtifactCount != 1 {
		t.Fatalf("unexpected header: %+v", firstReport.Header)
	}
}

func TestEncodeRejectsArtifactDriftAndCancellation(t *testing.T) {
	payload := []byte("expected")
	manifest, signature := packageFixture(t, payload)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, test := range map[string]struct {
		ctx    context.Context
		source []byte
	}{
		"digest":   {context.Background(), []byte("tampered")},
		"length":   {context.Background(), []byte("short")},
		"canceled": {canceled, payload},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			_, err := Encode(test.ctx, &output, manifest, signature,
				packageSources{manifest.Artifacts[0].Reference.Artifact.Digest: test.source})
			if err == nil {
				t.Fatal("unsafe artifact accepted")
			}
		})
	}
}

type packageSources map[string][]byte

func (sources packageSources) OpenArtifact(_ context.Context,
	reference evidencelifecycle.EvidenceReference) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(sources[reference.Artifact.Digest])), nil
}

func packageFixture(t *testing.T, payload []byte) (evidencelifecycle.ExportManifest,
	evidencelifecycle.DetachedSignature) {
	t.Helper()
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	caseRef := domain.CaseRef{OrganizationID: packageUUID("organization"), TenantID: packageUUID("tenant"),
		CaseID: packageUUID("case")}
	artifact := domain.ArtifactRef{Digest: packageDigest(payload), MediaType: "application/json",
		Classification: "restricted", Length: int64(len(payload))}
	manifestRef := domain.ArtifactRef{Digest: packageDigest([]byte("manifest-reference")),
		MediaType: "application/vnd.coh.artifact-manifest+json", Classification: "restricted", Length: 128}
	artifacts := []evidencelifecycle.ManifestArtifact{{Ordinal: 1, Role: evidencelifecycle.SourceArtifact,
		Reference: evidencelifecycle.EvidenceReference{Artifact: artifact, Manifest: manifestRef,
			ManifestProvenanceDigest: packageDigest([]byte("provenance")),
			IngestionReceiptDigest:   packageDigest([]byte("receipt"))},
		ParentArtifactDigests: []string{}, ParentManifestDigests: []string{}}}
	artifactSet, _ := evidencelifecycle.ArtifactSetBindingDigest(artifacts)
	manifest := evidencelifecycle.ExportManifest{SchemaVersion: evidencelifecycle.ExportManifestSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, ManifestID: packageUUID("manifest"),
		PackageVersion: evidencelifecycle.PackageVersion, Case: caseRef, CaseRevision: 2,
		Classification: "restricted", ActorID: packageUUID("actor"), ActorRevision: 4,
		PurposeDigest: packageDigest([]byte("purpose")), DestinationDigest: packageDigest([]byte("destination")),
		Artifacts: artifacts, ArtifactSetDigest: artifactSet,
		Components: []evidencelifecycle.Component{{Kind: "policy", Name: "tenant.policy", Version: "1.0.0",
			Digest: packageDigest([]byte("component"))}}, PolicyDigest: packageDigest([]byte("policy")),
		DecisionDigest: packageDigest([]byte("decision")), ApprovalDigest: packageDigest([]byte("approval")),
		RevocationDigest: packageDigest([]byte("revocation")), CustodyFromSequence: 1, CustodyToSequence: 3,
		CustodyReportDigest: packageDigest([]byte("custody")), AuditCheckpointID: packageUUID("checkpoint"),
		AuditCheckpointDigest: packageDigest([]byte("checkpoint")), AuditCheckpointSequence: 3,
		AuditSigningKeyRevision: 2, AuditProofDigest: packageDigest([]byte("audit-proof")),
		SigningAlgorithm: evidencelifecycle.SigningAlgorithm, SigningKeyID: "evidence.primary", SigningKeyRevision: 3,
		SigningTrustSnapshotDigest: packageDigest([]byte("trust")),
		SigningKeyRevocationDigest: packageDigest([]byte("key-revocation")),
		Compression:                evidencelifecycle.NoCompression,
		Limits: evidencelifecycle.PackageLimits{MaximumManifestBytes: 1 << 20, MaximumSignatureBytes: 512,
			MaximumArtifacts: 16, MaximumArtifactBytes: 1 << 30, MaximumPackageBytes: 2 << 30},
		CreatedAt: now, ValidUntil: now.Add(time.Hour), IdempotencyDigest: packageDigest([]byte("idempotency")),
		PreviousProvenanceDigest: packageDigest([]byte("previous"))}
	manifest.ManifestDigest, _ = evidencelifecycle.ManifestBindingDigest(manifest)
	signature := evidencelifecycle.DetachedSignature{SchemaVersion: evidencelifecycle.DetachedSignatureSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, Algorithm: evidencelifecycle.SigningAlgorithm,
		KeyID: manifest.SigningKeyID, KeyRevision: manifest.SigningKeyRevision, ManifestDigest: manifest.ManifestDigest,
		Signature: strings.Repeat("A", 86)}
	return manifest, signature
}

func packageDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func packageUUID(value string) string {
	hexValue := strings.TrimPrefix(packageDigest([]byte(value)), "sha256:")[:32]
	return hexValue[:8] + "-" + hexValue[8:12] + "-7" + hexValue[13:16] + "-8" + hexValue[17:20] + "-" + hexValue[20:32]
}
