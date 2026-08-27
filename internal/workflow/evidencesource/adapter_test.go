package evidencesource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type receiptResolverStub struct {
	receipt evidenceingest.Receipt
	found   bool
	err     error
}

func (stub receiptResolverStub) ResolveReceipt(context.Context, domain.CaseRef,
	string) (evidenceingest.Receipt, bool, error) {
	return stub.receipt, stub.found, stub.err
}

type artifactOpenerStub struct {
	payload []byte
	seen    *evidenceingest.Receipt
}

func (stub artifactOpenerStub) OpenIngestedArtifact(_ context.Context,
	receipt evidenceingest.Receipt) (io.ReadCloser, error) {
	*stub.seen = receipt
	return io.NopCloser(bytes.NewReader(stub.payload)), nil
}

func TestAdapterOpensOnlyExactlyBoundReceipt(t *testing.T) {
	scope, reference, receipt := sourceFixture(t)
	var seen evidenceingest.Receipt
	adapter, err := New(receiptResolverStub{receipt: receipt, found: true},
		artifactOpenerStub{payload: []byte("evidence"), seen: &seen})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := adapter.OpenArtifact(t.Context(), scope, reference)
	if err != nil {
		t.Fatal(err)
	}
	payload, readErr := io.ReadAll(reader)
	if closeErr := reader.Close(); readErr != nil || closeErr != nil || string(payload) != "evidence" ||
		seen.ReceiptDigest != receipt.ReceiptDigest {
		t.Fatalf("payload=%q seen=%+v read=%v close=%v", payload, seen, readErr, closeErr)
	}

	for name, mutate := range map[string]func(*evidencelifecycle.EvidenceReference){
		"artifact": func(value *evidencelifecycle.EvidenceReference) {
			value.Artifact.Digest = sourceDigest([]byte("substitute"))
		},
		"manifest": func(value *evidencelifecycle.EvidenceReference) {
			value.Manifest.Digest = sourceDigest([]byte("substitute manifest"))
		},
		"provenance": func(value *evidencelifecycle.EvidenceReference) {
			value.ManifestProvenanceDigest = sourceDigest([]byte("substitute provenance"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := reference
			mutate(&tampered)
			if _, openErr := adapter.OpenArtifact(t.Context(), scope, tampered); openErr == nil {
				t.Fatal("substituted reference was accepted")
			}
		})
	}
	foreign := scope
	foreign.CaseID = sourceUUID("foreign")
	if _, err = adapter.OpenArtifact(t.Context(), foreign, reference); err == nil {
		t.Fatal("foreign case was accepted")
	}
}

func sourceFixture(t *testing.T) (domain.CaseRef, evidencelifecycle.EvidenceReference,
	evidenceingest.Receipt) {
	t.Helper()
	scope := domain.CaseRef{OrganizationID: sourceUUID("org"), TenantID: sourceUUID("tenant"),
		CaseID: sourceUUID("case")}
	artifact := domain.ArtifactRef{Digest: sourceDigest([]byte("evidence")), MediaType: "text/plain",
		Classification: "restricted", Length: 8}
	manifest := domain.ArtifactRef{Digest: sourceDigest([]byte("manifest")),
		MediaType: "application/vnd.coh.artifact-manifest+json", Classification: "restricted", Length: 128}
	provenance := sourceDigest([]byte("provenance"))
	receipt := evidenceingest.Receipt{SchemaVersion: evidenceingest.ReceiptSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, RequestID: sourceUUID("request"), Case: scope,
		ActorID: sourceUUID("actor"), ActorRevision: 1, IntentDigest: sourceDigest([]byte("intent")),
		IdempotencyDigest:   sourceDigest([]byte("idempotency")),
		AuthorizationDigest: sourceDigest([]byte("authorization")), DecisionDigest: sourceDigest([]byte("decision")),
		RevocationDigest: sourceDigest([]byte("revocation")), TransportDigest: sourceDigest([]byte("transport")),
		Artifact: artifact, Manifest: manifest, EncryptedArtifact: sourcePublished(scope, artifact),
		EncryptedManifest: sourcePublished(scope, manifest), ManifestProvenanceDigest: provenance,
		AuditEventDigest: sourceDigest([]byte("audit")), CreatedAt: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)}
	receipt.ReceiptDigest, _ = evidenceingest.ReceiptBindingDigest(receipt)
	reference := evidencelifecycle.EvidenceReference{Artifact: artifact, Manifest: manifest,
		ManifestProvenanceDigest: provenance, IngestionReceiptDigest: receipt.ReceiptDigest}
	return scope, reference, receipt
}

func sourcePublished(scope domain.CaseRef, artifact domain.ArtifactRef) evidenceingest.PublishedObject {
	return evidenceingest.PublishedObject{Case: scope, PlaintextDigest: artifact.Digest,
		PlaintextLength: artifact.Length, CiphertextDigest: sourceDigest([]byte("ciphertext:" + artifact.Digest)),
		CiphertextLength: artifact.Length + 64, EncryptionFormat: evidenceingest.EncryptionFormatVersion,
		EncryptionContextDigest: sourceDigest([]byte("context:" + artifact.Digest)),
		LocatorDigest:           sourceDigest([]byte("locator:" + artifact.Digest))}
}

func sourceDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sourceUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
