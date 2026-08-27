package redactioningest

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
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

func TestAdapterPublishesThroughImmutableIngestionWithExactLineage(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	transport := evidenceingest.TransportContext{Mode: evidenceingest.InProcess,
		PeerIdentityDigest: adapterDigest("peer"), ChannelBindingDigest: adapterDigest("channel")}
	ingestor := &ingestorStub{now: now}
	adapter, err := New(ingestor, transport)
	if err != nil {
		t.Fatal(err)
	}
	parent := adapterEvidence("source", "text/plain", "restricted", 20)
	derivedBytes := []byte("redacted evidence")
	request := redaction.PublicationRequest{Role: redaction.DerivedPublication, RequestID: adapterID("request"),
		IdempotencyKey: "redaction-derived-1", Case: parentCase(), ActorID: adapterID("actor"), ActorRevision: 7,
		ExpectedArtifact: domain.ArtifactRef{Digest: bytesDigest(derivedBytes), MediaType: "text/plain",
			Classification: "confidential", Length: int64(len(derivedBytes))}, Parents: []redaction.EvidenceReference{parent},
		SourceIdentityDigest: adapterDigest("source-identity"), RuleDigest: adapterDigest("rule"),
		PlanDigest: adapterDigest("plan"), PolicyDigest: adapterDigest("policy"), KeyProfile: "redacted_evidence",
		KeyProfileDigest: adapterDigest("key-profile"), CreatedAt: now, Deadline: now.Add(time.Hour)}
	published, err := adapter.Publish(t.Context(), request, &adapterSource{value: derivedBytes})
	if err != nil {
		t.Fatal(err)
	}
	if published.Reference.Artifact != request.ExpectedArtifact || published.ReceiptDigest == "" ||
		!bytes.Equal(ingestor.received, derivedBytes) {
		t.Fatalf("published=%+v bytes=%q", published, ingestor.received)
	}
	command := ingestor.command
	if command.Source.Kind != evidenceingest.DerivedSource || !strings.Contains(command.Source.Identity, request.PlanDigest) ||
		len(command.ParentArtifacts) != 1 || command.ParentArtifacts[0] != parent.Artifact ||
		command.ParentManifestDigests[0] != parent.Manifest.Digest || command.ExpectedDigest != request.ExpectedArtifact.Digest ||
		command.PolicyDigest != request.PolicyDigest || command.KeyProfileDigest != request.KeyProfileDigest {
		t.Fatalf("ingestion command lost binding: %+v", command)
	}
}

func TestAdapterRejectsSubstitutedIngestionResult(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	transport := evidenceingest.TransportContext{Mode: evidenceingest.InProcess,
		PeerIdentityDigest: adapterDigest("peer"), ChannelBindingDigest: adapterDigest("channel")}
	ingestor := &ingestorStub{now: now, substitute: true}
	adapter, _ := New(ingestor, transport)
	parent := adapterEvidence("source", "text/plain", "restricted", 20)
	value := []byte("redacted evidence")
	request := redaction.PublicationRequest{Role: redaction.DerivedPublication, RequestID: adapterID("request"),
		IdempotencyKey: "redaction-derived-1", Case: parentCase(), ActorID: adapterID("actor"), ActorRevision: 7,
		ExpectedArtifact: domain.ArtifactRef{Digest: bytesDigest(value), MediaType: "text/plain", Classification: "confidential", Length: int64(len(value))},
		Parents:          []redaction.EvidenceReference{parent}, SourceIdentityDigest: adapterDigest("source-identity"),
		RuleDigest: adapterDigest("rule"), PlanDigest: adapterDigest("plan"), PolicyDigest: adapterDigest("policy"),
		KeyProfile: "redacted_evidence", KeyProfileDigest: adapterDigest("key-profile"), CreatedAt: now, Deadline: now.Add(time.Hour)}
	if _, err := adapter.Publish(t.Context(), request, &adapterSource{value: value}); redaction.CodeOf(err) != redaction.Denied {
		t.Fatalf("code=%s err=%v", redaction.CodeOf(err), err)
	}
}

type ingestorStub struct {
	now        time.Time
	command    evidenceingest.Command
	received   []byte
	substitute bool
}

func (stub *ingestorStub) Execute(ctx context.Context, command evidenceingest.Command,
	source evidenceingest.Source) (evidenceingest.Result, error) {
	stub.command = command
	buffer := make([]byte, 7)
	for {
		count, err := source.ReadContext(ctx, buffer)
		stub.received = append(stub.received, buffer[:count]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return evidenceingest.Result{}, err
		}
	}
	artifact := domain.ArtifactRef{Digest: command.ExpectedDigest, MediaType: command.MediaType,
		Classification: command.Classification, Length: command.ExpectedLength}
	if stub.substitute {
		artifact.Digest = adapterDigest("substitute")
	}
	manifest := domain.ArtifactRef{Digest: adapterDigest("manifest"), MediaType: "application/vnd.coh.artifact-manifest+json",
		Classification: command.Classification, Length: 512}
	contextDigest := func(artifact domain.ArtifactRef) string {
		request := evidenceingest.StageRequest{Case: command.Case,
			ExpectedDigest: artifact.Digest, ExpectedLength: artifact.Length, MediaType: artifact.MediaType,
			Classification: artifact.Classification, KeyProfile: command.KeyProfile, KeyProfileDigest: command.KeyProfileDigest,
			Deadline: command.Deadline}
		value, _ := evidenceingest.EncryptionContextBindingDigest(request)
		return value
	}
	published := func(artifact domain.ArtifactRef) evidenceingest.PublishedObject {
		return evidenceingest.PublishedObject{Case: command.Case,
			PlaintextDigest: artifact.Digest, PlaintextLength: artifact.Length, CiphertextDigest: adapterDigest("cipher-" + artifact.Digest),
			CiphertextLength: artifact.Length + 256, EncryptionFormat: evidenceingest.EncryptionFormatVersion,
			EncryptionContextDigest: contextDigest(artifact), LocatorDigest: adapterDigest("locator-" + artifact.Digest)}
	}
	intent, _ := evidenceingest.CommandBindingDigest(command)
	transport, _ := evidenceingest.TransportBindingDigest(command.Transport)
	receipt := evidenceingest.Receipt{SchemaVersion: evidenceingest.ReceiptSchemaVersion, ContractVersion: evidenceingest.ContractVersion,
		RequestID: command.RequestID, Case: command.Case, ActorID: command.ActorID, ActorRevision: command.ActorRevision,
		IntentDigest: intent, IdempotencyDigest: evidenceingest.IdempotencyBindingDigest(command.IdempotencyKey),
		AuthorizationDigest: adapterDigest("authorization"), DecisionDigest: adapterDigest("decision"),
		RevocationDigest: adapterDigest("revocation"), TransportDigest: transport, Artifact: artifact, Manifest: manifest,
		EncryptedArtifact: published(artifact), EncryptedManifest: published(manifest),
		ManifestProvenanceDigest: adapterDigest("provenance"), AuditEventDigest: adapterDigest("audit"), CreatedAt: stub.now}
	receipt.ReceiptDigest, _ = evidenceingest.ReceiptBindingDigest(receipt)
	return evidenceingest.Result{Artifact: artifact, Manifest: manifest, Receipt: receipt}, nil
}

type adapterSource struct {
	value  []byte
	offset int
}

func (source *adapterSource) ReadContext(ctx context.Context, destination []byte) (int, error) {
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
func (source *adapterSource) Close() error { return nil }

func parentCase() domain.CaseRef {
	return domain.CaseRef{OrganizationID: adapterID("org"), TenantID: adapterID("tenant"), CaseID: adapterID("case")}
}
func adapterEvidence(seed, media, classification string, length int64) redaction.EvidenceReference {
	return redaction.EvidenceReference{Artifact: domain.ArtifactRef{Digest: adapterDigest(seed), MediaType: media, Classification: classification, Length: length},
		Manifest:                 domain.ArtifactRef{Digest: adapterDigest(seed + "-manifest"), MediaType: "application/vnd.coh.artifact-manifest+json", Classification: classification, Length: 512},
		ManifestProvenanceDigest: adapterDigest(seed + "-provenance"), IngestionReceiptDigest: adapterDigest(seed + "-receipt")}
}
func adapterDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func bytesDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func adapterID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&15 | 0x70
	sum[8] = sum[8]&63 | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
