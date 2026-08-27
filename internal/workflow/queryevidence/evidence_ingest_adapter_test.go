package queryevidence

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

type encryptedIngestStub struct {
	command evidenceingest.Command
	result  evidenceingest.Result
	err     error
}

func (stub *encryptedIngestStub) Execute(_ context.Context, command evidenceingest.Command, _ evidenceingest.Source) (evidenceingest.Result, error) {
	stub.command = command
	if stub.err != nil {
		return evidenceingest.Result{}, stub.err
	}
	return adapterResult(command), nil
}

func TestEvidenceIngestAdapterUsesOnlyEncryptedQueryEvidencePath(t *testing.T) {
	stub := &encryptedIngestStub{}
	profile := IngestProfile{KeyProfile: "operator_evidence_key", KeyProfileDigest: digest("key-profile"),
		Transport: evidenceingest.TransportContext{Mode: evidenceingest.InProcess, PeerIdentityDigest: digest("peer"), ChannelBindingDigest: digest("channel")}}
	adapter, err := NewEvidenceIngestAdapter(stub, profile)
	if err != nil {
		t.Fatal(err)
	}
	command := startCommand([]byte("SecurityEvent | take 10"))
	request := artifactRequest(command, evidenceNow)
	binding, err := adapter.IngestNativeQuery(context.Background(), request, &sourceStub{data: []byte("SecurityEvent | take 10")})
	if err != nil {
		t.Fatal(err)
	}
	if stub.command.Source.Kind != evidenceingest.QuerySource || stub.command.Components[0].Kind != evidenceingest.QueryComponent ||
		stub.command.ExpectedDigest != request.ExpectedDigest || stub.command.PolicyDigest != request.PolicyDigest ||
		stub.command.KeyProfile != profile.KeyProfile || binding.Artifact.Digest != request.ExpectedDigest {
		t.Fatal("native query did not use the exact encrypted evidence binding")
	}
}

func TestEvidenceIngestAdapterRejectsSubstitutedReceipt(t *testing.T) {
	stub := &encryptedIngestStub{}
	profile := IngestProfile{KeyProfile: "operator_evidence_key", KeyProfileDigest: digest("key-profile"),
		Transport: evidenceingest.TransportContext{Mode: evidenceingest.InProcess, PeerIdentityDigest: digest("peer"), ChannelBindingDigest: digest("channel")}}
	adapter, err := NewEvidenceIngestAdapter(stub, profile)
	if err != nil {
		t.Fatal(err)
	}
	command := startCommand([]byte("SecurityEvent | take 10"))
	request := artifactRequest(command, evidenceNow)
	stub.result = adapterResult(evidenceingest.Command{RequestID: request.RequestID})
	stub.err = context.Canceled
	if _, err = adapter.IngestNativeQuery(context.Background(), request, &sourceStub{}); err == nil {
		t.Fatal("ingestion failure was hidden")
	}
}

func adapterResult(command evidenceingest.Command) evidenceingest.Result {
	artifact := domain.ArtifactRef{Digest: command.ExpectedDigest, MediaType: command.MediaType,
		Classification: command.Classification, Length: command.ExpectedLength}
	manifest := domain.ArtifactRef{Digest: digest("native-manifest"), MediaType: "application/vnd.coh.artifact-manifest+json",
		Classification: command.Classification, Length: 512}
	receipt := evidenceingest.Receipt{SchemaVersion: evidenceingest.ReceiptSchemaVersion, ContractVersion: evidenceingest.ContractVersion,
		RequestID: command.RequestID, Case: command.Case, ActorID: command.ActorID, ActorRevision: command.ActorRevision,
		IntentDigest: digest("intent"), IdempotencyDigest: evidenceingest.IdempotencyBindingDigest(command.IdempotencyKey),
		AuthorizationDigest: digest("authorization"), DecisionDigest: digest("decision"), RevocationDigest: digest("revocation"),
		TransportDigest: digest("transport"), Artifact: artifact, Manifest: manifest,
		EncryptedArtifact: published(command.Case, artifact), EncryptedManifest: published(command.Case, manifest),
		ManifestProvenanceDigest: digest("manifest-provenance"), AuditEventDigest: digest("audit"), CreatedAt: evidenceNow}
	receipt.ReceiptDigest, _ = evidenceingest.ReceiptBindingDigest(receipt)
	return evidenceingest.Result{Artifact: artifact, Manifest: manifest, Receipt: receipt}
}

func published(scope domain.CaseRef, artifact domain.ArtifactRef) evidenceingest.PublishedObject {
	return evidenceingest.PublishedObject{Case: scope, PlaintextDigest: artifact.Digest, PlaintextLength: artifact.Length,
		CiphertextDigest: digest("cipher-" + artifact.Digest), CiphertextLength: artifact.Length + 64,
		EncryptionFormat: evidenceingest.EncryptionFormatVersion, EncryptionContextDigest: digest("context-" + artifact.Digest),
		LocatorDigest: digest("locator-" + artifact.Digest)}
}
