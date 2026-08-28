package kustovalidator

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

func TestNativeOperationIsCredentiallessAndNetworkDenied(t *testing.T) {
	t.Parallel()
	operation := NativeOperation()
	if operation.BaselineActionTier != "T0" || operation.MaximumActionTier != "T0" ||
		operation.IsolationClass != "native_restricted" || len(operation.CredentialClasses) != 1 ||
		operation.CredentialClasses[0] != "none" || operation.NetworkPolicy.Mode != "none" ||
		operation.NetworkPolicy.PublicInternetAllowed || operation.NetworkPolicy.MetadataAllowed ||
		len(operation.NetworkPolicy.Protocols) != 0 || operation.NetworkPolicy.MaximumConnections != 0 {
		t.Fatalf("unsafe native operation: %+v", operation)
	}
	if len(operation.InputFields) != 8 || !operation.InputFields[0].Required {
		t.Fatalf("unexpected chunk surface: %+v", operation.InputFields)
	}
	for index, field := range operation.InputFields {
		if field.Name != "request_chunk_0"+string(rune('0'+index)) || field.Type != "string" ||
			field.Required != (index == 0) || field.MaximumBytes != 61_440 {
			t.Fatalf("chunk %d = %+v", index, field)
		}
	}
}

func TestNativeOperationPassesSignedRegistryPath(t *testing.T) {
	t.Parallel()
	manifest := toolregistry.Manifest{
		SchemaVersion: toolregistry.ManifestSchemaVersion, ContractVersion: toolregistry.ContractVersion,
		ManifestID: "0198d6c4-1111-7111-8111-111111111111", ToolName: NativeToolName,
		ToolVersion: NativeToolVersion, ArtifactDigest: fixtureDigest("a"), MaximumActionTier: "T0",
		PublisherID: "0198d6c4-2222-7222-8222-222222222222", ReviewID: "0198d6c4-3333-7333-8333-333333333333",
		ReviewRevision: 1, ReviewDecision: "approved",
		ReviewerActorIDs: []string{"0198d6c4-4444-7444-8444-444444444444"}, ThreatModelDigest: fixtureDigest("b"),
		ReviewedAt: "2026-08-27T00:00:00.000000000Z", ValidFrom: "2026-08-27T00:00:01.000000000Z",
		ValidUntil: "2027-08-27T00:00:01.000000000Z", Operations: []toolregistry.Operation{NativeOperation()},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := toolregistry.Decode(context.Background(), encoded)
	if err != nil {
		t.Fatalf("reviewed manifest denied: %v", err)
	}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	authority := toolregistry.PublisherAuthority{
		PublisherID: manifest.PublisherID, KeyID: "publisher.kusto", KeyRevision: 1,
		ApprovalRevision: 1, Active: true, Approved: true, PublicKey: private.Public().(ed25519.PublicKey),
	}
	message := append([]byte(toolregistry.SignatureDomain), validated.CanonicalBytes()...)
	envelope := toolregistry.Envelope{
		SchemaVersion: toolregistry.EnvelopeSchemaVersion, ContractVersion: toolregistry.ContractVersion,
		Manifest: validated.Value(), ManifestDigest: validated.Digest, PublisherID: manifest.PublisherID,
		PublisherKeyID: authority.KeyID, PublisherKeyRevision: authority.KeyRevision,
		SignatureAlgorithm: toolregistry.SignatureAlgorithm,
		Signature:          base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message)),
	}
	signed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Verify(context.Background(), signed, authority); err != nil {
		t.Fatalf("signed Kusto helper manifest denied: %v", err)
	}
}

func fixtureDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
