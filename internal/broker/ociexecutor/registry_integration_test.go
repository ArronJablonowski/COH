package ociexecutor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

func TestExecutorUsesActualSignedRegistryAndLivePublisherAuthority(t *testing.T) {
	request := testRequest()
	registry, publisher := signedOCIRegistry(t, request.Tool)
	authorizer := &fakeAuthorizer{authority: DispatchAuthority{AuthorizationID: "0198d6c4-7777-7777-8777-777777777777",
		DecisionDigest: testDecisionDigest, RuntimeCeiling: "T3", AuthorizedAt: formatTime(testNow.Add(-time.Second)),
		ValidUntil: formatTime(testNow.Add(time.Minute))}}
	network := &fakeNetworkBroker{clock: fixedClock{testNow}}
	runtime := &fakeRuntime{}
	executor, err := New(registry, authorizer, testContainmentNetwork(network), runtime, testOCIExecutionTracker(), fixedClock{testNow}, []Registration{testRegistration()})
	if err != nil {
		t.Fatal(err)
	}
	request.Publisher = publisher
	if _, err := executor.Execute(context.Background(), request); err != nil {
		t.Fatalf("signed execution error=%v", err)
	}
	revoked := request
	revoked.AttemptID = "0198d6c4-5555-7555-8555-555555555556"
	revoked.Publisher.Active = false
	result, err := executor.Execute(context.Background(), revoked)
	if Code(err) != Denied || Reason(err) != "registry_publisher_authority" || result.Provenance.Outcome != "denied" || runtime.calls != 1 {
		t.Fatalf("revoked result=%+v error=%v runtime calls=%d", result, err, runtime.calls)
	}
}

func signedOCIRegistry(t *testing.T, tool toolregistry.ToolReference) (*toolregistry.Registry, toolregistry.PublisherAuthority) {
	t.Helper()
	manifest := toolregistry.Manifest{SchemaVersion: toolregistry.ManifestSchemaVersion,
		ContractVersion: toolregistry.ContractVersion, ManifestID: "0198d6c4-6666-7666-8666-666666666666",
		ToolName: tool.Name, ToolVersion: tool.Version, ArtifactDigest: tool.ArtifactDigest, MaximumActionTier: "T3",
		PublisherID: "0198d6c4-8888-7888-8888-888888888888", ReviewID: "0198d6c4-9999-7999-8999-999999999999",
		ReviewRevision: 1, ReviewDecision: "approved",
		ReviewerActorIDs: []string{"0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa"}, ThreatModelDigest: testDecisionDigest,
		ReviewedAt: registryTime(testNow.Add(-time.Hour)), ValidFrom: registryTime(testNow.Add(-time.Minute)),
		ValidUntil: registryTime(testNow.Add(time.Hour)),
		Operations: []toolregistry.Operation{{Name: "execute", InputSchemaVersion: "coh.tool-input/v1",
			InputFields:        []toolregistry.InputField{{Name: "message", Type: "string", Required: true, MaximumBytes: 64, Enum: []string{}}},
			BaselineActionTier: "T2", MaximumActionTier: "T3", IsolationClass: "oci_sandbox",
			CredentialClasses: []string{"none"}, ResourceLimits: testLimits(), NetworkPolicy: noNetwork(),
			CancellationMode: "cooperative", RetryMode: "never"}}}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := toolregistry.Decode(context.Background(), manifestJSON)
	if err != nil {
		t.Fatalf("Decode() error=%v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	authority := toolregistry.PublisherAuthority{PublisherID: manifest.PublisherID, KeyID: "publisher.primary",
		KeyRevision: 1, ApprovalRevision: 1, Active: true, Approved: true,
		PublicKey: privateKey.Public().(ed25519.PublicKey)}
	signature := ed25519.Sign(privateKey, append([]byte(toolregistry.SignatureDomain), validated.CanonicalBytes()...))
	envelope := toolregistry.Envelope{SchemaVersion: toolregistry.EnvelopeSchemaVersion,
		ContractVersion: toolregistry.ContractVersion, Manifest: manifest, ManifestDigest: validated.Digest,
		PublisherID: authority.PublisherID, PublisherKeyID: authority.KeyID, PublisherKeyRevision: authority.KeyRevision,
		SignatureAlgorithm: toolregistry.SignatureAlgorithm, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.NewRegistry(registryClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Admit(context.Background(), envelopeJSON, authority); err != nil {
		t.Fatalf("Admit() error=%v", err)
	}
	return registry, authority
}

type registryClock struct{ value time.Time }

func (clock registryClock) Now() time.Time { return clock.value }

func registryTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
