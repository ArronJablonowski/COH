package evidenceingest

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	testOrg      = "0199a314-1001-7001-8001-000000000001"
	testTenant   = "0199a314-1002-7002-8002-000000000002"
	testCase     = "0199a314-1003-7003-8003-000000000003"
	testActor    = "0199a314-1004-7004-8004-000000000004"
	testRequest  = "0199a314-1005-7005-8005-000000000005"
	testDecision = "0199a314-1006-7006-8006-000000000006"
	testManifest = "0199a314-1007-7007-8007-000000000007"
)

var testNow = time.Now().UTC().Add(time.Hour).Truncate(time.Second)

func validCommand() Command {
	identity := "sensor://restricted/host-17/security-events"
	return Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequest, IdempotencyKey: "ingest-security-events-1",
		Case:    domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase},
		ActorID: testActor, ActorRevision: 3, ExpectedDigest: testDigest("plaintext"), ExpectedLength: 64,
		MediaType: "application/json", Classification: "internal",
		Source: SourceInput{Kind: UploadSource, Identity: identity, IdentityDigest: SourceIdentityDigest(identity),
			CollectionMethod: "secure_upload", CollectionMethodVersion: "1.0.0", CollectedAt: testNow},
		ParentArtifacts: []domain.ArtifactRef{}, ParentManifestDigests: []string{}, Components: []ComponentVersion{},
		KeyProfile: "operator_evidence", KeyProfileDigest: testDigest("key-profile"),
		PolicyDigest: testDigest("policy"), Transport: TransportContext{Mode: MTLS,
			PeerIdentityDigest: testDigest("peer"), ChannelBindingDigest: testDigest("channel")},
		Deadline: testNow.Add(time.Hour)}
}

func validAuthorization(command Command) AuthorizationRequest {
	intent, _ := CommandBindingDigest(command)
	value := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: command, CaseRevision: 2, CaseState: "open",
		CaseClassification: "restricted", CaseProvenanceDigest: testDigest("case-provenance")}
	value.AuthorizationDigest, _ = AuthorizationBindingDigest(value)
	return value
}

func validDecision(command Command, authorization AuthorizationRequest) Decision {
	transport, _ := TransportBindingDigest(command.Transport)
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: testDecision, AuthorizationDigest: authorization.AuthorizationDigest,
		IntentDigest: authorization.IntentDigest, Case: command.Case, ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, ArtifactDigest: command.ExpectedDigest,
		ArtifactLength: command.ExpectedLength, PolicyDigest: command.PolicyDigest,
		KeyProfileDigest: command.KeyProfileDigest, TransportDigest: transport,
		RevocationDigest: testDigest("revocation"), Outcome: "allow", ReasonCode: "ingestion_allowed",
		IssuedAt: testNow, ExpiresAt: testNow.Add(time.Minute), Revision: 1}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value
}

func validManifest(command Command, authorization AuthorizationRequest, decision Decision) ArtifactManifest {
	artifact := domain.ArtifactRef{Digest: command.ExpectedDigest, MediaType: command.MediaType,
		Classification: command.Classification, Length: command.ExpectedLength}
	stage := StageRequest{Case: command.Case, ExpectedDigest: command.ExpectedDigest,
		ExpectedLength: command.ExpectedLength, MediaType: command.MediaType,
		Classification: command.Classification, KeyProfile: command.KeyProfile,
		KeyProfileDigest: command.KeyProfileDigest, Deadline: command.Deadline}
	encryptionContext, _ := EncryptionContextBindingDigest(stage)
	value := ArtifactManifest{SchemaVersion: ManifestSchemaVersion, ContractVersion: ContractVersion,
		ManifestID: testManifest, Case: command.Case, Artifact: artifact, Source: command.Source,
		ParentArtifacts: command.ParentArtifacts, ParentManifestDigests: command.ParentManifestDigests,
		Components: command.Components, ActorID: command.ActorID, ActorRevision: command.ActorRevision,
		PolicyDigest: command.PolicyDigest, AuthorizationDigest: authorization.AuthorizationDigest,
		DecisionDigest: decision.DecisionDigest, RevocationDigest: decision.RevocationDigest,
		TransportDigest: decision.TransportDigest, EncryptionContextDigest: encryptionContext,
		AuditEventDigest: testDigest("audit"), CreatedAt: testNow, Revision: 1}
	value.ProvenanceDigest, _ = ManifestProvenanceDigest(value)
	return value
}

func validEncryptedObject(command Command, digestValue string, length int64, mediaType, classification string) EncryptedObject {
	stage := StageRequest{Case: command.Case, ExpectedDigest: digestValue, ExpectedLength: length,
		MediaType: mediaType, Classification: classification, KeyProfile: command.KeyProfile,
		KeyProfileDigest: command.KeyProfileDigest, Deadline: command.Deadline}
	contextDigest, _ := EncryptionContextBindingDigest(stage)
	return EncryptedObject{SchemaVersion: EncryptedObjectSchemaVersion, ContractVersion: ContractVersion,
		Status: Published, Case: command.Case, PlaintextDigest: digestValue, PlaintextLength: length,
		CiphertextDigest: testDigest("cipher-" + digestValue), CiphertextLength: length + 256,
		MediaType: mediaType, Classification: classification, EncryptionFormat: EncryptionFormatVersion,
		ChunkSize: 65536, ChunkCount: 1, KeyReference: "operator_evidence_key", KeyRevision: 1,
		KeyAlgorithm: "aes-256-gcm", WrappedKeyDigest: testDigest("wrapped-" + digestValue),
		EncryptionContextDigest: contextDigest, LocatorDigest: testDigest("locator-" + digestValue), CreatedAt: testNow}
}

func publishedFrom(value EncryptedObject) PublishedObject {
	return PublishedObject{Case: value.Case, PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, CiphertextDigest: value.CiphertextDigest,
		CiphertextLength: value.CiphertextLength, EncryptionFormat: value.EncryptionFormat,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest}
}

func validReceipt(command Command, authorization AuthorizationRequest, decision Decision,
	manifest ArtifactManifest) Receipt {
	manifestCanonical, _ := CanonicalManifest(manifest)
	manifestRef := domain.ArtifactRef{Digest: rawDigest(manifestCanonical),
		MediaType: "application/vnd.coh.artifact-manifest+json", Classification: command.Classification,
		Length: int64(len(manifestCanonical))}
	artifactObject := validEncryptedObject(command, command.ExpectedDigest, command.ExpectedLength,
		command.MediaType, command.Classification)
	manifestObject := validEncryptedObject(command, manifestRef.Digest, manifestRef.Length,
		manifestRef.MediaType, manifestRef.Classification)
	value := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: command.RequestID, Case: command.Case, ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, IntentDigest: authorization.IntentDigest,
		IdempotencyDigest:   IdempotencyBindingDigest(command.IdempotencyKey),
		AuthorizationDigest: authorization.AuthorizationDigest, DecisionDigest: decision.DecisionDigest,
		RevocationDigest: decision.RevocationDigest, TransportDigest: decision.TransportDigest,
		Artifact: manifest.Artifact, Manifest: manifestRef, EncryptedArtifact: publishedFrom(artifactObject),
		EncryptedManifest: publishedFrom(manifestObject), ManifestProvenanceDigest: manifest.ProvenanceDigest,
		AuditEventDigest: manifest.AuditEventDigest, CreatedAt: testNow}
	value.ReceiptDigest, _ = ReceiptBindingDigest(value)
	return value
}

func testDigest(value string) string { return rawDigest([]byte(value)) }
func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
