package extensionlifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var testNow = time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type admissionFixture struct {
	envelope []byte
	intent   []byte
	snapshot AuthoritySnapshot
}

func TestAdmissionIsCanonicalImmutableAndCurrent(t *testing.T) {
	fixture := newAdmissionFixture(t)
	validated, err := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
	if err != nil {
		t.Fatalf("VerifyAdmission() error = %v", err)
	}
	if validated.Envelope().ManifestDigest() != fixture.snapshot.ManifestDigest ||
		validated.Intent().Digest() != validated.Intent().Value().IntentDigest || validated.AuthorityRevision() != 7 {
		t.Fatalf("validated admission = %#v", validated)
	}
	envelopeBytes := validated.Envelope().CanonicalBytes()
	intentBytes := validated.Intent().CanonicalBytes()
	envelopeBytes[0], intentBytes[0] = 'x', 'x'
	if validated.Envelope().CanonicalBytes()[0] != '{' || validated.Intent().CanonicalBytes()[0] != '{' {
		t.Fatal("validated bytes alias caller mutation")
	}
	replayed, err := VerifyAdmission(context.Background(), validated.Envelope().CanonicalBytes(), validated.Intent().CanonicalBytes(), fixture.snapshot, fixedClock{testNow})
	if err != nil || !bytes.Equal(replayed.Envelope().CanonicalBytes(), validated.Envelope().CanonicalBytes()) {
		t.Fatalf("canonical replay err=%v", err)
	}
}

func TestAdmissionFailsClosedForAuthorityDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthoritySnapshot)
		reason string
	}{
		{"promotion", func(value *AuthoritySnapshot) { value.PromotionActive = false }, "authority_inactive"},
		{"review", func(value *AuthoritySnapshot) { value.ReviewActive = false }, "authority_inactive"},
		{"review drift", func(value *AuthoritySnapshot) { value.ReviewDigest = testDigest('f') }, "authority_inactive"},
		{"qualification", func(value *AuthoritySnapshot) { value.QualificationActive = false }, "authority_inactive"},
		{"policy", func(value *AuthoritySnapshot) { value.PolicyAllowed = false }, "authority_inactive"},
		{"audit", func(value *AuthoritySnapshot) { value.AuditAvailable = false }, "authority_inactive"},
		{"dependency", func(value *AuthoritySnapshot) { value.DependenciesQualified = false }, "authority_inactive"},
		{"artifact revocation", func(value *AuthoritySnapshot) { value.ArtifactRevoked = true }, "authority_inactive"},
		{"profile", func(value *AuthoritySnapshot) { value.ProfileRevision++ }, "profile_binding"},
		{"registry", func(value *AuthoritySnapshot) { value.RegistryRevision++ }, "authority_binding"},
		{"scope", func(value *AuthoritySnapshot) { value.Scope.TaskID = "0198d6c4-0009-7000-8000-000000000009" }, "scope_or_permission_widening"},
		{"permission", func(value *AuthoritySnapshot) { value.Permissions = []string{"write.timeline"} }, "scope_or_permission_widening"},
		{"stale", func(value *AuthoritySnapshot) { value.ExpiresAt = testNow }, "authority_snapshot"},
		{"revoked signer", func(value *AuthoritySnapshot) {
			value.Records[0].Revoked = true
			value.Records[0].RevocationRevision = 9
		}, "signer_revoked"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAdmissionFixture(t)
			fixture.snapshot.Records = slices.Clone(fixture.snapshot.Records)
			test.mutate(&fixture.snapshot)
			_, err := VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, fixedClock{testNow})
			if Reason(err) != test.reason {
				t.Fatalf("reason=%q err=%v", Reason(err), err)
			}
		})
	}
}

func TestStrictDecodersAndReservedAuthorityDenials(t *testing.T) {
	fixture := newAdmissionFixture(t)
	var envelope map[string]any
	if err := json.Unmarshal(fixture.envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["unknown"] = true
	unknown, _ := json.Marshal(envelope)
	if _, err := DecodeEnvelope(context.Background(), unknown); Reason(err) != "document_decoding" {
		t.Fatalf("unknown err=%v", err)
	}
	duplicate := bytes.Replace(fixture.envelope, []byte(`{"contract_version"`), []byte(`{"schema_version":"coh.signed-extension-manifest/v1","contract_version"`), 1)
	if _, err := DecodeEnvelope(context.Background(), duplicate); Reason(err) != "document_decoding" {
		t.Fatalf("duplicate err=%v", err)
	}

	valid := validManifest()
	valid.Registrations[0].Capability.CapabilityID = "authority.broker"
	if _, _, err := CanonicalManifest(valid); Reason(err) != "reserved_authority" {
		t.Fatalf("reserved err=%v", err)
	}
	valid = validManifest()
	valid.Registrations[0].ProviderID = "coh.audit"
	if _, _, err := CanonicalManifest(valid); Reason(err) != "reserved_authority" {
		t.Fatalf("provider err=%v", err)
	}
}

func TestAuthoritySnapshotCannotBeSerialized(t *testing.T) {
	fixture := newAdmissionFixture(t)
	if _, err := json.Marshal(fixture.snapshot); err == nil {
		t.Fatal("authority snapshot serialized")
	}
	var snapshot AuthoritySnapshot
	if err := json.Unmarshal([]byte(`{}`), &snapshot); err == nil {
		t.Fatal("authority snapshot accepted JSON")
	}
}

func newAdmissionFixture(t *testing.T) admissionFixture {
	t.Helper()
	manifest := validManifest()
	manifestBytes, manifestDigest, err := CanonicalManifest(manifest)
	if err != nil || len(manifestBytes) == 0 {
		t.Fatalf("CanonicalManifest() err=%v", err)
	}
	keys := map[string]ed25519.PrivateKey{}
	for _, role := range []string{"administrator", "owner", "publisher", "reviewer"} {
		keys[role] = testKey(role)
	}
	envelope := Envelope{SchemaVersion: EnvelopeSchemaVersion, ContractVersion: ContractVersion, Manifest: manifest, ManifestDigest: manifestDigest,
		PublisherSignature: testSignature("publisher", "0198d6c4-0002-7000-8000-000000000002", manifestDigest, publisherSignatureDomain, keys["publisher"]),
		ReviewSignatures:   []Signature{testSignature("reviewer", "0198d6c4-0003-7000-8000-000000000003", manifestDigest, reviewerSignatureDomain, keys["reviewer"])},
		OwnerSignature:     testSignature("owner", manifest.OwnerActorID, manifestDigest, ownerSignatureDomain, keys["owner"])}
	envelopeBytes := canonicalJSON(t, envelope)
	scope := ExactScope{OrganizationID: "0198d6c4-0005-7000-8000-000000000005", TenantID: "0198d6c4-0006-7000-8000-000000000006", CaseID: "0198d6c4-0007-7000-8000-000000000007"}
	scopeDigest, _ := ScopeDigest(scope)
	permissions := []string{"read.timeline"}
	permissionsDigest, _ := PermissionsDigest(permissions)
	intent := ActivationIntent{SchemaVersion: IntentSchemaVersion, ContractVersion: ContractVersion, RequestID: "0198d6c4-0010-7000-8000-000000000010", IdempotencyKey: "0198d6c4-0011-7000-8000-000000000011", ActorID: "0198d6c4-0004-7000-8000-000000000004", ActorKind: "administrator", OrganizationID: scope.OrganizationID, TenantID: scope.TenantID, ExtensionID: manifest.ExtensionID, ManifestDigest: manifestDigest, Operation: "activate", Mode: "maintenance", RequestedScopeDigest: scopeDigest, RequestedPermissionsDigest: permissionsDigest, ExpectedPredecessorManifestDigest: "", RollbackAuthorizationDigest: "", ActiveProfileRevision: 3, ProfileBindingDigest: testDigest('b'), CompositionDigest: testDigest('c'), CapabilityGraphDigest: testDigest('d'), ExpectedLifecycleRevision: 0, ExpectedRegistryRevision: 11, PolicyDecisionDigest: testDigest('e'), PromotionSnapshotDigest: testDigest('a'), QualificationSnapshotDigest: testDigest('b'), AuditAvailabilityDigest: testDigest('c'), EStopState: "armed", EStopRevision: 5, MaximumDrainDurationMS: 30000, IssuedAt: "2026-08-28T07:59:00Z", DeadlineAt: "2026-08-28T08:01:00Z"}
	intent, err = SealIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.AdministratorSignature = testSignature("administrator", intent.ActorID, intent.IntentDigest, administratorSignatureDomain, keys["administrator"])
	intentBytes := canonicalJSON(t, intent)
	records := []SigningAuthority{
		testAuthority("administrator", intent.ActorID, keys["administrator"]), testAuthority("owner", manifest.OwnerActorID, keys["owner"]),
		testAuthority("publisher", envelope.PublisherSignature.ActorID, keys["publisher"]), testAuthority("reviewer", envelope.ReviewSignatures[0].ActorID, keys["reviewer"]),
	}
	sort.Slice(records, func(i, j int) bool {
		return authorityIdentity(records[i].Role, records[i].ActorID, records[i].KeyID) < authorityIdentity(records[j].Role, records[j].ActorID, records[j].KeyID)
	})
	snapshot := AuthoritySnapshot{CreatedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute), AuthorityRevision: 7, RegistryRevision: 11, ManifestDigest: manifestDigest, ReviewDigest: manifest.ReviewDigest, PromotionSnapshotDigest: intent.PromotionSnapshotDigest, QualificationSnapshotDigest: intent.QualificationSnapshotDigest, PolicyDecisionDigest: intent.PolicyDecisionDigest, AuditAvailabilityDigest: intent.AuditAvailabilityDigest, ProfileRevision: 3, ProfileBindingDigest: intent.ProfileBindingDigest, CompositionDigest: intent.CompositionDigest, CapabilityGraphDigest: intent.CapabilityGraphDigest, EStopState: "armed", EStopRevision: 5, Scope: scope, Permissions: permissions, PromotionActive: true, ReviewActive: true, QualificationActive: true, PolicyAllowed: true, AuditAvailable: true, DependenciesQualified: true, Records: records}
	return admissionFixture{envelope: envelopeBytes, intent: intentBytes, snapshot: snapshot}
}

func validManifest() Manifest {
	return Manifest{SchemaVersion: ManifestSchemaVersion, ContractVersion: ContractVersion, ExtensionID: "0198d6c4-0001-7000-8000-000000000001", ExtensionName: "timeline_provider", ExtensionVersion: "1.0.0", ExtensionKind: "skill_provider", OwnerActorID: "0198d6c4-0008-7000-8000-000000000008", OwnerModule: "timeline_extension", ArtifactDigest: testDigest('1'), SBOMDigest: testDigest('2'), ProvenanceDigest: testDigest('3'), TestEvidenceDigest: testDigest('4'), ThreatModelDigest: testDigest('5'), DeclaredPermissions: []string{"read.timeline"}, DeclaredScopeTypes: []string{"case", "organization", "task", "tenant"}, Dependencies: []CapabilityRef{{CapabilityID: "analysis.events", CapabilityVersion: "1.0.0"}}, Registrations: []Registration{{RegistrationID: "timeline_reader", Role: "provider", Capability: CapabilityRef{CapabilityID: "analysis.timeline", CapabilityVersion: "1.0.0"}, ProviderID: "extension.timeline", Permissions: []string{"read.timeline"}, ScopeTypes: []string{"case", "organization", "tenant"}, ResourceLimitsDigest: testDigest('6')}}, MaximumActiveWork: 16, MaximumDrainDurationMS: 60000, ReviewDigest: testDigest('7'), ValidFrom: "2026-08-28T00:00:00Z", ValidUntil: "2026-08-29T00:00:00Z"}
}

func testAuthority(role, actorID string, private ed25519.PrivateKey) SigningAuthority {
	return SigningAuthority{Role: role, ActorID: actorID, KeyID: role + "_key", KeyRevision: 1, ApprovalRevision: 1, AuthorityRevision: 7, ValidFrom: testNow.Add(-time.Hour), ValidUntil: testNow.Add(time.Hour), Active: true, PublicKey: slices.Clone(private.Public().(ed25519.PublicKey))}
}
func testSignature(role, actorID, digest, domain string, private ed25519.PrivateKey) Signature {
	raw, _ := hex.DecodeString(digest[len("sha256:"):])
	return Signature{ActorID: actorID, KeyID: role + "_key", KeyRevision: 1, ApprovalRevision: 1, Algorithm: SignatureAlgorithm, Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(domain), raw...)))}
}
func testKey(role string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("CYB-184/" + role))
	return ed25519.NewKeyFromSeed(seed[:])
}
func testDigest(value byte) string { return "sha256:" + string(bytes.Repeat([]byte{value}, 64)) }
func canonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
