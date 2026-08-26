package sqlite_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

const (
	skillOrg       = "0198d6c4-1001-7001-8001-000000000001"
	skillTenant    = "0198d6c4-1002-7002-8002-000000000002"
	skillCase      = "0198d6c4-1003-7003-8003-000000000003"
	skillTask      = "0198d6c4-1004-7004-8004-000000000004"
	skillOwner     = "0198d6c4-1005-7005-8005-000000000005"
	skillPublisher = "0198d6c4-1006-7006-8006-000000000006"
	skillReviewer  = "0198d6c4-1007-7007-8007-000000000007"
	skillConsumer  = "0198d6c4-1008-7008-8008-000000000008"
)

type skillClock struct{ now time.Time }

func (clock skillClock) Now() time.Time { return clock.now }

type skillAuditor struct{}

func (skillAuditor) Append(_ context.Context,
	event skillregistry.AuditEvent) (skillregistry.AuditReceipt, error) {
	digest, err := skillregistry.DigestAuditEvent(event)
	if err != nil {
		return skillregistry.AuditReceipt{}, err
	}
	return skillregistry.AuditReceipt{EventID: event.EventID, EventDigest: digest,
		ReceiptDigest: skillDigest("receipt\x00" + digest)}, nil
}

type skillFixture struct {
	now          time.Time
	owner        skillregistry.SigningAuthority
	publisher    skillregistry.SigningAuthority
	reviewer     skillregistry.SigningAuthority
	review       skillregistry.ReviewAuthority
	ownerPrivate ed25519.PrivateKey
	pubPrivate   ed25519.PrivateKey
	revPrivate   ed25519.PrivateKey
}

func TestSkillRegistrySurvivesSQLiteCloseAndReopen(t *testing.T) {
	fixture := newSkillFixture()
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "coh.sqlite3")
	driver := openSkillSQLite(t, path, backup, fixture.now)
	registry, _ := composeSkillRegistry(t, driver, fixture)

	manifest := fixture.manifest()
	envelope, manifestDigest := fixture.envelope(t, manifest)
	request := fixture.promotion(t, envelope, manifestDigest)
	state, err := registry.Change(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openSkillSQLite(t, path, backup, fixture.now)
	t.Cleanup(func() { _ = driver.Close() })
	registry, repository := composeSkillRegistry(t, driver, fixture)
	loaded, found, err := repository.LoadState(context.Background(), skillOrg, skillTenant, "timeline_builder")
	if err != nil || !found || loaded.ProvenanceDigest != state.ProvenanceDigest {
		t.Fatalf("state did not survive restart: %#v %v", loaded, err)
	}
	version, found, err := repository.LoadVersion(context.Background(), skillOrg, skillTenant, manifestDigest)
	if err != nil || !found || !bytes.Equal(version.Envelope, envelope) {
		t.Fatalf("immutable envelope did not survive restart: %#v %v", version, err)
	}

	resolve := skillregistry.ResolveRequest{
		SchemaVersion: skillregistry.ResolveSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		RequestID: skillUUID("resolve"), OrganizationID: skillOrg, TenantID: skillTenant,
		CaseID: skillCase, TaskID: skillTask, ActorID: skillConsumer, SkillName: "timeline_builder",
		ExpectedManifestDigest: manifestDigest, RequiredPermission: "evidence.read",
		PolicyDigest: skillDigest("policy"), Deadline: fixture.now.Add(time.Hour),
	}
	access := skillregistry.AccessDecision{
		SchemaVersion: skillregistry.AccessSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		DecisionID: skillUUID("access"), PolicyDigest: resolve.PolicyDigest,
		OrganizationID: skillOrg, TenantID: skillTenant, CaseID: skillCase, TaskID: skillTask,
		ActorID: skillConsumer, SkillName: resolve.SkillName, ManifestDigest: manifestDigest,
		Permission: resolve.RequiredPermission, Outcome: "allow", Revision: 1,
		IssuedAt: fixture.now.Add(-time.Minute), ExpiresAt: fixture.now.Add(time.Hour),
	}
	access.DecisionDigest, _ = skillregistry.DigestAccessDecision(access)
	resolved, err := registry.Resolve(context.Background(), resolve, access,
		skillregistry.ResolutionAuthority{Publisher: fixture.publisher,
			Reviewers: []skillregistry.SigningAuthority{fixture.reviewer}, Review: fixture.review})
	if err != nil || resolved.ManifestDigest != manifestDigest ||
		resolved.ProvenanceDigest != state.ProvenanceDigest {
		t.Fatalf("restarted resolution failed: %#v %v", resolved, err)
	}

	replayed, err := registry.Change(context.Background(), request)
	if err != nil || replayed.ProvenanceDigest != state.ProvenanceDigest {
		t.Fatalf("durable replay did not recover exactly: %#v %v", replayed, err)
	}
}

func newSkillFixture() skillFixture {
	now := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	owner, ownerPrivate := skillAuthority("owner", skillOwner)
	publisher, pubPrivate := skillAuthority("publisher", skillPublisher)
	reviewer, revPrivate := skillAuthority("reviewer", skillReviewer)
	return skillFixture{now: now, owner: owner, publisher: publisher, reviewer: reviewer,
		review: skillregistry.ReviewAuthority{ReviewID: skillUUID("review"), Revision: 1,
			Decision: "approved", ReviewerIDs: []string{skillReviewer},
			EvidenceDigest: skillDigest("review"), Active: true},
		ownerPrivate: ownerPrivate, pubPrivate: pubPrivate, revPrivate: revPrivate}
}

func (fixture skillFixture) manifest() skillregistry.Manifest {
	return skillregistry.Manifest{
		SchemaVersion: skillregistry.ManifestSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		ManifestID: skillUUID("manifest"), SkillName: "timeline_builder", SkillVersion: "1.0.0",
		OwnerActorID: skillOwner, PublisherActorID: skillPublisher, ContentDigest: skillDigest("content"),
		Resources: []skillregistry.Resource{{Name: "instructions", Digest: skillDigest("resource"),
			MediaType: "text/markdown", Classification: "internal", Length: 128}},
		Permissions: []string{"evidence.read"}, TestSuiteDigest: skillDigest("suite"),
		TestEvidenceDigest: skillDigest("tests"), ThreatModelDigest: skillDigest("threat"),
		ReviewID: fixture.review.ReviewID, ReviewRevision: 1, ReviewDecision: "approved",
		ReviewerActorIDs: []string{skillReviewer}, ReviewEvidenceDigest: fixture.review.EvidenceDigest,
		ReviewedAt: fixture.now.Add(-2 * time.Hour), ValidFrom: fixture.now.Add(-time.Hour),
		ValidUntil: fixture.now.Add(48 * time.Hour),
	}
}

func (fixture skillFixture) envelope(t *testing.T,
	manifest skillregistry.Manifest) ([]byte, string) {
	t.Helper()
	payload, digest, err := skillregistry.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	value := skillregistry.Envelope{
		SchemaVersion: skillregistry.EnvelopeSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		Manifest: manifest, ManifestDigest: digest,
		PublisherSignature: fixture.signature(fixture.publisher, fixture.pubPrivate,
			skillregistry.ManifestDomain, payload),
		ReviewSignatures: []skillregistry.DetachedSignature{
			fixture.signature(fixture.reviewer, fixture.revPrivate, skillregistry.ReviewDomain, payload),
		},
	}
	encoded, err := skillregistry.CanonicalEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, digest
}

func (fixture skillFixture) promotion(t *testing.T, envelope []byte,
	manifestDigest string) skillregistry.ChangeRequest {
	t.Helper()
	command := skillregistry.ChangeCommand{
		SchemaVersion: skillregistry.CommandSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		CommandID: skillUUID("command"), Action: skillregistry.Promote,
		OrganizationID: skillOrg, TenantID: skillTenant, CaseID: skillCase, TaskID: skillTask,
		ActorID: skillOwner, SkillName: "timeline_builder", TargetManifestDigest: manifestDigest,
		ReasonDigest: skillDigest("reason"), CreatedAt: fixture.now.Add(-time.Minute),
		Deadline: fixture.now.Add(time.Hour),
	}
	payload, commandDigest, err := skillregistry.CanonicalChangeCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	signed := skillregistry.SignedChange{
		SchemaVersion: skillregistry.SignedCommandVersion, ContractVersion: skillregistry.ContractVersion,
		Command: command, CommandDigest: commandDigest,
		Signature: fixture.signature(fixture.owner, fixture.ownerPrivate,
			skillregistry.CommandDomain, payload),
	}
	signedBytes, err := skillregistry.CanonicalSignedChange(signed)
	if err != nil {
		t.Fatal(err)
	}
	policy := skillregistry.PolicyDecision{
		SchemaVersion: skillregistry.PolicySchemaVersion, ContractVersion: skillregistry.ContractVersion,
		DecisionID: skillUUID("policy"), PolicyDigest: skillDigest("policy-source"),
		OrganizationID: skillOrg, TenantID: skillTenant, CaseID: skillCase, TaskID: skillTask,
		ActorID: skillOwner, Action: skillregistry.Promote, SkillName: command.SkillName,
		ManifestDigest: manifestDigest, Outcome: "allow", Revision: 1,
		IssuedAt: fixture.now.Add(-time.Minute), ExpiresAt: fixture.now.Add(time.Hour),
	}
	policy.DecisionDigest, _ = skillregistry.DigestPolicyDecision(policy)
	return skillregistry.ChangeRequest{IdempotencyKey: "sqlite-skill-promotion",
		SignedCommand: signedBytes, SignedManifest: envelope, Signer: fixture.owner,
		Publisher: fixture.publisher, Reviewers: []skillregistry.SigningAuthority{fixture.reviewer},
		Review: fixture.review, Policy: policy}
}

func (fixture skillFixture) signature(authority skillregistry.SigningAuthority,
	private ed25519.PrivateKey, domainName string, payload []byte) skillregistry.DetachedSignature {
	message := append(append([]byte(nil), domainName...), payload...)
	return skillregistry.DetachedSignature{ActorID: authority.ActorID, KeyID: authority.KeyID,
		KeyRevision: authority.KeyRevision, ApprovalRevision: authority.ApprovalRevision,
		SignatureAlgorithm: skillregistry.SignatureAlgorithm,
		Signature:          base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
}

func composeSkillRegistry(t *testing.T, driver *sqlite.Store,
	fixture skillFixture) (*skillregistry.Controller, *skillregistry.RepositoryStore) {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := skillregistry.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := skillregistry.New(repository, skillAuditor{}, skillClock{fixture.now})
	if err != nil {
		t.Fatal(err)
	}
	return registry, repository
}

func openSkillSQLite(t *testing.T, path, backup string, now time.Time) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{
		Path: path, BackupDirectory: backup, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func skillAuthority(label, actorID string) (skillregistry.SigningAuthority, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(label))
	private := ed25519.NewKeyFromSeed(seed[:])
	return skillregistry.SigningAuthority{ActorID: actorID, KeyID: label + "_key",
		KeyRevision: 1, ApprovalRevision: 1, Active: true, Approved: true,
		PublicKey: private.Public().(ed25519.PublicKey)}, private
}

func skillUUID(value string) string {
	sum := sha256.Sum256([]byte("COH-SKILL-SQLITE-TEST-ID\x00" + value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:]
}

func skillDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
