package skillregistry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

const (
	testOrganization = "0198d6c4-0001-7001-8001-000000000001"
	testTenant       = "0198d6c4-0002-7002-8002-000000000002"
	testCase         = "0198d6c4-0003-7003-8003-000000000003"
	testTask         = "0198d6c4-0004-7004-8004-000000000004"
	testOwner        = "0198d6c4-0005-7005-8005-000000000005"
	testPublisher    = "0198d6c4-0006-7006-8006-000000000006"
	testReviewer     = "0198d6c4-0007-7007-8007-000000000007"
	testConsumer     = "0198d6c4-0008-7008-8008-000000000008"
)

type testFixture struct {
	now          time.Time
	owner        SigningAuthority
	publisher    SigningAuthority
	reviewer     SigningAuthority
	review       ReviewAuthority
	ownerPrivate ed25519.PrivateKey
	pubPrivate   ed25519.PrivateKey
	revPrivate   ed25519.PrivateKey
}

func newFixture(t *testing.T) testFixture {
	t.Helper()
	now := mustTime(t, "2026-08-26T20:00:00.000000000Z")
	owner, ownerPrivate := testAuthority("owner", testOwner)
	publisher, pubPrivate := testAuthority("publisher", testPublisher)
	reviewer, revPrivate := testAuthority("reviewer", testReviewer)
	return testFixture{
		now: now, owner: owner, publisher: publisher, reviewer: reviewer,
		review: ReviewAuthority{ReviewID: deterministicUUID("review", "one"), Revision: 1,
			Decision: "approved", ReviewerIDs: []string{testReviewer},
			EvidenceDigest: testDigest("e"), Active: true},
		ownerPrivate: ownerPrivate, pubPrivate: pubPrivate, revPrivate: revPrivate,
	}
}

func (fixture testFixture) manifest(t *testing.T, version, previous, content string) Manifest {
	t.Helper()
	return Manifest{
		SchemaVersion: ManifestSchemaVersion, ContractVersion: ContractVersion,
		ManifestID: deterministicUUID("manifest", version), SkillName: "timeline_builder",
		SkillVersion: version, OwnerActorID: testOwner, PublisherActorID: testPublisher,
		ContentDigest: testDigest(content), Resources: []Resource{{
			Name: "instructions", Digest: testDigest(content), MediaType: "text/markdown",
			Classification: "internal", Length: 128,
		}}, Permissions: []string{"evidence.read", "timeline.write"},
		TestSuiteDigest: testDigest("a"), TestEvidenceDigest: testDigest("b"),
		ThreatModelDigest: testDigest("c"), PreviousManifestDigest: previous,
		ReviewID: fixture.review.ReviewID, ReviewRevision: fixture.review.Revision,
		ReviewDecision: "approved", ReviewerActorIDs: []string{testReviewer},
		ReviewEvidenceDigest: fixture.review.EvidenceDigest,
		ReviewedAt:           fixture.now.Add(-2 * time.Hour), ValidFrom: fixture.now.Add(-time.Hour),
		ValidUntil: fixture.now.Add(48 * time.Hour),
	}
}

func (fixture testFixture) envelope(t *testing.T, manifest Manifest) ([]byte, string) {
	t.Helper()
	payload, digest, err := canonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{
		SchemaVersion: EnvelopeSchemaVersion, ContractVersion: ContractVersion,
		Manifest: manifest, ManifestDigest: digest,
		PublisherSignature: signed(fixture.publisher, fixture.pubPrivate, ManifestDomain, payload),
		ReviewSignatures: []DetachedSignature{
			signed(fixture.reviewer, fixture.revPrivate, ReviewDomain, payload),
		},
	}
	encoded, err := canonicalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, digest
}

func (fixture testFixture) change(t *testing.T, action ChangeAction, target, expected string,
	revision uint64, id string) ([]byte, ChangeCommand) {
	t.Helper()
	command := ChangeCommand{
		SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		CommandID: deterministicUUID("command", id), Action: action,
		OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase, TaskID: testTask,
		ActorID: testOwner, SkillName: "timeline_builder", TargetManifestDigest: target,
		ExpectedCurrentDigest: expected, ExpectedRevision: revision, ReasonDigest: testDigest("d"),
		CreatedAt: fixture.now.Add(-time.Minute), Deadline: fixture.now.Add(time.Hour),
	}
	payload, digest, err := canonicalCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	value := SignedChange{SchemaVersion: SignedCommandVersion, ContractVersion: ContractVersion,
		Command: command, CommandDigest: digest,
		Signature: signed(fixture.owner, fixture.ownerPrivate, CommandDomain, payload)}
	encoded, err := canonicalSignedChange(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, command
}

func (fixture testFixture) policy(command ChangeCommand, id string) PolicyDecision {
	value := PolicyDecision{
		SchemaVersion: PolicySchemaVersion, ContractVersion: ContractVersion,
		DecisionID:   deterministicUUID("policy", id),
		PolicyDigest: testDigest("1"), OrganizationID: command.OrganizationID, TenantID: command.TenantID,
		CaseID: command.CaseID, TaskID: command.TaskID, ActorID: command.ActorID,
		Action: command.Action, SkillName: command.SkillName, ManifestDigest: command.TargetManifestDigest,
		Outcome: "allow", Revision: 1, IssuedAt: fixture.now.Add(-time.Minute),
		ExpiresAt: fixture.now.Add(time.Hour),
	}
	value.DecisionDigest, _ = policyDecisionDigest(value)
	return value
}

func (fixture testFixture) changeRequest(t *testing.T, id string, action ChangeAction, manifest []byte,
	target, expected string, revision uint64) ChangeRequest {
	t.Helper()
	signedCommand, command := fixture.change(t, action, target, expected, revision, id)
	return ChangeRequest{IdempotencyKey: id, SignedCommand: signedCommand, SignedManifest: manifest,
		Signer: fixture.owner, Publisher: fixture.publisher, Reviewers: []SigningAuthority{fixture.reviewer},
		Review: fixture.review, Policy: fixture.policy(command, id)}
}

func signed(authority SigningAuthority, private ed25519.PrivateKey, domain string, payload []byte) DetachedSignature {
	message := append(append([]byte(nil), domain...), payload...)
	return DetachedSignature{
		ActorID: authority.ActorID, KeyID: authority.KeyID, KeyRevision: authority.KeyRevision,
		ApprovalRevision: authority.ApprovalRevision, SignatureAlgorithm: SignatureAlgorithm,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message)),
	}
}

func testAuthority(label, actorID string) (SigningAuthority, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(label))
	private := ed25519.NewKeyFromSeed(seed[:])
	return SigningAuthority{ActorID: actorID, KeyID: label + "_key", KeyRevision: 1,
		ApprovalRevision: 1, Active: true, Approved: true,
		PublicKey: append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)}, private
}

type fixedClock struct{ value time.Time }

func (clock fixedClock) Now() time.Time { return clock.value }

type memoryStore struct {
	mu           sync.Mutex
	state        State
	stateFound   bool
	versions     map[string]Version
	replays      map[string]State
	commits      int
	lostResponse bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{versions: map[string]Version{}, replays: map[string]State{}}
}

func (store *memoryStore) LoadState(_ context.Context, organizationID, tenantID,
	skillName string) (State, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.stateFound {
		return State{}, false, nil
	}
	if store.state.OrganizationID != organizationID || store.state.TenantID != tenantID ||
		store.state.SkillName != skillName {
		return State{}, false, nil
	}
	return cloneState(store.state), true, nil
}

func (store *memoryStore) LoadVersion(_ context.Context, organizationID, tenantID,
	digest string) (Version, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.versions[digest]
	if !found || value.OrganizationID != organizationID || value.TenantID != tenantID {
		return Version{}, false, nil
	}
	return cloneVersion(value), true, nil
}

func (store *memoryStore) Commit(_ context.Context, key string, expected *State,
	next State, version *Version) (State, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if replay, found := store.replays[key]; found {
		if !reflect.DeepEqual(replay, next) {
			return State{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return cloneState(replay), true, nil
	}
	if expected == nil && store.stateFound ||
		expected != nil && (!store.stateFound || !reflect.DeepEqual(*expected, store.state)) {
		return State{}, false, newError(Conflict, "optimistic_conflict", false, nil)
	}
	if version != nil {
		if prior, found := store.versions[version.ManifestDigest]; found &&
			(!bytes.Equal(prior.Envelope, version.Envelope) || prior.ManifestID != version.ManifestID) {
			return State{}, false, newError(Denied, "immutable_version_collision", false, nil)
		}
		store.versions[version.ManifestDigest] = cloneVersion(*version)
	}
	store.state, store.stateFound = cloneState(next), true
	store.replays[key] = cloneState(next)
	store.commits++
	if store.lostResponse {
		store.lostResponse = false
		return State{}, false, errors.New("lost commit response")
	}
	return cloneState(next), false, nil
}

type memoryAuditor struct {
	mu     sync.Mutex
	events map[string]string
	count  int
	fail   bool
}

func newMemoryAuditor() *memoryAuditor { return &memoryAuditor{events: map[string]string{}} }

func (auditor *memoryAuditor) Append(_ context.Context, event AuditEvent) (AuditReceipt, error) {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	if auditor.fail {
		return AuditReceipt{}, errors.New("audit unavailable")
	}
	digest, err := auditEventDigest(event)
	if err != nil {
		return AuditReceipt{}, err
	}
	if prior, found := auditor.events[event.EventID]; found && prior != digest {
		return AuditReceipt{}, newError(Denied, "audit_changed_replay", false, nil)
	} else if !found {
		auditor.events[event.EventID] = digest
		auditor.count++
	}
	return AuditReceipt{EventID: event.EventID, EventDigest: digest,
		ReceiptDigest: digestBytes([]byte("receipt\x00" + digest))}, nil
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}

func testDigest(character string) string {
	return "sha256:" + string(bytes.Repeat([]byte(character), 64))
}
