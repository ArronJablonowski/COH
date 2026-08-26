package tamperaudit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
)

const (
	testOrganization = "0198d6c4-1111-7111-8111-111111111111"
	testTenant       = "0198d6c4-2222-7222-8222-222222222222"
	testCase         = "0198d6c4-3333-7333-8333-333333333333"
	testActor        = "0198d6c4-4444-7444-8444-444444444444"
	testEvent        = "0198d6c4-5555-7555-8555-555555555555"
	testCheckpoint   = "0198d6c4-6666-7666-8666-666666666666"
	testTime         = "2026-08-26T01:00:00.000000000Z"
)

func TestRecordAndCheckpointRoundTrip(t *testing.T) {
	event := validEvent()
	record, err := BuildRecord(event, 1, GenesisHash, testTime)
	if err != nil || VerifyRecord(record, 1, GenesisHash) != nil {
		t.Fatalf("record failed: %+v err=%v", record, err)
	}
	canonicalBytes, err := CanonicalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := DecodeRecord(canonicalBytes)
	if err != nil || recovered.ChainHash != record.ChainHash {
		t.Fatalf("decode failed: %+v err=%v", recovered, err)
	}
	seed := sha256.Sum256([]byte("COH-CYB-49-DETERMINISTIC-TEST-KEY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	checkpoint := Checkpoint{SchemaVersion: CheckpointSchemaVersion, ContractVersion: ContractVersion,
		CheckpointID: testCheckpoint, OrganizationID: testOrganization, TenantID: testTenant,
		CoveredFromSequence: 1, Sequence: 1, RecordCount: 1, ChainHash: record.ChainHash,
		Reason: "manual_final", SigningKeyID: "audit-primary", SigningKeyRevision: 3,
		SignatureAlgorithm: SignatureAlgorithm, CreatedAt: testTime}
	signed, err := SignCheckpoint(checkpoint, privateKey)
	if err != nil || VerifyCheckpoint(signed, privateKey.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("checkpoint failed: %+v err=%v", signed, err)
	}
}

func TestTamperGapForkAndSignatureDeny(t *testing.T) {
	first, _ := BuildRecord(validEvent(), 1, GenesisHash, testTime)
	mutations := map[string]func(*Record){
		"event":  func(record *Record) { record.Event.Outcome = "denied" },
		"digest": func(record *Record) { record.EventDigest = GenesisHash },
		"chain":  func(record *Record) { record.ChainHash = GenesisHash },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := first
			mutate(&candidate)
			if !errors.Is(VerifyRecord(candidate, 1, GenesisHash), ErrIntegrity) {
				t.Fatal("tampered record was accepted")
			}
		})
	}
	if !errors.Is(VerifyRecord(first, 2, GenesisHash), ErrIntegrity) ||
		!errors.Is(VerifyRecord(first, 1, first.ChainHash), ErrIntegrity) {
		t.Fatal("gap or fork was accepted")
	}

	seed := sha256.Sum256([]byte("COH-CYB-49-DETERMINISTIC-TEST-KEY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	checkpoint, _ := SignCheckpoint(Checkpoint{SchemaVersion: CheckpointSchemaVersion, ContractVersion: ContractVersion,
		CheckpointID: testCheckpoint, OrganizationID: testOrganization, TenantID: testTenant,
		CoveredFromSequence: 1, Sequence: 1, RecordCount: 1, ChainHash: first.ChainHash,
		Reason: "daily", SigningKeyID: "audit-primary", SigningKeyRevision: 3,
		SignatureAlgorithm: SignatureAlgorithm, CreatedAt: testTime}, privateKey)
	checkpoint.ChainHash = GenesisHash
	if !errors.Is(VerifyCheckpoint(checkpoint, privateKey.Public().(ed25519.PublicKey)), ErrIntegrity) {
		t.Fatal("tampered checkpoint was accepted")
	}
}

func TestEventRejectsNoncanonicalOrUnsafeShape(t *testing.T) {
	tests := map[string]func(*Event){
		"free-form operation":    func(event *Event) { event.Operation = "read secret" },
		"actor without revision": func(event *Event) { event.ActorRevision = 0 },
		"unsorted evidence": func(event *Event) {
			event.EvidenceDigests = []string{"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		},
		"noncanonical time": func(event *Event) { event.OccurredAt = "2026-08-26T01:00:00Z" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			event := validEvent()
			mutate(&event)
			if !errors.Is(ValidateEvent(event), ErrInvalidInput) {
				t.Fatal("unsafe event accepted")
			}
		})
	}
}

func validEvent() Event {
	return Event{SchemaVersion: EventSchemaVersion, ContractVersion: ContractVersion,
		EventID: testEvent, OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase,
		ActorID: testActor, ActorRevision: 7, SourceSchema: "coh.approval-lifecycle/v2",
		Operation: "grant", Outcome: "allowed", ReasonCode: "approval_granted",
		SubjectID: "0198d6c4-7777-7777-8777-777777777777", SubjectRevision: 2,
		SubjectDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EvidenceDigests: []string{}, OccurredAt: testTime}
}
