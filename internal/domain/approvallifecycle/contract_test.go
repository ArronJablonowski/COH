package approvallifecycle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTrackedRequestedFixtureIsCanonicalAndValid(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "approval", "v1", "fixtures", "valid", "approval-lifecycle-requested.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	input = bytes.TrimSpace(input)
	record, err := DecodeRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalRecord(record)
	if err != nil || string(canonical) != string(input) {
		t.Fatalf("fixture changed: err=%v", err)
	}
}

func TestTransitionTable(t *testing.T) {
	requested := fixtureRecord()
	granted := requested
	granted.Revision++
	granted.State = Granted
	granted.Grants = []Grant{{ActorID: "0198d6c4-7777-7777-8777-777777777777", ActorRevision: 9, GrantedAt: "2026-08-26T01:01:00.000000000Z"}}
	granted.LastActorID = granted.Grants[0].ActorID
	granted.LastActorRevision = 9
	granted.ReasonCode = "approval_granted"
	granted.UpdatedAt = granted.Grants[0].GrantedAt
	consumed := granted
	consumed.Revision++
	consumed.State = Consumed
	consumed.UseCount = 1
	consumed.LastActorID = "0198d6c4-8888-7888-8888-888888888888"
	consumed.LastActorRevision = 5
	consumed.ReasonCode = "approval_consumed"
	consumed.UpdatedAt = "2026-08-26T01:02:00.000000000Z"
	for name, pair := range map[string][2]Record{
		"grant":   {requested, granted},
		"consume": {granted, consumed},
	} {
		if err := ValidateTransition(pair[0], pair[1]); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*Record){
		"stale revision": func(value *Record) { value.Revision = requested.Revision },
		"binding change": func(value *Record) {
			value.FingerprintDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		},
		"self approval": func(value *Record) { value.Grants[0].ActorID = value.RequestorActorID },
		"use before grant": func(value *Record) {
			value.State, value.Grants, value.UseCount = Consumed, nil, 1
		},
	} {
		candidate := granted
		candidate.Grants = append([]Grant(nil), granted.Grants...)
		mutate(&candidate)
		if err := ValidateTransition(requested, candidate); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := ValidateTransition(consumed, consumed); err == nil {
		t.Fatal("terminal transition accepted")
	}
}

func fixtureRecord() Record {
	return Record{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		ApprovalID: "0198d6c4-6666-7666-8666-666666666666", OrganizationID: "0198d6c4-1111-7111-8111-111111111111",
		TenantID: "0198d6c4-3333-7333-8333-333333333333", CaseID: "0198d6c4-4444-7444-8444-444444444444",
		FingerprintDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PolicyDecisionDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		RequestorActorID:     "0198d6c4-2222-7222-8222-222222222222", RequestorRevision: 4,
		ActionOwnerActorID: "0198d6c4-5555-7555-8555-555555555555",
		State:              Requested, Revision: 1, RequestedAt: "2026-08-26T01:00:00.000000000Z",
		ValidFrom: "2026-08-26T01:00:00.000000000Z", ValidUntil: "2026-08-26T02:00:00.000000000Z",
		RequiredGrantCount: 1, Grants: []Grant{}, MaximumUseCount: 1, UseCount: 0,
		ReasonCode: "approval_requested", LastActorID: "0198d6c4-2222-7222-8222-222222222222",
		LastActorRevision: 4, LastOperationDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		LastEventID: "0198d6c4-9999-7999-8999-999999999999", UpdatedAt: "2026-08-26T01:00:00.000000000Z"}
}
