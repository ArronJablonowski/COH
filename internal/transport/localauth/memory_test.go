package localauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

func TestMemoryRepositoryRunsAuthenticationAuthorizationAndRevocation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := localidentity.Actor{
		SchemaVersion: localidentity.SchemaVersion, ContractVersion: localidentity.ContractVersion,
		ID: testActorID, OrganizationID: testOrganizationID, Name: "analyst.one",
		Roles:     []localidentity.Role{localidentity.Analyst},
		Grants:    []localidentity.ScopeGrant{{TenantID: testTenantID, CaseIDs: []string{testCaseID}}},
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Revision: 1, Active: true,
	}
	repository, err := NewMemoryRepository([]localidentity.Actor{actor})
	if err != nil {
		t.Fatal(err)
	}
	audit := &auditMemory{}
	clock := &fixedClock{current: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	service := Service{
		Actors: repository, Challenges: repository, Sessions: repository, Replay: repository,
		Audit: audit, Clock: clock,
	}
	issued := issueTestSession(t, service, privateKey)
	decision, err := service.Authorize(context.Background(), issued.Token, validAuthorizationRequest(localidentity.QueryExecute, ""))
	if err != nil || decision.Outcome != "allowed" {
		t.Fatalf("decision = %+v, err = %v", decision, err)
	}
	actor.Revision = 2
	actor.Active = false
	if err := repository.ReplaceActor(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	decision, err = service.Authorize(context.Background(), issued.Token, validAuthorizationRequest(localidentity.QueryExecute, ""))
	if localidentity.Code(err) != localidentity.Denied || decision.ReasonCode != "actor_revoked" {
		t.Fatalf("revoked decision = %+v, err = %v", decision, err)
	}
}

func TestMemoryRepositoryClonesActorsAndRequiresNextRevision(t *testing.T) {
	_, _, actors, _, _, _, _ := authenticationFixture(t)
	repository, err := NewMemoryRepository([]localidentity.Actor{actors.actor})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LookupActor(context.Background(), testOrganizationID, testActorID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Roles[0] = localidentity.Administrator
	loaded.Grants[0].CaseIDs[0] = "0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
	unchanged, err := repository.LookupActor(context.Background(), testOrganizationID, testActorID)
	if err != nil || unchanged.Roles[0] != localidentity.Analyst || unchanged.Grants[0].CaseIDs[0] != testCaseID {
		t.Fatalf("actor alias leaked: %+v, err = %v", unchanged, err)
	}
	updated := unchanged
	updated.Revision = 2
	updated.Active = false
	if err := repository.ReplaceActor(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReplaceActor(context.Background(), updated); localidentity.Code(err) != localidentity.Conflict {
		t.Fatalf("stale revision err = %v", err)
	}
}

func TestMemoryRepositoryChallengeTakeIsAtomic(t *testing.T) {
	repository, err := NewMemoryRepository(nil)
	if err != nil {
		t.Fatal(err)
	}
	record := ChallengeRecord{ID: "challenge", Message: []byte("message")}
	if err := repository.SaveChallenge(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, takeErr := repository.TakeChallenge(context.Background(), record.ID); takeErr == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful takes = %d", successes.Load())
	}
}

func TestMemoryRepositoryReplayCheckIsAtomic(t *testing.T) {
	repository, err := NewMemoryRepository(nil)
	if err != nil {
		t.Fatal(err)
	}
	record := ReplayRecord{SessionID: "session", IdempotencyKey: "request", RequestDigest: "sha256:one"}
	const workers = 64
	var fresh atomic.Int32
	var exact atomic.Int32
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, replayErr := repository.CheckAndStore(context.Background(), record)
			if replayErr != nil {
				t.Errorf("replay check: %v", replayErr)
				return
			}
			switch result {
			case ReplayNew:
				fresh.Add(1)
			case ReplayExact:
				exact.Add(1)
			default:
				t.Errorf("result = %q", result)
			}
		}()
	}
	wait.Wait()
	if fresh.Load() != 1 || exact.Load() != workers-1 {
		t.Fatalf("new = %d, exact = %d", fresh.Load(), exact.Load())
	}
	conflict := record
	conflict.RequestDigest = "sha256:two"
	if result, err := repository.CheckAndStore(context.Background(), conflict); err != nil || result != ReplayConflict {
		t.Fatalf("conflict result = %q, err = %v", result, err)
	}
}

func TestMemoryRepositorySessionRevocationIsImmediateAndIdempotent(t *testing.T) {
	repository, err := NewMemoryRepository(nil)
	if err != nil {
		t.Fatal(err)
	}
	record := SessionRecord{ID: "session", TokenDigest: "digest"}
	if err := repository.SaveSession(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	if err := repository.RevokeSession(context.Background(), record.TokenDigest, first); err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeSession(context.Background(), record.TokenDigest, first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LookupSession(context.Background(), record.TokenDigest)
	if err != nil || !loaded.RevokedAt.Equal(first) {
		t.Fatalf("session = %+v, err = %v", loaded, err)
	}
}
