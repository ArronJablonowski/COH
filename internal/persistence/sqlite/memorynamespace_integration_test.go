package sqlite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/memorynamespace"
)

type memoryClock struct{ now time.Time }

func (clock memoryClock) Now() time.Time { return clock.now }

type memoryAuthority struct{ now time.Time }

func (authority memoryAuthority) AuthorizeMemory(_ context.Context, request memorynamespace.AccessRequest) (memorynamespace.Decision, error) {
	bound, _ := memorynamespace.AccessDigest(request)
	decision := memorynamespace.Decision{SchemaVersion: memorynamespace.AccessSchemaVersion, ContractVersion: memorynamespace.ContractVersion,
		Allowed: true, ReasonCode: "memory_allowed", AccessRequestDigest: bound,
		DecidedAt: authority.now, ExpiresAt: authority.now.Add(time.Minute)}
	decision.DecisionDigest, _ = memorynamespace.DecisionBindingDigest(decision)
	return decision, nil
}

type memoryReviewAuthority struct{ now time.Time }

func (authority memoryReviewAuthority) AuthorizeReview(_ context.Context, request memorynamespace.ReviewRequest) (memorynamespace.ReviewDecision, error) {
	bound, _ := memorynamespace.ReviewDigest(request)
	expires := authority.now.Add(time.Minute)
	if expires.After(request.Review.ValidUntil) {
		expires = request.Review.ValidUntil
	}
	decision := memorynamespace.ReviewDecision{SchemaVersion: memorynamespace.ReviewSchemaVersion, ContractVersion: memorynamespace.ContractVersion,
		Allowed: true, ReasonCode: "review_allowed", ReviewRequestDigest: bound,
		DecidedAt: authority.now, ExpiresAt: expires}
	decision.DecisionDigest, _ = memorynamespace.ReviewDecisionBindingDigest(decision)
	return decision, nil
}

func TestMemoryNamespacesSurviveSQLiteRestartAndRecoverOldReplay(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	path := filepath.Join(root, "coh.sqlite3")
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openMemorySQLite(t, path, backup, now)
	controller := composeMemoryController(t, driver, now)
	requests := map[memorynamespace.Namespace]memorynamespace.PutRequest{}
	for _, namespace := range []memorynamespace.Namespace{memorynamespace.SessionMemory, memorynamespace.CaseMemory,
		memorynamespace.AnalystPreferenceMemory, memorynamespace.ReviewedOrganizationMemory} {
		request := memoryPut(namespace, now)
		requests[namespace] = request
		if result, err := controller.Put(context.Background(), request); err != nil || result.Record.Namespace != namespace {
			t.Fatalf("Put(%s)=%+v err=%v", namespace, result, err)
		}
	}
	caseFirst := requests[memorynamespace.CaseMemory]
	caseSecond := caseFirst
	caseSecond.RequestID = memoryUUID("request-2")
	caseSecond.IdempotencyKey = "case-write-2"
	caseSecond.ExpectedRevision = 1
	caseSecond.Value.Digest = memoryDigest("case-value-2")
	if result, err := controller.Put(context.Background(), caseSecond); err != nil || result.Record.Revision != 2 {
		t.Fatalf("update=%+v err=%v", result, err)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openMemorySQLite(t, path, backup, now)
	defer driver.Close()
	restarted := composeMemoryController(t, driver, now)
	for namespace, request := range requests {
		read := memorynamespace.GetRequest{SchemaVersion: memorynamespace.GetSchemaVersion, ContractVersion: memorynamespace.ContractVersion,
			RequestID: memoryUUID("read-" + string(namespace)), ActorID: request.ActorID,
			Namespace: namespace, Scope: request.Scope, Key: request.Key, PolicyDigest: request.PolicyDigest, Deadline: now.Add(time.Hour)}
		result, err := restarted.Get(context.Background(), read)
		if err != nil {
			t.Fatalf("Get(%s): %v", namespace, err)
		}
		wantRevision := uint64(1)
		if namespace == memorynamespace.CaseMemory {
			wantRevision = 2
		}
		if result.Record.Revision != wantRevision {
			t.Fatalf("Get(%s) revision=%d", namespace, result.Record.Revision)
		}
	}
	replayed, err := restarted.Put(context.Background(), caseFirst)
	if err != nil || !replayed.Replayed || replayed.Record.Revision != 1 || replayed.Record.Value.Digest != caseFirst.Value.Digest {
		t.Fatalf("old replay=%+v err=%v", replayed, err)
	}
	changed := caseFirst
	changed.Value.Digest = memoryDigest("changed-replay")
	if _, err = restarted.Put(context.Background(), changed); memorynamespace.CodeOf(err) != memorynamespace.Denied || memorynamespace.Reason(err) != "changed_replay" {
		t.Fatalf("changed replay err=%v", err)
	}
}

func composeMemoryController(t *testing.T, driver *sqlite.Store, now time.Time) *memorynamespace.Controller {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	stores := make(map[memorynamespace.Namespace]*memorynamespace.RepositoryStore)
	for _, namespace := range []memorynamespace.Namespace{memorynamespace.SessionMemory, memorynamespace.CaseMemory,
		memorynamespace.AnalystPreferenceMemory, memorynamespace.ReviewedOrganizationMemory} {
		stores[namespace], err = memorynamespace.NewRepositoryStore(namespace, guarded)
		if err != nil {
			t.Fatal(err)
		}
	}
	controller, err := memorynamespace.New(stores[memorynamespace.SessionMemory], stores[memorynamespace.CaseMemory],
		stores[memorynamespace.AnalystPreferenceMemory], stores[memorynamespace.ReviewedOrganizationMemory],
		memoryAuthority{now}, memoryReviewAuthority{now}, memoryClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func openMemorySQLite(t *testing.T, path, backup string, now time.Time) *sqlite.Store {
	t.Helper()
	driver, err := sqlite.Open(context.Background(), sqlite.Config{Path: path, BackupDirectory: backup,
		Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func memoryPut(namespace memorynamespace.Namespace, now time.Time) memorynamespace.PutRequest {
	scope := memorynamespace.Scope{OrganizationID: memoryUUID("org"), TenantID: memoryUUID("tenant")}
	switch namespace {
	case memorynamespace.SessionMemory:
		scope.CaseID = memoryUUID("case")
		scope.SessionID = memoryUUID("session")
		scope.SubjectActorID = memoryUUID("actor")
	case memorynamespace.CaseMemory:
		scope.CaseID = memoryUUID("case")
	case memorynamespace.AnalystPreferenceMemory:
		scope.SubjectActorID = memoryUUID("actor")
	}
	class := map[memorynamespace.Namespace]string{memorynamespace.SessionMemory: "session_ephemeral", memorynamespace.CaseMemory: "case_record",
		memorynamespace.AnalystPreferenceMemory: "analyst_preference", memorynamespace.ReviewedOrganizationMemory: "reviewed_organization"}[namespace]
	request := memorynamespace.PutRequest{SchemaVersion: memorynamespace.PutSchemaVersion, ContractVersion: memorynamespace.ContractVersion,
		RequestID: memoryUUID("request-" + string(namespace)), IdempotencyKey: "write-" + string(namespace),
		ActorID: memoryUUID("actor"), Namespace: namespace, Scope: scope, Key: "investigation.summary",
		Value: domain.ArtifactRef{Digest: memoryDigest("value-" + string(namespace)), MediaType: "application/json", Classification: "restricted", Length: 64},
		ValueType: map[memorynamespace.Namespace]string{memorynamespace.SessionMemory: "session_state_reference",
			memorynamespace.CaseMemory: "case_memory_reference", memorynamespace.AnalystPreferenceMemory: "analyst_preference_reference",
			memorynamespace.ReviewedOrganizationMemory: "reviewed_organization_reference"}[namespace],
		Retention:    memorynamespace.RetentionPolicy{Class: class, PolicyDigest: memoryDigest("retention-" + string(namespace)), ExpiresAt: now.Add(2 * time.Hour)},
		PolicyDigest: memoryDigest("policy"), Deadline: now.Add(time.Hour)}
	if namespace == memorynamespace.ReviewedOrganizationMemory {
		request.Review = memorynamespace.Review{ReviewID: memoryUUID("review"), ReviewerActorID: memoryUUID("reviewer"),
			Revision: 1, AuthorityDigest: memoryDigest("review-authority"), ReviewedAt: now.Add(-time.Hour), ValidUntil: now.Add(30 * time.Minute)}
	}
	return request
}

func memoryDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func memoryUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
