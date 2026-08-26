package sqlite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/retrievalguard"
)

type retrievalClock struct{ now time.Time }

func (clock retrievalClock) Now() time.Time { return clock.now }

type retrievalAuthority struct{ now time.Time }

func (authority retrievalAuthority) AuthorizeRetrieval(_ context.Context, request retrievalguard.AuthorizationRequest) (retrievalguard.Decision, error) {
	decision := retrievalguard.Decision{SchemaVersion: retrievalguard.DecisionSchemaVersion,
		ContractVersion: retrievalguard.ContractVersion, DecisionID: retrievalUUID("decision"),
		RequestDigest: request.RequestDigest, Case: request.Case, TaskID: request.TaskID,
		ActorID: request.ActorID, ActorRevision: request.ActorRevision,
		PolicyDigest: request.PolicyDigest, RevocationDigest: retrievalDigest("revocation"),
		Outcome: "allow", ReasonCode: "inspection_allowed", Revision: 1,
		IssuedAt: authority.now.Add(-time.Minute), ExpiresAt: authority.now.Add(time.Minute)}
	decision.DecisionDigest, _ = retrievalguard.DecisionBindingDigest(decision)
	return decision, nil
}

type retrievalInspector struct{ calls int }

func (inspector *retrievalInspector) Inspect(_ context.Context, request retrievalguard.InspectionRequest) (retrievalguard.InspectionResult, error) {
	inspector.calls++
	findings, _ := retrievalguard.FindingsBindingDigest(nil)
	return retrievalguard.InspectionResult{SourceDigest: request.Source.Artifact.Digest,
		SourceProvenanceDigest: request.Source.ProvenanceDigest,
		Sanitized: domain.ArtifactRef{Digest: retrievalDigest("sanitized"), MediaType: "application/json",
			Classification: request.Source.Artifact.Classification, Length: 96},
		Trust: retrievalguard.UntrustedContent, Findings: []retrievalguard.Finding{},
		FindingsDigest: findings, Complete: true, InspectorDigest: retrievalDigest("inspector")}, nil
}

type retrievalVerifier struct{ calls int }

func (verifier *retrievalVerifier) VerifyArtifact(_ context.Context, artifact domain.ArtifactRef) error {
	verifier.calls++
	if artifact.Digest != retrievalDigest("sanitized") {
		return errors.New("sanitized artifact changed")
	}
	return nil
}

type retrievalAuditor struct {
	fail   bool
	events map[string]tamperaudit.Event
}

func (auditor *retrievalAuditor) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	if auditor.fail {
		return errors.New("audit unavailable")
	}
	if prior, found := auditor.events[event.EventID]; found && !reflect.DeepEqual(prior, event) {
		return errors.New("changed audit replay")
	}
	auditor.events[event.EventID] = event
	return nil
}

func TestRetrievalGuardRecoversCommittedInspectionAfterSQLiteRestart(t *testing.T) {
	now := time.Date(2026, 8, 26, 22, 30, 0, 0, time.UTC)
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "coh.sqlite3")
	driver := openRetrievalSQLite(t, path, backup, now)
	inspector := &retrievalInspector{}
	auditor := &retrievalAuditor{fail: true, events: map[string]tamperaudit.Event{}}
	controller := composeRetrievalController(t, driver, now, inspector, &retrievalVerifier{}, auditor)
	request := retrievalRequest(now)
	if _, err := controller.Inspect(context.Background(), request); retrievalguard.CodeOf(err) != retrievalguard.Unavailable || retrievalguard.Reason(err) != "audit_unavailable" {
		t.Fatalf("initial lost audit result=%v", err)
	}
	if inspector.calls != 1 {
		t.Fatalf("initial inspections=%d", inspector.calls)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openRetrievalSQLite(t, path, backup, now)
	defer driver.Close()
	restartedInspector := &retrievalInspector{}
	auditor.fail = false
	restarted := composeRetrievalController(t, driver, now, restartedInspector, &retrievalVerifier{}, auditor)
	result, err := restarted.Inspect(context.Background(), request)
	if err != nil || !result.Replayed || result.Inspection.Sanitized.Digest != retrievalDigest("sanitized") || restartedInspector.calls != 0 {
		t.Fatalf("recovered result=%+v err=%v inspections=%d", result, err, restartedInspector.calls)
	}
	if len(auditor.events) != 2 {
		t.Fatalf("historical and fresh replay authorization events=%d", len(auditor.events))
	}
	changed := request
	changed.Source.Artifact.Digest = retrievalDigest("changed")
	if _, err = restarted.Inspect(context.Background(), changed); retrievalguard.CodeOf(err) != retrievalguard.Denied || retrievalguard.Reason(err) != "changed_replay" {
		t.Fatalf("changed durable replay=%v", err)
	}
}

func composeRetrievalController(t *testing.T, driver *sqlite.Store, now time.Time, inspector retrievalguard.Inspector, verifier retrievalguard.ArtifactVerifier, auditor retrievalguard.Auditor) *retrievalguard.Controller {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := retrievalguard.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := retrievalguard.New(retrievalAuthority{now}, inspector, verifier, auditor, store, retrievalClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func openRetrievalSQLite(t *testing.T, path, backup string, now time.Time) *sqlite.Store {
	t.Helper()
	driver, err := sqlite.Open(context.Background(), sqlite.Config{Path: path, BackupDirectory: backup,
		Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func retrievalRequest(now time.Time) retrievalguard.Request {
	profile := retrievalguard.InspectionProfile{Name: "strict_data", Revision: 1, MaximumBytes: 1 << 20,
		AllowedMediaTypes: []string{"text/plain"}, DenyActiveFormats: true, RedactSecrets: true,
		NeutralizeDirectives: true}
	profile.ProfileDigest, _ = retrievalguard.ProfileBindingDigest(profile)
	return retrievalguard.Request{SchemaVersion: retrievalguard.RequestSchemaVersion,
		ContractVersion: retrievalguard.ContractVersion, RequestID: retrievalUUID("request"),
		IdempotencyKey: "sqlite-retrieval", Case: domain.CaseRef{OrganizationID: retrievalUUID("org"),
			TenantID: retrievalUUID("tenant"), CaseID: retrievalUUID("case")}, TaskID: retrievalUUID("task"),
		ActorID: retrievalUUID("actor"), ActorRevision: 2,
		Source: retrievalguard.Source{Kind: retrievalguard.DocumentSource,
			Artifact: domain.ArtifactRef{Digest: retrievalDigest("source"), MediaType: "text/plain", Classification: "restricted", Length: 512},
			Trust:    retrievalguard.UntrustedContent, ProvenanceDigest: retrievalDigest("source-provenance")},
		Profile: profile, PolicyDigest: retrievalDigest("policy"), Deadline: now.Add(time.Hour)}
}

func retrievalDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func retrievalUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
